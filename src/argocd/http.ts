export interface HttpResponse<T> {
  status: number;
  headers: Headers;
  body: T;
}

type SearchParams = Record<string, string | number | boolean | undefined | null> | null;

// A refreshable source of bearer tokens. current() returns the token to use for
// the next request; refresh() is called once after a 401 to obtain a new one.
export interface BearerTokenProvider {
  current(): Promise<string>;
  refresh(): Promise<string>;
}

export type TokenSource = string | BearerTokenProvider;

export class HttpClient {
  public readonly baseUrl: string;
  private readonly tokenSource: TokenSource;

  constructor(baseUrl: string, token: TokenSource) {
    this.baseUrl = baseUrl;
    this.tokenSource = token;
  }

  // Backward-compatible accessor for callers/tests that inspect the resolved
  // client's token. Only meaningful for a static string source: a
  // BearerTokenProvider has no single "the token" (call current() for that),
  // so this returns undefined in that case.
  get apiToken(): string | undefined {
    return typeof this.tokenSource === 'string' ? this.tokenSource : undefined;
  }

  private isProvider(): boolean {
    return typeof this.tokenSource !== 'string';
  }

  private async currentToken(): Promise<string> {
    return typeof this.tokenSource === 'string'
      ? this.tokenSource
      : await this.tokenSource.current();
  }

  private async refreshToken(): Promise<string> {
    // Only reachable when tokenSource is a provider (guarded by isProvider()).
    return (this.tokenSource as BearerTokenProvider).refresh();
  }

  // Best-effort extraction of ArgoCD's error text from a failed response body.
  // ArgoCD returns `{ "error": "...", "message": "..." }`; we prefer `message`.
  // Returns undefined for empty or non-JSON bodies so the caller can omit it.
  //
  // Consumes the response body directly (no clone()): this is only called on the
  // 401 path right before the response is discarded and refetched, so cloning
  // would just buffer the body a second time for no benefit.
  private async readErrorReason(response: Response): Promise<string | undefined> {
    try {
      const data = (await response.json()) as Record<string, unknown>;
      const reason = data?.message ?? data?.error;
      return typeof reason === 'string' && reason ? reason : undefined;
    } catch {
      return undefined;
    }
  }

  private headersFor(token: string, extra?: HeadersInit): Record<string, string> {
    return {
      ...(extra as Record<string, string>),
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    };
  }

  private async request<R>(
    url: string,
    params?: SearchParams,
    init?: RequestInit
  ): Promise<HttpResponse<R>> {
    const urlObject = this.absUrl(url);
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        urlObject.searchParams.set(key, value?.toString() || '');
      });
    }

    let token = await this.currentToken();
    let response = await fetch(urlObject, {
      ...init,
      headers: this.headersFor(token, init?.headers)
    });

    // A session-scoped SSO token can expire mid-session. When it does, refresh
    // once and retry a single time. Static-string tokens are never retried.
    if (response.status === 401 && this.isProvider()) {
      // Capture ArgoCD's own rejection reason before we discard this response.
      // If the refresh then fails (e.g. no session/refresh token on record), we
      // report WHY ArgoCD refused the token — an audience mismatch or signature
      // failure surfaces here — instead of the misleading refresh-side message.
      const reason = await this.readErrorReason(response);
      try {
        token = await this.refreshToken();
      } catch (err) {
        const detail = err instanceof Error ? err.message : String(err);
        throw new Error(
          `ArgoCD rejected the bearer token (401${reason ? `: ${reason}` : ''}); ` +
            `token refresh failed: ${detail}`
        );
      }
      response = await fetch(urlObject, {
        ...init,
        headers: this.headersFor(token, init?.headers)
      });
    }

    const body = await response.json();
    return { status: response.status, headers: response.headers, body: body as R };
  }

  private async requestStream<R>(
    url: string,
    params?: SearchParams,
    cb?: (chunk: R) => void,
    init?: RequestInit
  ) {
    const urlObject = this.absUrl(url);
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        urlObject.searchParams.set(key, value?.toString() || '');
      });
    }
    const token = await this.currentToken();
    const response = await fetch(urlObject, {
      ...init,
      headers: this.headersFor(token, init?.headers)
    });
    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error('response body is not readable');
    }
    const decoder = new TextDecoder('utf-8');
    let buffer = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (line.trim()) {
          const json = JSON.parse(line);
          cb?.(json['result']);
        }
      }
    }
  }

  absUrl(url: string): URL {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      return new URL(url);
    }
    return new URL(url, this.baseUrl);
  }

  async get<R>(url: string, params?: SearchParams): Promise<HttpResponse<R>> {
    return this.request<R>(url, params);
  }

  async getStream<R>(url: string, params?: SearchParams, cb?: (chunk: R) => void): Promise<void> {
    await this.requestStream<R>(url, params, cb);
  }

  async post<T, R>(url: string, params?: SearchParams, body?: T): Promise<HttpResponse<R>> {
    return this.request<R>(url, params, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined
    });
  }

  async put<T, R>(url: string, params?: SearchParams, body?: T): Promise<HttpResponse<R>> {
    return this.request<R>(url, params, {
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined
    });
  }

  async delete<R>(url: string, params?: SearchParams): Promise<HttpResponse<R>> {
    return this.request<R>(url, params, { method: 'DELETE' });
  }
}
