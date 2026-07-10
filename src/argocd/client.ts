import {
  ApplicationLogEntry,
  V1alpha1Application,
  V1alpha1ApplicationList,
  V1alpha1ApplicationTree,
  V1EventList,
  V1alpha1ResourceAction,
  V1alpha1ResourceDiff,
  V1alpha1ResourceResult,
  V1alpha1ApplicationResourceResult,
  V1alpha1ClusterList,
  ApplicationApplicationResponse,
  ApplicationOperationTerminateResponse
} from '../types/argocd-types.js';
import { HttpClient, type TokenSource } from './http.js';

export class ArgoCDClient {
  private baseUrl: string;
  private client: HttpClient;

  constructor(baseUrl: string, token: TokenSource) {
    this.baseUrl = baseUrl;
    this.client = new HttpClient(this.baseUrl, token);
  }

  public async listApplications(params?: { search?: string; limit?: number; offset?: number }) {
    const { body } = await this.client.get<V1alpha1ApplicationList>(
      `/api/v1/applications`,
      params?.search ? { search: params.search } : undefined
    );

    // ArgoCD's list endpoint has no server-side limit/offset, so the full list
    // is always fetched. Paginate the RAW items FIRST, then strip heavy fields
    // from only the returned page — building a stripped copy of every app (the
    // old order) meant peak memory ignored `limit`.
    const rawItems = body.items ?? [];
    const totalItems = rawItems.length;
    const start = params?.offset ?? 0;
    const end = params?.limit ? start + params.limit : totalItems;
    const items = rawItems.slice(start, end).map((app) => ({
      metadata: {
        name: app.metadata?.name,
        namespace: app.metadata?.namespace,
        labels: app.metadata?.labels,
        creationTimestamp: app.metadata?.creationTimestamp
      },
      spec: {
        project: app.spec?.project,
        source: app.spec?.source,
        destination: app.spec?.destination
      },
      status: {
        sync: app.status?.sync,
        health: app.status?.health,
        summary: app.status?.summary
      }
    }));

    return {
      items,
      metadata: {
        resourceVersion: body.metadata?.resourceVersion,
        totalItems,
        returnedItems: items.length,
        hasMore: end < totalItems
      }
    };
  }

  public async listClusters(params?: { server?: string; name?: string }) {
    const queryParams: Record<string, string> = {};
    if (params?.server) queryParams.server = params.server;
    if (params?.name) queryParams.name = params.name;

    const { body } = await this.client.get<V1alpha1ClusterList>(
      `/api/v1/clusters`,
      Object.keys(queryParams).length > 0 ? queryParams : undefined
    );

    return body;
  }

  public async getApplication(applicationName: string, appNamespace?: string) {
    const queryParams = appNamespace ? { appNamespace } : undefined;
    const { body } = await this.client.get<V1alpha1Application>(
      `/api/v1/applications/${applicationName}`,
      queryParams
    );
    return body;
  }

  public async createApplication(application: V1alpha1Application) {
    const { body } = await this.client.post<V1alpha1Application, V1alpha1Application>(
      `/api/v1/applications`,
      null,
      application
    );
    return body;
  }

  public async updateApplication(applicationName: string, application: V1alpha1Application) {
    const { body } = await this.client.put<V1alpha1Application, V1alpha1Application>(
      `/api/v1/applications/${applicationName}`,
      null,
      application
    );
    return body;
  }

  public async deleteApplication(
    applicationName: string,
    options?: {
      appNamespace?: string;
      cascade?: boolean;
      propagationPolicy?: string;
    }
  ) {
    const queryParams: Record<string, string | boolean> = {};

    if (options?.appNamespace) {
      queryParams.appNamespace = options.appNamespace;
    }
    if (options?.cascade !== undefined) {
      queryParams.cascade = options.cascade;
    }
    if (options?.propagationPolicy) {
      queryParams.propagationPolicy = options.propagationPolicy;
    }

    const { body } = await this.client.delete<V1alpha1Application>(
      `/api/v1/applications/${applicationName}`,
      Object.keys(queryParams).length > 0 ? queryParams : undefined
    );
    return body;
  }

  public async syncApplication(
    applicationName: string,
    options?: {
      appNamespace?: string;
      dryRun?: boolean;
      prune?: boolean;
      revision?: string;
      syncOptions?: string[];
    }
  ) {
    const syncRequest: Record<string, string | boolean | string[]> = {};

    if (options?.appNamespace) {
      syncRequest.appNamespace = options.appNamespace;
    }
    if (options?.dryRun !== undefined) {
      syncRequest.dryRun = options.dryRun;
    }
    if (options?.prune !== undefined) {
      syncRequest.prune = options.prune;
    }
    if (options?.revision) {
      syncRequest.revision = options.revision;
    }
    if (options?.syncOptions) {
      syncRequest.syncOptions = options.syncOptions;
    }

    const { body } = await this.client.post<V1alpha1Application, V1alpha1Application>(
      `/api/v1/applications/${applicationName}/sync`,
      null,
      Object.keys(syncRequest).length > 0 ? syncRequest : undefined
    );
    return body;
  }

  public async getApplicationResourceTree(applicationName: string, appNamespace?: string) {
    const queryParams = appNamespace ? { appNamespace } : undefined;
    const { body } = await this.client.get<V1alpha1ApplicationTree>(
      `/api/v1/applications/${applicationName}/resource-tree`,
      queryParams
    );
    return body;
  }

  public async getApplicationManagedResources(
    applicationName: string,
    filters?: {
      namespace?: string;
      name?: string;
      version?: string;
      group?: string;
      kind?: string;
      appNamespace?: string;
      project?: string;
    }
  ) {
    const { body } = await this.client.get<{ items: V1alpha1ResourceDiff[] }>(
      `/api/v1/applications/${applicationName}/managed-resources`,
      filters
    );
    return body;
  }

  public async getApplicationLogs(applicationName: string) {
    const logs: ApplicationLogEntry[] = [];
    await this.client.getStream<ApplicationLogEntry>(
      `/api/v1/applications/${applicationName}/logs`,
      {
        follow: false,
        tailLines: 100
      },
      (chunk) => logs.push(chunk)
    );
    return logs;
  }

  public async getWorkloadLogs(
    applicationName: string,
    applicationNamespace: string,
    resourceRef: V1alpha1ResourceResult,
    container: string
  ) {
    const logs: ApplicationLogEntry[] = [];
    await this.client.getStream<ApplicationLogEntry>(
      `/api/v1/applications/${applicationName}/logs`,
      {
        appNamespace: applicationNamespace,
        namespace: resourceRef.namespace,
        resourceName: resourceRef.name,
        group: resourceRef.group,
        kind: resourceRef.kind,
        version: resourceRef.version,
        follow: false,
        tailLines: 100,
        container: container
      },
      (chunk) => logs.push(chunk)
    );
    return logs;
  }

  public async getPodLogs(applicationName: string, podName: string) {
    const logs: ApplicationLogEntry[] = [];
    await this.client.getStream<ApplicationLogEntry>(
      `/api/v1/applications/${applicationName}/pods/${podName}/logs`,
      {
        follow: false,
        tailLines: 100
      },
      (chunk) => logs.push(chunk)
    );
    return logs;
  }

  public async getApplicationEvents(applicationName: string, appNamespace?: string) {
    const queryParams = appNamespace ? { appNamespace } : undefined;
    const { body } = await this.client.get<V1EventList>(
      `/api/v1/applications/${applicationName}/events`,
      queryParams
    );
    return body;
  }

  public async getResource(
    applicationName: string,
    applicationNamespace: string,
    resourceRef: V1alpha1ResourceResult
  ) {
    const { body } = await this.client.get<V1alpha1ApplicationResourceResult>(
      `/api/v1/applications/${applicationName}/resource`,
      {
        appNamespace: applicationNamespace,
        namespace: resourceRef.namespace,
        resourceName: resourceRef.name,
        group: resourceRef.group,
        kind: resourceRef.kind,
        version: resourceRef.version
      }
    );
    return body.manifest;
  }

  public async getResourceEvents(
    applicationName: string,
    applicationNamespace: string,
    resourceUID: string,
    resourceNamespace: string,
    resourceName: string
  ) {
    const { body } = await this.client.get<V1EventList>(
      `/api/v1/applications/${applicationName}/events`,
      {
        appNamespace: applicationNamespace,
        resourceNamespace,
        resourceUID,
        resourceName
      }
    );
    return body;
  }

  public async getResourceActions(
    applicationName: string,
    applicationNamespace: string,
    resourceRef: V1alpha1ResourceResult
  ) {
    const { body } = await this.client.get<{ actions: V1alpha1ResourceAction[] }>(
      `/api/v1/applications/${applicationName}/resource/actions`,
      {
        appNamespace: applicationNamespace,
        namespace: resourceRef.namespace,
        resourceName: resourceRef.name,
        group: resourceRef.group,
        kind: resourceRef.kind,
        version: resourceRef.version
      }
    );
    return body;
  }

  public async runResourceAction(
    applicationName: string,
    applicationNamespace: string,
    resourceRef: V1alpha1ResourceResult,
    action: string
  ) {
    const { body } = await this.client.post<string, V1alpha1Application>(
      `/api/v1/applications/${applicationName}/resource/actions`,
      {
        appNamespace: applicationNamespace,
        namespace: resourceRef.namespace,
        resourceName: resourceRef.name,
        group: resourceRef.group,
        kind: resourceRef.kind,
        version: resourceRef.version
      },
      action
    );
    return body;
  }

  public async patchResource(
    applicationName: string,
    applicationNamespace: string | undefined,
    resourceRef: V1alpha1ResourceResult,
    patch: string,
    patchType: string
  ) {
    const queryParams: Record<string, string | undefined> = {
      namespace: resourceRef.namespace,
      resourceName: resourceRef.name,
      group: resourceRef.group,
      kind: resourceRef.kind,
      version: resourceRef.version,
      patchType
    };
    if (applicationNamespace) {
      queryParams.appNamespace = applicationNamespace;
    }
    // The API takes the patch as a JSON-encoded string body (like the action
    // name in runResourceAction), so the patch string is passed through as-is.
    const { body } = await this.client.post<string, V1alpha1ApplicationResourceResult>(
      `/api/v1/applications/${applicationName}/resource`,
      queryParams,
      patch
    );
    return body;
  }

  public async deleteResource(
    applicationName: string,
    applicationNamespace: string | undefined,
    resourceRef: V1alpha1ResourceResult,
    options?: { force?: boolean; orphan?: boolean }
  ) {
    const queryParams: Record<string, string | boolean | undefined> = {
      namespace: resourceRef.namespace,
      resourceName: resourceRef.name,
      group: resourceRef.group,
      kind: resourceRef.kind,
      version: resourceRef.version
    };
    if (applicationNamespace) {
      queryParams.appNamespace = applicationNamespace;
    }
    if (options?.force !== undefined) {
      queryParams.force = options.force;
    }
    if (options?.orphan !== undefined) {
      queryParams.orphan = options.orphan;
    }
    const { body } = await this.client.delete<ApplicationApplicationResponse>(
      `/api/v1/applications/${applicationName}/resource`,
      queryParams
    );
    return body;
  }

  public async terminateOperation(applicationName: string, appNamespace?: string) {
    const queryParams = appNamespace ? { appNamespace } : undefined;
    const { body } = await this.client.delete<ApplicationOperationTerminateResponse>(
      `/api/v1/applications/${applicationName}/operation`,
      queryParams
    );
    return body;
  }
}
