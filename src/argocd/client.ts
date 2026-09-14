import {
  ApplicationLogEntry,
  V1alpha1Application,
  V1alpha1ApplicationList,
  V1alpha1ApplicationSource,
  V1alpha1ApplicationDestination,
  V1alpha1ApplicationTree,
  V1EventList,
  V1alpha1ResourceAction,
  V1alpha1ResourceDiff,
  V1alpha1ResourceResult,
  V1alpha1ApplicationResourceResult,
  V1alpha1ClusterList,
  ApplicationApplicationResponse,
  ApplicationOperationTerminateResponse,
  V1alpha1AppProject
} from '../types/argocd-types.js';
import { HttpClient, type TokenSource } from './http.js';

export interface ListApplicationsParams {
  /** Case-insensitive substring match on the application name. Applied locally. */
  search?: string;
  /** Restrict to a single ArgoCD project. Sent to the API as `projects`. */
  project?: string;
  /** Kubernetes label selector matched against Application resources. */
  selector?: string;
  /** Exact repository URL match. */
  repo?: string;
  /** Namespace the Application resources live in. */
  appNamespace?: string;
  limit?: number;
  offset?: number;
}

export interface ApplicationSourceSummary {
  repoURL?: string;
  path?: string;
  chart?: string;
  targetRevision?: string;
  ref?: string;
}

/**
 * Compact projection of an Application for list responses. Rendered Helm
 * values, resource lists, operation history and managed fields are omitted;
 * getApplication returns the complete object.
 */
export interface ApplicationSummary {
  name?: string;
  namespace?: string;
  project?: string;
  labels?: Record<string, string>;
  createdAt?: string;
  source?: ApplicationSourceSummary;
  sources?: ApplicationSourceSummary[];
  destination?: V1alpha1ApplicationDestination;
  sync: { status?: string; revision?: string; revisions?: string[] };
  health: { status?: string; message?: string };
  operationPhase?: string;
  autoSync: boolean;
}

const summarizeSource = (source: V1alpha1ApplicationSource): ApplicationSourceSummary => ({
  repoURL: source.repoURL,
  path: source.path,
  chart: source.chart,
  targetRevision: source.targetRevision,
  ref: source.ref
});

export const summarizeApplication = (app: V1alpha1Application): ApplicationSummary => ({
  name: app.metadata?.name,
  namespace: app.metadata?.namespace,
  project: app.spec?.project,
  labels: app.metadata?.labels,
  createdAt: app.metadata?.creationTimestamp,
  source: app.spec?.source ? summarizeSource(app.spec.source) : undefined,
  sources: app.spec?.sources?.map(summarizeSource),
  destination: app.spec?.destination,
  sync: {
    status: app.status?.sync?.status,
    revision: app.status?.sync?.revision,
    revisions: app.status?.sync?.revisions
  },
  health: {
    status: app.status?.health?.status,
    message: app.status?.health?.message
  },
  operationPhase: app.status?.operationState?.phase,
  autoSync: Boolean(app.spec?.syncPolicy?.automated)
});

export class ArgoCDClient {
  private baseUrl: string;
  private client: HttpClient;

  constructor(baseUrl: string, token: TokenSource) {
    this.baseUrl = baseUrl;
    this.client = new HttpClient(this.baseUrl, token);
  }

  public async listApplications(params: ListApplicationsParams = {}) {
    // Only parameters the ArgoCD API understands are sent upstream. Anything
    // else is silently dropped by the server, so it must be handled locally.
    const query: Record<string, string> = {};
    if (params.project) query.projects = params.project;
    if (params.selector) query.selector = params.selector;
    if (params.repo) query.repo = params.repo;
    if (params.appNamespace) query.appNamespace = params.appNamespace;

    const { body } = await this.client.get<V1alpha1ApplicationList>(
      `/api/v1/applications`,
      Object.keys(query).length > 0 ? query : undefined
    );

    // The list endpoint has no free-text search and no server-side pagination.
    // Filter by name first so that totals and paging reflect the matches, then
    // reduce only the returned page to the summary shape.
    const needle = params.search?.trim().toLowerCase();
    const matched = (body.items ?? []).filter(
      (app) => !needle || (app.metadata?.name ?? '').toLowerCase().includes(needle)
    );

    const offset = params.offset ?? 0;
    const end = params.limit ? offset + params.limit : matched.length;
    const items = matched.slice(offset, end).map(summarizeApplication);

    return {
      items,
      metadata: {
        resourceVersion: body.metadata?.resourceVersion,
        totalItems: matched.length,
        returnedItems: items.length,
        offset,
        hasMore: end < matched.length
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

  public async getAppProject(projectName: string) {
    const { body } = await this.client.get<V1alpha1AppProject>(`/api/v1/projects/${projectName}`);
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
