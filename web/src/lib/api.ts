// The client of hyrouterd's API. The session is a cookie; every change
// carries the session's CSRF token.

import type {
  Device,
  ConnView,
  EditResp,
  GeoStatus,
  Group,
  GroupProbe,
  LogEntry,
  MergeStats,
  Neighbour,
  RulesConfig,
  Session,
  StateView,
  StatsReport,
  Status,
} from './types';

export interface SubInput {
  url: string;
  name: string;
  intervalH: number;
  enabled: boolean;
}

let csrf = '';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = csrf;
  let r: Response;
  try {
    r = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    });
  } catch {
    throw new ApiError(0, 'Роутер не отвечает');
  }
  let data: unknown = null;
  try {
    data = await r.json();
  } catch {
    data = null;
  }
  if (!r.ok) {
    const msg = (data as { error?: string } | null)?.error ?? `Ошибка ${r.status}`;
    throw new ApiError(r.status, msg);
  }
  return data as T;
}

export const api = {
  async session(): Promise<Session> {
    const s = await call<Session>('GET', '/api/session');
    csrf = s.csrf ?? '';
    return s;
  },
  async login(password: string): Promise<void> {
    const r = await call<{ csrf: string }>('POST', '/api/login', { password });
    csrf = r.csrf;
  },
  logout: () => call<unknown>('POST', '/api/logout', {}),
  status: () => call<{ version: string; status: Status }>('GET', '/api/status'),
  state: () => call<StateView>('GET', '/api/state'),
  routing: (enabled: boolean) => call<{ status: Status }>('POST', '/api/routing', { enabled }),
  addServer: (link: string, name: string) =>
    call<EditResp & { warnings: string[]; id: string }>('POST', '/api/servers', { link, name }),
  renameServer: (id: string, name: string) =>
    call<EditResp>('PATCH', `/api/servers/${encodeURIComponent(id)}`, { name }),
  deleteServer: (id: string) => call<EditResp>('DELETE', `/api/servers/${encodeURIComponent(id)}`),
  setMain: (id: string) => call<EditResp>('PUT', '/api/main', { id }),
  addGroup: (g: Omit<Group, 'id'>) => call<EditResp & { id: string }>('POST', '/api/groups', g),
  editGroup: (g: Group) => call<EditResp>('PUT', `/api/groups/${encodeURIComponent(g.id)}`, g),
  deleteGroup: (id: string) => call<EditResp>('DELETE', `/api/groups/${encodeURIComponent(id)}`),
  setGroupProbe: (p: GroupProbe) => call<EditResp>('PUT', '/api/group-probe', p),
  saveRules: (cfg: RulesConfig) => call<EditResp>('PUT', '/api/rules', cfg),
  saveDevices: (devices: Device[]) => call<EditResp>('PUT', '/api/devices', devices),
  neighbours: () => call<Neighbour[]>('GET', '/api/neighbours'),
  addSub: (s: SubInput) => call<EditResp & { id: string; stats: MergeStats }>('POST', '/api/subs', s),
  editSub: (id: string, s: SubInput) => call<EditResp>('PUT', `/api/subs/${encodeURIComponent(id)}`, s),
  updateSub: (id: string) => call<EditResp & { stats: MergeStats }>('POST', `/api/subs/${encodeURIComponent(id)}/update`, {}),
  deleteSub: (id: string) => call<EditResp>('DELETE', `/api/subs/${encodeURIComponent(id)}`),
  connections: () => call<{ active: ConnView[]; closed: ConnView[] }>('GET', '/api/connections'),
  stats: (period: string) => call<StatsReport>('GET', '/api/stats?period=' + encodeURIComponent(period)),
  setStats: (enabled: boolean) => call<EditResp>('PUT', '/api/stats', { enabled }),
  resetStats: () => call<unknown>('POST', '/api/stats/reset', {}),
  geo: () => call<GeoStatus>('GET', '/api/geo'),
  saveGeo: (g: { source: string; auto: boolean }) => call<EditResp & { geo: GeoStatus }>('PUT', '/api/geo', g),
  updateGeo: () => call<GeoStatus>('POST', '/api/geo/update', {}),
  saveSettings: (s: { lan: string[]; dnsByRules: boolean; dnsTunnel: string; killSwitch: boolean }) =>
    call<EditResp>('PUT', '/api/settings', s),
  log: (after: number) => call<LogEntry[]>('GET', `/api/log?after=${after}`),
};

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
