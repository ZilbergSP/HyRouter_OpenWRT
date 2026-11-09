// The shapes of hyrouterd's API (internal/web).

export type Action = 'direct' | 'tunnel' | 'block';

export interface Rule {
  id?: string;
  name: string;
  enabled?: boolean;
  devices?: string[];
  domains?: string[];
  protocol?: string;
  ports?: string;
  action: Action;
  profile?: string;
  fallback?: string[];
}

export interface RulesConfig {
  defaultAction: Action;
  defaultProfile?: string;
  defaultFallback?: string[];
  rules: Rule[];
}

export interface Server {
  id: string;
  name: string;
  protocol?: string;
  host: string;
  ports: string;
  source?: string;
  missing?: boolean;
}

export type Strategy = 'failover' | 'latency' | 'roundrobin' | 'random' | 'sticky';

export interface Group {
  id: string;
  name: string;
  strategy: Strategy;
  members: string[];
  subs?: string[];
  revert?: boolean;
  toleranceMs?: number;
  switchAfterErrors?: number;
}

export interface GroupProbe {
  url?: string;
  intervalSec?: number;
}

export interface GroupsFile {
  version: number;
  probe?: GroupProbe;
  groups: Group[];
}

export interface MemberStatus {
  id: string;
  latencyMs: number;
  error?: string;
  errors: number;
  skipped: boolean;
  reason?: string;
}

export interface GroupStatus {
  id: string;
  active: string;
  up: number;
  running: string[];
  probeBroken: boolean;
  rejected: number;
  used: boolean;
  members: MemberStatus[];
}

export interface Device {
  id: string;
  name: string;
  macs?: string[];
  addrs?: string[];
}

export interface Settings {
  enabled: boolean;
  lan: string[];
  main: string;
  dns: { byRules: boolean; tunnel: { preset: string } };
  tunnelPort: number;
  namePort: number;
  dnsPort: number;
  webPort: number;
  killSwitch?: boolean;
  stats: boolean;
  geo: { source?: string; auto: boolean };
}

export interface SubInfo {
  summary: string;
  details: string;
  level: '' | 'low' | 'out';
  warning: string;
  usedPct: number;
  percent: number;
}

export interface Sub {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  intervalH: number;
  lastUpdate?: string;
  lastAttempt?: string;
  lastError?: string;
  count: number;
  warnings?: string[];
  ignored?: Record<string, number>;
  viaVPN?: boolean;
  supportUrl?: string;
  info: SubInfo | null;
  servers: number;
  missing: number;
}

export interface MergeStats {
  added: number;
  updated: number;
  removed: number;
  missingKept: number;
}

export interface StateView {
  edition: string;
  lite: boolean;
  vless: boolean;
  groupRun: number;
  settings: Settings;
  servers: Server[];
  rules: RulesConfig;
  devices: Device[];
  groups: GroupsFile;
  subs: Sub[];
  strategies: { id: Strategy; name: string }[];
  dnsPresets: { id: string; name: string }[];
}

export interface ServerStatus {
  id: string;
  name: string;
  state: 'stopped' | 'connecting' | 'connected' | 'failed';
  message: string;
  udp: boolean;
  restarts: number;
  sent: number;
  recv: number;
}

export interface Status {
  edition: string;
  running: boolean;
  since: string;
  error?: string;
  issues: string[];
  servers: ServerStatus[];
  groups: GroupStatus[];
  relay: number;
  guard: boolean;
}

export interface Session {
  loggedIn: boolean;
  csrf?: string;
  version: string;
}

export interface Neighbour {
  mac: string;
  ip: string;
  name: string;
}

export interface LogEntry {
  seq: number;
  time: string;
  level: string;
  msg: string;
}

export interface EditResp {
  state: StateView;
}
