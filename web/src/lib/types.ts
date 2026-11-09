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

export interface GeoSource {
  id: string;
  name: string;
  short: string;
  description: string;
  size: string;
}

// A well-known geosite (kind "site") or geoip ("ip") category and the
// databases that have it.
export interface GeoCategory {
  name: string;
  kind: 'site' | 'ip';
  title: string;
  hint: string;
  group: string;
  sources: string[];
}

export interface GeoStatus {
  source: string;
  sources: GeoSource[];
  auto: boolean;
  updated?: string;
  checked?: string;
  error?: string;
  busy: boolean;
  sites: string[];
  ips: string[];
  missing: string[];
  categories: GeoCategory[];
}

export interface ConnView {
  id: number;
  process: string;
  path: string;
  proto: string;
  src: string;
  dst: string;
  domain: string;
  domainSrc: string;
  rule: string;
  route: string;
  profile: string;
  outcome: string;
  group?: string;
  failover?: boolean;
  sent: number;
  recv: number;
  start: string;
  closed: boolean;
}

export interface StatsCounters {
  tc?: number;
  tu?: number;
  td?: number;
  dc?: number;
  du?: number;
  bc?: number;
  f?: number;
  fo?: number;
}

export interface StatsRow extends StatsCounters {
  k: string;
  n?: string;
  gone?: boolean;
}

export interface StatsReport {
  period: string;
  from: string;
  to: string;
  total: StatsCounters;
  days: (StatsCounters & { day: string })[];
  apps: StatsRow[] | null;
  servers: StatsRow[] | null;
  groups: StatsRow[] | null;
  months: string[] | null;
  mode: string;
  storeError?: string;
}

export interface RestorePlan {
  token: string;
  created: string;
  edition: string;
  servers: number;
  rules: number;
  devices: number;
  groups: number;
  subs: number;
  routing: boolean;
  warnings: string[];
}

export interface ZapretView {
  available: boolean;
  routing: boolean;
  settings: {
    enabled: boolean;
    targets: string[] | null;
    sites?: string[] | null;
    methods?: Record<string, string> | null;
    via?: Record<string, string> | null;
    autoHeal?: boolean;
  };
  status: { state: string; error?: string; restarts: number; lines: string[] };
  error?: string;
  network: string;
  wan: string[];
  offload: boolean;
  targets: { target: string; name: string; on: boolean; fixed?: string; picked?: string; using: string; via?: string }[];
  methods: { id: string; name: string }[];
  pick?: {
    running: boolean;
    step: string;
    done: number;
    total: number;
    results: Record<string, string> | null;
    tried: number;
    diagnosis?: Record<string, { kind: string; text: string; detail: string; bypass: boolean }> | null;
    error?: string;
    skipped?: string[];
    auto?: boolean;
    why?: string;
  };
  commandLine?: string;
  healNote?: string;
}

export interface MergeStats {
  added: number;
  updated: number;
  removed: number;
  missingKept: number;
}

// The router's system: OpenWrt, or KeeneticOS with Entware.
export type Platform = 'openwrt' | 'keenetic';

export interface StateView {
  platform: Platform;
  // stopCommand stops HyRouter from SSH.
  stopCommand: string;
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
  undo: { at: string; partial: boolean } | null;
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
  platform: Platform;
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
  platform?: Platform;
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
