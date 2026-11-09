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
}

export interface StateView {
  edition: string;
  lite: boolean;
  vless: boolean;
  settings: Settings;
  servers: Server[];
  rules: RulesConfig;
  devices: Device[];
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
  relay: number;
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
