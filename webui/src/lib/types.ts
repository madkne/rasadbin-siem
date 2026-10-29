export type Role = "admin" | "user";

export interface Identity {
  username: string;
  role: Role;
  expires_at?: string;
  instance_name?: string;
}

export interface Session {
  username: string;
  role: Role;
  expiresAt: number;
}

export interface Stats {
  time: string;
  uptime_seconds: number;
  version: string;
  commit: string;
  goroutines: number;
  heap_mb: number;
  sys_mb: number;
  gc_cycles: number;
  clients: number;
  events_total: number;
}

export interface EventEntry {
  time: string;
  source: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  message: string;
}

export interface DashboardPayload {
  stats: Stats;
  events: EventEntry[];
}

export interface Settings {
  instance_name: string;
  log_level: "debug" | "info" | "warn" | "error";
  session_minutes: number;
  retention_days: number;
  refresh_seconds: number;
}

export interface ErrorPayload {
  for?: string;
  message: string;
}

// Wire envelope — mirrors internal/web/hub.go:message.
export interface Envelope<T = unknown> {
  type: string;
  data?: T;
}
export interface SearchQuery {
  query?: string;
  severity?: string;
  sources?: string[];
  from?: string; // RFC3339
  to?: string;
  limit?: number;
  sort_desc?: boolean;
}

export interface HistogramBucket {
  time: string;
  count: number;
}

export interface SearchResult {
  events: EventEntry[];
  total: number;
  buckets: HistogramBucket[] | null;
  took_ms: number;
}

export interface Alert {
  id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  first_seen: string;
  last_seen: string;
  count: number;
  source: string;
  source_ip?: string;
  evidence?: string[];
  status: string;
}

export interface Integration {
  id: string;
  name: string;
  description: string;
  category: string;
  enabled: boolean;
  collector: string;
  processor: string;
  detections: string[];
  alerting: boolean;
  status: string;
  updated_at?: string;
}

export interface LoginOk {
  token: string;
  username: string;
  role: string;
  expires_at: string;
}

// Typed map of WebSocket message types to their payload shapes.
export interface WsMessageMap {
  ready: Identity;
  open: undefined;
  close: undefined;
  dashboard: DashboardPayload;
  stats: Stats;
  event: EventEntry;
  alert: Alert;
  alerts: Alert[];
  integrations: Integration[];
  rules: DetectionRule[];
  "rule.saved": { rule: DetectionRule; rules: DetectionRule[] };
  "rule.deleted": { id: string; rules: DetectionRule[] };
  "rule.validated": { valid: boolean; message: string };
  integration_saved: Integration;
  "integration.events": { id: string; events: EventEntry[] };
  "integration.status": { id: string; status: string };
  "discover.results": SearchResult;
  "discover.sources": string[];
  "match_terms": string[];
  settings: Settings;
  settings_saved: Settings;
  error: ErrorPayload;
  session_expired: null;
  logged_out: null;
  password_changed: null;
  login_ok: LoginOk;
  login_failed: ErrorPayload;
  auth_ok: Identity;
  auth_failed: null;
}

export interface DetectionRule {
  id: string;
  title: string;
  description: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  enabled: boolean;
  sources: string[];
  match_any: string[];
  threshold: number;
  window_seconds: number;
  dedup_seconds: number;
  kind: string;
}
