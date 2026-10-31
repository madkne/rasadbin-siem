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
  "alerts.page": { total: number; limit: number; offset: number };
  "alert.updated": Alert;
  "alert.notes": { alert_id: string; notes: AlertNote[] };
  "alert.history": { alert_id: string; history: AlertHistoryEntry[] };
  "alert.note.added": AlertNote;
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
  profiles: InstalledProfile[];
  "profile.validated": ProfilePreview;
  "profile.installed": ProfileInstalledPayload;
  "profile.deleted": ProfileDeletedPayload;
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
  status:
    | "new"
    | "acknowledged"
    | "investigating"
    | "resolved"
    | "false_positive";
  assignee?: string;
  updated_at?: string;
  resolved_at?: string | null;
}

export interface AlertNote {
  id: number;
  alert_id: string;
  author: string;
  body: string;
  created_at: string;
}

export interface AlertHistoryEntry {
  id: number;
  alert_id: string;
  action: string;
  from_status?: string;
  to_status?: string;
  actor?: string;
  details?: string;
  created_at: string;
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


// Security profile archive and installation API.
export interface SecurityProfileMetadata {
  id: string;
  name: string;
  version: string;
  description?: string;
  author?: string;
  tags?: string[];
}
export interface SecurityProfileManifest {
  apiVersion: string;
  kind: string;
  metadata: SecurityProfileMetadata;
}
export interface ProfileIntegration {
  id: string;
  enabled: boolean;
  alerting?: boolean;
}
export interface ProfilePreview {
  manifest: SecurityProfileManifest;
  rules: string[];
  integrations: ProfileIntegration[];
  config_files: string[];
  warnings: string[];
}
export interface InstalledProfile {
  manifest: SecurityProfileManifest;
  installed_at: string;
  rule_ids: string[];
  integrations: ProfileIntegration[];
  previous_integrations?: Array<{ id: string; enabled: boolean; alerting: boolean }>;
  config_files: string[];
}
export interface ProfileInstalledPayload {
  profile: InstalledProfile;
}
export interface ProfileDeletedPayload {
  id: string;
  profiles: InstalledProfile[];
}
