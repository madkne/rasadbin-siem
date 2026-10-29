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