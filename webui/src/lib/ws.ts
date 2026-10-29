import type { Envelope } from "./types";

const TOKEN_KEY = "rasadbin.token";

type Handler<T = unknown> = (data: T) => void;
type StatusHandler = (connected: boolean) => void;

class WebSocketClient {
  private ws: WebSocket | null = null;
  private ready = false;
  private retries = 0;
  private leaving = false;
  private authRequired = false;
  private outbox: Array<[string, unknown]> = [];
  private handlers = new Map<string, Set<Handler>>();
  private statusHandlers = new Set<StatusHandler>();

  get token(): string | null {
    return sessionStorage.getItem(TOKEN_KEY);
  }

  setToken(t: string | null) {
    if (t) sessionStorage.setItem(TOKEN_KEY, t);
    else sessionStorage.removeItem(TOKEN_KEY);
  }

  on<T = unknown>(type: string, fn: Handler<T>): () => void {
    let set = this.handlers.get(type);
    if (!set) {
      set = new Set();
      this.handlers.set(type, set);
    }
    set.add(fn as Handler);
    return () => set!.delete(fn as Handler);
  }

  onStatus(fn: StatusHandler): () => void {
    this.statusHandlers.add(fn);
    return () => this.statusHandlers.delete(fn);
  }

  send(type: string, data?: unknown) {
    if (this.ready && this.ws?.readyState === WebSocket.OPEN) {
      this.raw(type, data);
    } else {
      this.outbox.push([type, data]);
    }
  }

  connect(opts: { auth: boolean }) {
    this.authRequired = opts.auth;
    this.leaving = false;
    this.open();
  }

  disconnect() {
    this.leaving = true;
    this.ws?.close();
  }

  private raw(type: string, data: unknown) {
    this.ws?.send(JSON.stringify({ type, data }));
  }

  private emit(type: string, data: unknown) {
    this.handlers.get(type)?.forEach((fn) => fn(data));
  }

  private emitStatus(up: boolean) {
    this.statusHandlers.forEach((fn) => fn(up));
  }

  private goLogin() {
    this.leaving = true;
    this.setToken(null);
    if (location.pathname !== "/login") location.replace("/login");
    else window.dispatchEvent(new CustomEvent("rasadbin:goto-login"));
  }

  private applyIdentity(me: { username: string; role: string; instance_name?: string }) {
    if (me.instance_name) document.title = me.instance_name;
    window.dispatchEvent(new CustomEvent("rasadbin:identity", { detail: me }));
  }

  private open() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    this.ws = new WebSocket(`${proto}//${location.host}/ws`);

    this.ws.onopen = () => {
      this.retries = 0;
      this.emitStatus(true);
      if (this.authRequired) {
        const t = this.token;
        if (!t) return this.goLogin();
        this.raw("auth", { token: t });
      } else {
        this.ready = true;
        this.flush();
        this.emit("open", undefined);
      }
    };

    this.ws.onmessage = (ev) => {
      let m: Envelope;
      try {
        m = JSON.parse(ev.data as string) as Envelope;
      } catch {
        return;
      }

      switch (m.type) {
        case "auth_ok": {
          this.ready = true;
          const d = m.data as Identity;
          this.applyIdentity(d);
          this.flush();
          this.emit("ready", d);
          return;
        }
        case "auth_failed":
        case "session_expired":
        case "logged_out":
        case "password_changed":
          this.goLogin();
          return;
      }

      this.emit(m.type, m.data);
    };

    this.ws.onclose = () => {
      this.ready = false;
      this.emitStatus(false);
      this.emit("close", undefined);
      if (this.leaving) return;
      this.retries++;
      const delay = Math.min(10000, 500 * 2 ** this.retries);
      setTimeout(() => this.open(), delay);
    };
  }

  private flush() {
    while (this.outbox.length) {
      const [t, d] = this.outbox.shift()!;
      this.raw(t, d);
    }
  }
}

// Need Identity type in scope for applyIdentity above.
import type { Identity } from "./types";

export const ws = new WebSocketClient();

export function fmtDuration(totalSec: number): string {
  const sec = Math.floor(totalSec);
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}