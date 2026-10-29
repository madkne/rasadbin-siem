import type { Envelope, Identity, WsMessageMap } from "./types";

const TOKEN_KEY = "rasadbin.token";
type Handler<T = unknown> = (data: T) => void;
type StatusHandler = (connected: boolean) => void;

class WebSocketClient {
  private socket: WebSocket | null = null;
  private ready = false;
  private connected = false;
  private retries = 0;
  private leaving = false;
  private authRequired = false;
  private reconnectTimer: number | null = null;
  private generation = 0;
  private outbox: Array<[string, unknown]> = [];
  private handlers = new Map<string, Set<Handler>>();
  private statusHandlers = new Set<StatusHandler>();
  private identity: Identity | null = null;

  get token(): string | null {
    return sessionStorage.getItem(TOKEN_KEY);
  }
  get isReady(): boolean {
    return this.ready;
  }
  get isConnected(): boolean {
    return this.connected;
  }

  setToken(token: string | null) {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  }

  on<K extends string = string>(type: K, fn: (data: K extends keyof WsMessageMap ? WsMessageMap[K] : unknown) => void): () => void {
    let set = this.handlers.get(type);
    if (!set) {
      set = new Set();
      this.handlers.set(type, set);
    }
    set.add(fn as Handler);
    // Authentication can finish before protected components mount. Replay the
    // latest identity so those components don't miss the one-time ready event.
    if (type === "ready" && this.ready && this.identity) (fn as Handler)(this.identity);
    return () => set!.delete(fn as Handler);
  }

  onStatus(fn: StatusHandler): () => void {
    this.statusHandlers.add(fn);
    fn(this.connected);
    return () => this.statusHandlers.delete(fn);
  }

  send(type: string, data?: unknown) {
    if (this.ready && this.socket?.readyState === WebSocket.OPEN)
      this.raw(type, data);
    else if (
      type === "login" ||
      type === "auth" ||
      type === "logout" ||
      type === "subscribe" ||
      type === "unsubscribe" ||
      type.startsWith("settings.") ||
      type.startsWith("password.")
    ) {
      // Keep bounded, but don't queue credentials or commands across a new
      // socket/session. Authentication commands are sent only on an open socket.
      if (type === "login" && this.socket?.readyState === WebSocket.OPEN)
        this.raw(type, data);
      else if (type !== "login" && type !== "auth" && type !== "logout") {
        if (this.outbox.length < 32) this.outbox.push([type, data]);
      }
    }
  }

  connect(opts: { auth: boolean }) {
    const modeChanged = this.authRequired !== opts.auth;
    this.authRequired = opts.auth;
    this.leaving = false;
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (
      this.socket &&
      (this.socket.readyState === WebSocket.OPEN ||
        this.socket.readyState === WebSocket.CONNECTING)
    ) {
      if (modeChanged) {
        this.ready = false;
        this.identity = null;
        if (this.socket.readyState === WebSocket.OPEN && this.authRequired)
          this.authenticate();
        else if (
          this.socket.readyState === WebSocket.OPEN &&
          !this.authRequired
        ) {
          this.ready = true;
          this.flush();
          this.emit("open", undefined);
        }
      } else if (
        this.authRequired &&
        this.socket.readyState === WebSocket.OPEN &&
        !this.ready
      ) {
        this.authenticate();
      }
      return;
    }
    this.open();
  }

  disconnect() {
    this.leaving = true;
    this.ready = false;
    this.identity = null;
    if (this.reconnectTimer !== null) window.clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    this.socket?.close(1000, "client disconnect");
  }

  private raw(type: string, data: unknown) {
    if (this.socket?.readyState === WebSocket.OPEN)
      this.socket.send(JSON.stringify({ type, data }));
  }

  private emit(type: string, data: unknown) {
    this.handlers.get(type)?.forEach((fn) => fn(data));
  }
  private emitStatus(up: boolean) {
    this.connected = up;
    this.statusHandlers.forEach((fn) => fn(up));
  }

  private goLogin() {
    this.leaving = true;
    this.ready = false;
    this.identity = null;
    this.outbox = [];
    this.setToken(null);
    if (location.pathname !== "/login") location.replace("/login");
    else window.dispatchEvent(new CustomEvent("rasadbin:goto-login"));
  }

  private applyIdentity(me: Identity) {
    this.identity = me;
    if (me.instance_name) document.title = `${me.instance_name} · Rasadbin`;
    window.dispatchEvent(new CustomEvent("rasadbin:identity", { detail: me }));
  }

  private authenticate() {
    const token = this.token;
    if (!token) {
      this.goLogin();
      return;
    }
    this.raw("auth", { token });
  }

  private open() {
    if (this.leaving) return;
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    const generation = ++this.generation;
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    let socket: WebSocket;
    try {
      socket = new WebSocket(`${proto}//${location.host}/ws`);
    } catch {
      this.scheduleReconnect(generation);
      return;
    }
    this.socket = socket;

    socket.onopen = () => {
      if (generation !== this.generation) {
        socket.close();
        return;
      }
      this.retries = 0;
      this.emitStatus(true);
      if (this.authRequired) this.authenticate();
      else {
        this.retries = 0;
        this.ready = true;
        this.flush();
        this.emit("open", undefined);
      }
    };

    socket.onmessage = (ev) => {
      if (generation !== this.generation) return;
      let message: Envelope;
      try {
        if (typeof ev.data !== "string") return;
        message = JSON.parse(ev.data) as Envelope;
      } catch {
        return;
      }

      switch (message.type) {
        case "auth_ok": {
          const me = message.data as Identity;
          this.retries = 0;
          this.ready = true;
          this.applyIdentity(me);
          this.flush();
          this.emit("ready", me);
          return;
        }
        case "auth_failed":
        case "session_expired":
        case "logged_out":
        case "password_changed":
          this.goLogin();
          return;
        case "login_ok":
          this.setToken((message.data as { token: string }).token);
          break;
        case "login_failed":
          break;
      }
      this.emit(message.type, message.data);
    };

    socket.onerror = () => {
      // onclose owns reconnect handling; this prevents duplicate retry timers.
    };

    socket.onclose = () => {
      if (generation !== this.generation) return;
      this.socket = null;
      this.ready = false;
      this.identity = null;
      this.emitStatus(false);
      this.emit("close", undefined);
      if (!this.leaving) this.scheduleReconnect(generation);
    };
  }

  private scheduleReconnect(generation: number) {
    if (this.leaving || this.reconnectTimer !== null) return;

    this.retries++;

    const delay = Math.min(30_000, 1_000 * 2 ** Math.min(this.retries - 1, 5));

    const jitter = Math.floor(Math.random() * 500);

    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;

      if (!this.leaving && generation === this.generation) {
        this.open();
      }
    }, delay + jitter);
  }

  private flush() {
    while (this.ready && this.outbox.length) {
      const [type, data] = this.outbox.shift()!;
      this.raw(type, data);
    }
  }
}

export const ws = new WebSocketClient();

export function fmtDuration(totalSec: number): string {
  const sec = Math.max(0, Math.floor(totalSec));
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}
