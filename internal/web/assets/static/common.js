"use strict";

// Shared WebSocket client. Everything the UI does goes through /ws.
const RB = (() => {
  const KEY = "rasadbin.token";
  const handlers = {};
  const outbox = [];
  let ws = null, ready = false, retries = 0, leaving = false, opts = {};

  const $ = (sel) => document.querySelector(sel);
  const token = () => sessionStorage.getItem(KEY);
  const setToken = (t) => (t ? sessionStorage.setItem(KEY, t) : sessionStorage.removeItem(KEY));
  const on = (type, fn) => { handlers[type] = fn; };
  const emit = (type, data) => { if (handlers[type]) handlers[type](data); };

  function raw(type, data) {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type, data }));
  }
  function send(type, data) {
    if (ready) raw(type, data); else outbox.push([type, data]);
  }
  function flush() {
    while (outbox.length) { const [t, d] = outbox.shift(); raw(t, d); }
  }
  function setConn(up) {
    const dot = $("#conn");
    if (dot) { dot.classList.toggle("on", up); dot.title = up ? "connected" : "disconnected"; }
  }
  function goLogin() {
    leaving = true;
    setToken(null);
    location.replace("/login");
  }

  function open() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(proto + "//" + location.host + "/ws");

    ws.onopen = () => {
      retries = 0;
      setConn(true);
      if (opts.auth) {
        const t = token();
        if (!t) return goLogin();
        raw("auth", { token: t });
      } else {
        ready = true;
        flush();
        emit("open");
      }
    };

    ws.onmessage = (ev) => {
      let m;
      try { m = JSON.parse(ev.data); } catch { return; }
      switch (m.type) {
        case "auth_ok":
          ready = true;
          applyIdentity(m.data);
          flush();
          emit("ready", m.data);
          return;
        case "auth_failed":
        case "session_expired":
        case "logged_out":
        case "password_changed":
          return goLogin();
      }
      emit(m.type, m.data);
    };

    ws.onclose = () => {
      ready = false;
      setConn(false);
      emit("close");
      if (leaving) return;
      retries++;
      setTimeout(open, Math.min(10000, 500 * 2 ** retries));
    };
  }

  function applyIdentity(me) {
    const user = $("#user");
    if (user) user.textContent = me.username + " (" + me.role + ")";
    const brand = $("#brand");
    if (brand && me.instance_name) {
      brand.textContent = me.instance_name;
      document.title = document.title.replace("Rasadbin", me.instance_name);
    }
    document.querySelectorAll("[data-admin]").forEach((el) => { el.hidden = me.role !== "admin"; });
  }

  function connect(options) {
    opts = options || {};
    const logout = $("#logout");
    if (logout) logout.addEventListener("click", () => send("logout"));
    open();
  }

  function fmtDuration(sec) {
    const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600),
      m = Math.floor(sec % 3600 / 60), s = sec % 60;
    if (d) return d + "d " + h + "h";
    if (h) return h + "h " + m + "m";
    if (m) return m + "m " + s + "s";
    return s + "s";
  }

  return { connect, send, on, token, setToken, fmtDuration };
})();
