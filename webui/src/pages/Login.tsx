import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ws } from "../lib/ws";

export default function Login() {
  const nav = useNavigate();
  const [connected, setConnected] = useState(ws.isConnected);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const pwRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const offStatus = ws.onStatus(setConnected);
    const offOk = ws.on("login_ok", () => nav("/dashboard", { replace: true }));
    const offFail = ws.on("login_failed", (d) => {
      setMsg(d.message || "Sign-in failed. Check your credentials and try again.");
      setBusy(false); setPassword(""); pwRef.current?.focus();
    });
    ws.connect({ auth: false });
    return () => { offStatus(); offOk(); offFail(); };
  }, [nav]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!connected || busy) return;
    setMsg(""); setBusy(true);
    ws.send("login", { username: username.trim(), password });
  }

  return <div className="login-shell">
    <aside className="login-aside">
      <div className="login-brand"><span className="brand-mark">R</span><span>RASADBIN<span className="brand-sub">SECURITY INTELLIGENCE</span></span></div>
      <div className="login-pitch"><div className="eyebrow">LINUX-FIRST SIEM</div><h1>See what’s happening.<br /><em>Know what matters.</em></h1>
        <p>A focused command center for system health, security telemetry, and the signals that deserve your attention.</p></div>
      <div className="login-aside-foot"><span className="live-dot" /> Local instance · Protected access</div>
    </aside>
    <main className="login-main">
      <section className="login-card">
        <div className="login-card-heading"><div className="eyebrow">ADMINISTRATOR ACCESS</div><h2>Welcome back</h2><p>Sign in to open your security workspace.</p></div>
        <form onSubmit={submit}>
          <label>Username<input autoComplete="username" maxLength={128} required autoFocus value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Enter your username" /></label>
          <label>Password<input ref={pwRef} type="password" autoComplete="current-password" maxLength={128} required value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Enter your password" /></label>
          {msg && <p className="msg error" role="alert">{msg}</p>}
          <button className="sign-in-button" type="submit" disabled={!connected || busy}>{busy ? <><span className="button-spinner" /> Signing in…</> : "Sign in securely"} <span aria-hidden="true">→</span></button>
        </form>
        <div className={`connection-note ${connected ? "connected" : ""}`}><span className="live-dot" />{connected ? "Secure channel available" : "Connecting to local service…"}</div>
      </section>
      <footer className="login-footer">Rasadbin <span>·</span> Security monitoring, built for Linux</footer>
    </main>
  </div>;
}
