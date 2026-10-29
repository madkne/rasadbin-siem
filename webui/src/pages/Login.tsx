import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ws } from "../lib/ws";
import type { ErrorPayload } from "../lib/types";

interface LoginOk {
  token: string;
  username: string;
  role: string;
  expires_at: string;
}

export default function Login() {
  const nav = useNavigate();
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const pwRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    ws.connect({ auth: false });
    const offStatus = ws.onStatus(setConnected);
    const offOk = ws.on<LoginOk>("login_ok", (d) => {
      ws.setToken(d.token);
      nav("/dashboard", { replace: true });
    });
    const offFail = ws.on<ErrorPayload>("login_failed", (d) => {
      setMsg(d.message);
      setBusy(false);
      setPassword("");
      pwRef.current?.focus();
    });
    return () => {
      offStatus();
      offOk();
      offFail();
    };
  }, [nav]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setMsg("");
    setBusy(true);
    ws.send("login", { username: username.trim(), password });
  }

  return (
    <div className="center">
      <main className="card login">
        <h1>Rasadbin</h1>
        <p className="muted">Sign in to continue</p>
        <form onSubmit={submit}>
          <label>
            Username
            <input
              autoComplete="username"
              maxLength={128}
              required
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </label>
          <label>
            Password
            <input
              ref={pwRef}
              type="password"
              autoComplete="current-password"
              maxLength={128}
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <button type="submit" disabled={!connected || busy}>
            {!connected ? "Connecting…" : busy ? "Signing in…" : "Sign in"}
          </button>
          {msg && <p className="msg error" role="alert">{msg}</p>}
        </form>
      </main>
    </div>
  );
}