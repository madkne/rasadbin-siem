import { useEffect, useState, type ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { ws } from "../lib/ws";
import type { Identity } from "../lib/types";

interface Props {
  children: ReactNode;
  requireAdmin?: boolean;
}

// Waits for the socket to authenticate before rendering. If the token is
// missing or the session has expired, redirects to /login.
export default function RequireAuth({ children, requireAdmin }: Props) {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [failed, setFailed] = useState(!ws.token);

  useEffect(() => {
    if (!ws.token) {
      setFailed(true);
      return;
    }
    const offReady = ws.on("ready", (me) => {
      setIdentity(me);
      setFailed(false);
    });
    ws.connect({ auth: true });
    return () => {
      offReady();
    };
  }, []);

  if (failed) return <Navigate to="/login" replace />;
  if (!identity) return <p className="muted" style={{ padding: 24 }}>Connecting…</p>;
  if (requireAdmin && identity.role !== "admin") {
    return <Navigate to="/dashboard" replace />;
  }
  return <>{children}</>;
}
