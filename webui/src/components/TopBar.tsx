import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { ws } from "../lib/ws";
import type { Alert, Identity } from "../lib/types";

export default function TopBar() {
  const { pathname } = useLocation();
  const [connected, setConnected] = useState(false);
  const [me, setMe] = useState<Identity | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);

  useEffect(() => {
    const offStatus = ws.onStatus(setConnected);
    const offReady = ws.on("ready", (identity) => {
      setMe(identity);
      ws.send("alerts.get");
    });

    const offAlerts = ws.on("alerts", (a) => setAlerts(a ?? []));
    const offAlert = ws.on("alert", (a) => {
      setAlerts((prev) => {
        const idx = prev.findIndex((x) => x.id === a.id);
        if (idx >= 0) {
          const next = [...prev];
          next[idx] = a;
          return next;
        }
        return [a, ...prev];
      });
    });

    const onIdentity = (e: Event) => setMe((e as CustomEvent<Identity>).detail);
    window.addEventListener("rasadbin:identity", onIdentity);

    if (ws.isReady) ws.send("alerts.get");

    return () => {
      offStatus();
      offReady();
      offAlerts();
      offAlert();
      window.removeEventListener("rasadbin:identity", onIdentity);
    };
  }, []);

  const brand = me?.instance_name ?? "Rasadbin";
  const alertCount = alerts.length;

  return (
    <header className="topbar">
      <span className="brand">{brand}</span>
      <nav>
        <Link
          to="/dashboard"
          className={pathname === "/dashboard" ? "active" : ""}
        >
          Dashboard
        </Link>
        <Link
          to="/discover"
          className={pathname === "/discover" ? "active" : ""}
        >
          Discover
        </Link>
        <Link
          to="/alerts"
          className={pathname === "/alerts" ? "active" : ""}
        >
          Alerts
          {alertCount > 0 && (
            <span
              className="badge alert-badge"
              data-testid="alerts-badge"
              id="alerts-badge"
              aria-label={`${alertCount} alerts`}
            >
              {alertCount > 99 ? "99+" : alertCount}
            </span>
          )}
        </Link>
        {me?.role === "admin" && (
          <Link to="/rules" className={pathname === "/rules" ? "active" : ""}>
            Rules
          </Link>
        )}
        {me?.role === "admin" && (
          <Link
            to="/integrations"
            className={pathname.startsWith("/integrations") ? "active" : ""}
          >
            Integrations
          </Link>
        )}

        {me?.role === "admin" && (
          <Link
            to="/settings"
            className={pathname === "/settings" ? "active" : ""}
          >
            Settings
          </Link>
        )}
      </nav>
      <span className="spacer" />
      <span
        className={`dot${connected ? " on" : ""}`}
        title={connected ? "WebSocket connected" : "WebSocket disconnected"}
        role="status"
        aria-label={
          connected ? "WebSocket connected" : "WebSocket disconnected"
        }
      />
      <span className="muted">{me ? `${me.username} (${me.role})` : ""}</span>
      <button className="ghost" type="button" onClick={() => ws.send("logout")}>
        Sign out
      </button>
    </header>
  );
}
