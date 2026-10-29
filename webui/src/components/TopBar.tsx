import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { ws } from "../lib/ws";
import type { Identity } from "../lib/types";

export default function TopBar() {
  const { pathname } = useLocation();
  const [connected, setConnected] = useState(false);
  const [me, setMe] = useState<Identity | null>(null);

  useEffect(() => {
    const offStatus = ws.onStatus(setConnected);
    const offIdentity = ws.on("ready", setMe);

    const onIdentity = (e: Event) => setMe((e as CustomEvent<Identity>).detail);
    window.addEventListener("rasadbin:identity", onIdentity);

    return () => {
      offStatus();
      offIdentity();
      window.removeEventListener("rasadbin:identity", onIdentity);
    };
  }, []);

  const brand = me?.instance_name ?? "Rasadbin";

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
        </Link>
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
