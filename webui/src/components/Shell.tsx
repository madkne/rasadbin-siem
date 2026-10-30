import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { ws } from "../lib/ws";
import type { Alert, Identity } from "../lib/types";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: "D", admin: false },
  { to: "/discover", label: "Discover", icon: "S", admin: false },
  { to: "/alerts", label: "Alerts", icon: "A", admin: false },
  { to: "/rules", label: "Rules", icon: "R", admin: true },
  { to: "/integrations", label: "Integrations", icon: "I", admin: true },
  { to: "/profiles", label: "Profiles", icon: "P", admin: true },
  { to: "/settings", label: "Settings", icon: "T", admin: true },
];

export default function Shell({ children }: { children: React.ReactNode }) {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const [connected, setConnected] = useState(false);
  const [me, setMe] = useState<Identity | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [search, setSearch] = useState("");
  const [navOpen, setNavOpen] = useState(false);
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
    const onIdentity = (e: Event) =>
      setMe((e as CustomEvent<Identity>).detail);
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

  const alertCount = alerts.length;

  useEffect(() => {
    setNavOpen(false);
  }, [pathname]);

  function submitSearch(e: React.FormEvent) {
    e.preventDefault();
    const q = search.trim();
    navigate(q ? `/discover?q=${encodeURIComponent(q)}` : "/discover");
  }

  return (
    <div className="app-shell">
      {navOpen && (
        <button
          type="button"
          className="side-nav-overlay"
          aria-label="Close navigation"
          onClick={() => setNavOpen(false)}
        />
      )}
      <aside
        className={`side-nav ${navOpen ? "open" : ""}`}
        aria-label="Primary navigation"
      >
        <div className="side-brand">
          <span className="side-brand-mark">R</span>
          <div>
            <div className="side-brand-name">{me?.instance_name ?? "Rasadbin"}</div>
            <div className="side-brand-sub">Security Intelligence</div>
          </div>
        </div>
        <nav className="side-nav-list">
          {NAV.filter((n) => !n.admin || me?.role === "admin").map((n) => {
            const active =
              n.to === "/integrations"
                ? pathname.startsWith("/integrations")
                : pathname === n.to;
            return (
              <Link
                key={n.to}
                to={n.to}
                className={`side-nav-item ${active ? "active" : ""}`}
              >
                <span className="side-nav-icon" aria-hidden>
                  {n.icon}
                </span>
                <span>{n.label}</span>
                {n.to === "/alerts" && alertCount > 0 && (
                  <span className="side-nav-badge">
                    {alertCount > 99 ? "99+" : alertCount}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>
        <div className="side-nav-footer">
          <span className={`dot ${connected ? "on" : ""}`} />
          <span className="muted">
            {connected ? "Connected" : "Reconnecting"}
          </span>
        </div>
      </aside>

      <div className="app-main">
        <header className="topbar">
          <button
            type="button"
            className="side-nav-toggle"
            aria-label="Toggle navigation"
            aria-expanded={navOpen}
            onClick={() => setNavOpen((v) => !v)}
          >
            ☰
          </button>
          <form className="topbar-search" onSubmit={submitSearch}>
            <span className="topbar-search-icon" aria-hidden>
              ⌕
            </span>
            <input
              type="search"
              placeholder="Search events, sources, rules…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Global search"
            />
          </form>
          <span className="spacer" />
          <span className="topbar-user">
            {me ? `${me.username} · ${me.role}` : ""}
          </span>
          <button
            className="ghost topbar-signout"
            type="button"
            onClick={() => ws.send("logout")}
          >
            Sign out
          </button>
        </header>
        <div className="app-content">{children}</div>
      </div>
    </div>
  );
}
