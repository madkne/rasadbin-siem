import { useEffect, useMemo, useState } from "react";
import TopBar from "../components/TopBar";
import { fmtDuration, ws } from "../lib/ws";
import type { EventEntry, Stats } from "../lib/types";

const MAX_POINTS = 60;
const MAX_EVENTS = 50;

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [events, setEvents] = useState<EventEntry[]>([]);
  const [heap, setHeap] = useState<number[]>([]);
  const [severity, setSeverity] = useState("all");

  useEffect(() => {
    const subscribe = () => ws.send("subscribe", { topic: "dashboard" });
    const offReady = ws.on("ready", subscribe);
    const offDash = ws.on("dashboard", (d) => {
      setStats(d.stats);
      setEvents(d.events ?? []);
      pushHeap(d.stats.heap_mb);
    });
    const offStats = ws.on("stats", (s) => {
      setStats(s);
      pushHeap(s.heap_mb);
    });
    const offEvent = ws.on("event", (e) => setEvents((prev) => [e, ...prev].slice(0, MAX_EVENTS)));
    // If this component mounts after auth completes, subscribe immediately.
    if (ws.isReady) subscribe();
    function pushHeap(value: number) {
      setHeap((prev) => [...prev.slice(-(MAX_POINTS - 1)), value]);
    }
    return () => {
      offReady(); offDash(); offStats(); offEvent();
      if (ws.isReady) ws.send("unsubscribe");
    };
  }, []);

  const visibleEvents = useMemo(
    () => severity === "all" ? events : events.filter((e) => e.severity === severity),
    [events, severity],
  );

  return <>
    <TopBar />
    <main className="dashboard">
      <section className="page-heading">
        <div>
          <div className="eyebrow">SECURITY OPERATIONS / OVERVIEW</div>
          <h1>System overview</h1>
          <p className="muted">Live health and runtime activity for your Rasadbin instance.</p>
        </div>
        <div className={`live-pill ${ws.isConnected ? "is-live" : ""}`}>
          <span className="live-dot" />{ws.isConnected ? "Live connection" : "Reconnecting"}
        </div>
      </section>

      <section className="metric-grid" aria-label="System metrics">
        <Stat label="Uptime" value={stats ? fmtDuration(stats.uptime_seconds) : "—"} detail="Since service start" icon="◷" />
        <Stat label="Events received" value={stats ? stats.events_total.toLocaleString() : "—"} detail="Lifetime in this process" icon="⌁" />
        <Stat label="Connected clients" value={stats ? String(stats.clients) : "—"} detail="Authenticated sessions" icon="◎" />
        <Stat label="Goroutines" value={stats ? stats.goroutines.toLocaleString() : "—"} detail="Go runtime workers" icon="⤢" />
      </section>

      <section className="content-grid">
        <article className="panel memory-panel">
          <div className="panel-heading">
            <div><div className="eyebrow">RUNTIME TELEMETRY</div><h2>Heap memory</h2></div>
            <span className="metric-chip">{stats ? `${stats.heap_mb.toFixed(1)} MB` : "Waiting…"}</span>
          </div>
          <HeapChart values={heap} />
          <div className="chart-foot"><span>Recent samples</span><span>Auto-updated</span></div>
        </article>
        <article className="panel runtime-panel">
          <div className="eyebrow">INSTANCE DETAILS</div><h2>Runtime status</h2>
          <Detail label="Version" value={stats?.version ?? "—"} />
          <Detail label="Commit" value={stats?.commit ?? "—"} mono />
          <Detail label="System memory" value={stats ? `${stats.sys_mb.toFixed(1)} MB` : "—"} />
          <Detail label="GC cycles" value={stats ? stats.gc_cycles.toLocaleString() : "—"} />
          <Detail label="Last update" value={stats ? new Date(stats.time).toLocaleTimeString() : "Waiting for data"} />
        </article>
      </section>

      <section className="panel events-panel">
        <div className="panel-heading events-heading">
          <div><div className="eyebrow">LIVE TELEMETRY</div><h2>Recent events <span className="count">{events.length}</span></h2></div>
          <label className="filter-label">Severity
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="all">All events</option><option value="critical">Critical</option>
              <option value="high">High</option><option value="medium">Medium</option>
              <option value="low">Low</option><option value="info">Info</option>
            </select>
          </label>
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Time</th><th>Source</th><th>Severity</th><th>Event</th></tr></thead>
            <tbody>{visibleEvents.map((e, i) => <tr key={`${e.time}-${i}`}>
              <td className="time-cell">{new Date(e.time).toLocaleTimeString()}</td>
              <td><span className="source-tag">{e.source || "system"}</span></td>
              <td><span className={`sev sev-${e.severity.replace(/[^a-z]/g, "")}`}><i />{e.severity}</span></td>
              <td className="event-message">{e.message}</td>
            </tr>)}</tbody>
          </table>
          {visibleEvents.length === 0 && <div className="empty-state">
            <span className="empty-icon">⌁</span><strong>{events.length ? "No events match this filter" : "No events collected yet"}</strong>
            <p>{events.length ? "Choose another severity to see more activity." : "The live feed is ready. Events will appear here when collectors publish them."}</p>
          </div>}
        </div>
        <footer className="panel-footer"><span><span className="live-dot" /> Live feed</span><span>Showing up to {MAX_EVENTS} latest events</span></footer>
      </section>
    </main>
  </>;
}

function Stat({ label, value, detail, icon }: { label: string; value: string; detail: string; icon: string }) {
  return <article className="metric-card"><div className="metric-top"><span>{label}</span><span className="metric-icon">{icon}</span></div>
    <strong className="metric-value">{value}</strong><span className="metric-detail">{detail}</span></article>;
}
function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div className="detail-row"><span>{label}</span><strong className={mono ? "mono" : ""}>{value}</strong></div>;
}
function HeapChart({ values }: { values: number[] }) {
  const points = useMemo(() => {
    if (values.length < 1) return "";
    const max = Math.max(...values, 1) * 1.15;
    return values.map((v, i) => `${(i / Math.max(MAX_POINTS - 1, 1)) * 300},${58 - (v / max) * 48}`).join(" ");
  }, [values]);
  return <div className="chart-area"><svg id="heap" viewBox="0 0 300 64" preserveAspectRatio="none" role="img" aria-label="Heap memory history">
    {[12, 28, 44, 60].map((y) => <line key={y} x1="0" y1={y} x2="300" y2={y} className="chart-gridline" />)}
    {points && <><polyline points={points} className="chart-line" /><circle cx={points.split(" ").at(-1)?.split(",")[0]} cy={points.split(" ").at(-1)?.split(",")[1]} r="2.8" className="chart-point" /></>}
  </svg></div>;
}
