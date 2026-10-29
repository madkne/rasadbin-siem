import { useEffect, useMemo, useState } from "react";
import TopBar from "../components/TopBar";
import { fmtDuration, ws } from "../lib/ws";
import type { DashboardPayload, EventEntry, Stats } from "../lib/types";

const MAX_POINTS = 60;
const MAX_EVENTS = 50;

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [events, setEvents] = useState<EventEntry[]>([]);
  const [heap, setHeap] = useState<number[]>([]);

  useEffect(() => {
    const offReady = ws.on("ready", () => ws.send("subscribe", { topic: "dashboard" }));

    const offDash = ws.on<DashboardPayload>("dashboard", (d) => {
      setStats(d.stats);
      setEvents(d.events ?? []);
      pushHeap(d.stats.heap_mb);
    });

    const offStats = ws.on<Stats>("stats", (s) => {
      setStats(s);
      pushHeap(s.heap_mb);
    });

    const offEvent = ws.on<EventEntry>("event", (e) => {
      setEvents((prev) => [e, ...prev].slice(0, MAX_EVENTS));
    });

    function pushHeap(v: number) {
      setHeap((prev) => [...prev.slice(-(MAX_POINTS - 1)), v]);
    }

    return () => {
      offReady();
      offDash();
      offStats();
      offEvent();
    };
  }, []);

  return (
    <>
      <TopBar />
      <main>
        <section className="grid">
          <Stat label="Uptime" value={stats ? fmtDuration(stats.uptime_seconds) : "–"} />
          <Stat label="Events received" value={stats ? stats.events_total.toLocaleString() : "–"} />
          <Stat label="Signed-in clients" value={stats ? String(stats.clients) : "–"} />
          <Stat label="Goroutines" value={stats ? String(stats.goroutines) : "–"} />
          <Stat label="Heap" value={stats ? `${stats.heap_mb.toFixed(1)} MB` : "–"} />
          <Stat label="Version" value={stats ? `${stats.version} (${stats.commit})` : "–"} />
        </section>

        <section className="card">
          <h2>Heap memory (last few minutes)</h2>
          <HeapChart values={heap} />
        </section>

        <section className="card">
          <h2>Recent events</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Severity</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e, i) => (
                  <tr key={`${e.time}-${i}`}>
                    <td>{new Date(e.time).toLocaleTimeString()}</td>
                    <td>{e.source}</td>
                    <td>
                      <span className={`sev sev-${e.severity.replace(/[^a-z]/g, "")}`}>
                        {e.severity}
                      </span>
                    </td>
                    <td>{e.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {events.length === 0 && (
            <p className="muted">No events yet. Collectors are not implemented yet.</p>
          )}
        </section>
      </main>
    </>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="card stat">
      <span className="label">{label}</span>
      <span className="value">{value}</span>
    </div>
  );
}

function HeapChart({ values }: { values: number[] }) {
  const points = useMemo(() => {
    if (values.length === 0) return "";
    const max = Math.max(...values, 1) * 1.1;
    return values
      .map((v, i) => {
        const x = (i / (MAX_POINTS - 1)) * 300;
        const y = 60 - (v / max) * 60;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  }, [values]);

  return (
    <svg id="heap" viewBox="0 0 300 60" preserveAspectRatio="none" role="img" aria-label="Heap memory chart">
      {points && (
        <polyline
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          vectorEffect="non-scaling-stroke"
          points={points}
        />
      )}
    </svg>
  );
}