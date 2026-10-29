import { Fragment, useEffect, useState } from "react";
import TopBar from "../components/TopBar";
import { ws } from "../lib/ws";
import type { Alert } from "../lib/types";

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    const subscribe = () => {
      ws.send("subscribe", { topic: "dashboard" });
      ws.send("alerts.get");
    };
    const offReady = ws.on("ready", subscribe);
    const offAlerts = ws.on<Alert[]>("alerts", (a) => setAlerts(a ?? []));
    const offAlert = ws.on<Alert>("alert", (a) => {
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
    const offErr = ws.on<{ for?: string; message: string }>("error", (e) => {
      if (e.for === "alerts.get") {
        setError(e.message);
      }
    });
    if (ws.isReady) subscribe();
    return () => {
      offReady();
      offAlerts();
      offAlert();
      offErr();
      if (ws.isReady) ws.send("unsubscribe");
    };
  }, []);

  return (
    <>
      <TopBar />
      <main className="discover-page">
        <div className="page-heading">
          <div>
            <p className="eyebrow">DETECTION</p>
            <h1>Alerts</h1>
            <p className="muted">Rule-based alerts raised by the detection engine.</p>
          </div>
          <span className="integration-count">{alerts.length} alerts</span>
        </div>
        {error && <p className="msg error" role="alert">{error}</p>}
        <section className="discover-results">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 100 }}>Severity</th>
                  <th>Title</th>
                  <th style={{ width: 140 }}>Source</th>
                  <th style={{ width: 80 }}>Count</th>
                  <th style={{ width: 160 }}>Last seen</th>
                  <th style={{ width: 100 }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => {
                  const open = expanded === a.id;
                  return (
                    <Fragment key={a.id}>
                      <tr
                        className={`discover-row ${open ? "expanded" : ""}`}
                        onClick={() => setExpanded(open ? null : a.id)}
                        tabIndex={0}
                        onKeyDown={(ev) => {
                          if (ev.key === "Enter") setExpanded(open ? null : a.id);
                        }}
                      >
                        <td>
                          <span className={`sev sev-${a.severity.replace(/[^a-z]/g, "")}`}>
                            <i />
                            {a.severity}
                          </span>
                        </td>
                        <td>{a.title}</td>
                        <td>
                          <span className="source-tag">{a.source || "system"}</span>
                        </td>
                        <td>{a.count}</td>
                        <td className="time-cell">
                          {a.last_seen ? new Date(a.last_seen).toLocaleString() : "—"}
                        </td>
                        <td>{a.status}</td>
                      </tr>
                      {open && (
                        <tr key={a.id + "-doc"} className="discover-doc">
                          <td colSpan={6}>
                            <div>
                              <p>{a.description}</p>
                              {a.source_ip && <p className="muted">Source IP: {a.source_ip}</p>}
                              {a.evidence?.length ? (
                                <pre>{a.evidence.join("\n")}</pre>
                              ) : null}
                              <p className="muted">
                                Rule: {a.rule_id} · First seen:{" "}
                                {a.first_seen ? new Date(a.first_seen).toLocaleString() : "—"}
                              </p>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
            {alerts.length === 0 && (
              <div className="empty-state">
                <strong>No alerts</strong>
                <p>Alerts will appear here when detection rules fire.</p>
              </div>
            )}
          </div>
        </section>
      </main>
    </>
  );
}