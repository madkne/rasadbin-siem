import { Fragment, useEffect, useState } from "react";
import Shell from "../components/Shell";
import { ws } from "../lib/ws";
import type { Alert, AlertHistoryEntry, AlertNote } from "../lib/types";

const STATUSES: Alert["status"][] = [
  "new", "acknowledged", "investigating", "resolved", "false_positive",
];

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");
  const [notes, setNotes] = useState<Record<string, AlertNote[]>>({});
  const [history, setHistory] = useState<Record<string, AlertHistoryEntry[]>>({});
  const [noteDraft, setNoteDraft] = useState("");
  const [assigneeDraft, setAssigneeDraft] = useState("");
  const [total, setTotal] = useState(0);

  useEffect(() => {
    const subscribe = () => {
      ws.send("subscribe", { topic: "dashboard" });
      ws.send("alerts.get", { limit: 500, offset: 0 });
    };
    const mergeAlert = (updated: Alert) => setAlerts((prev) => {
      const idx = prev.findIndex((x) => x.id === updated.id);
      if (idx < 0) return [updated, ...prev];
      const next = [...prev];
      next[idx] = updated;
      return next;
    });
    const offReady = ws.on("ready", subscribe);
    const offAlerts = ws.on("alerts", (a) => setAlerts(a ?? []));
    const offAlert = ws.on("alert", mergeAlert);
    const offPage = ws.on("alerts.page", (page) => setTotal(page.total));
    const offUpdated = ws.on("alert.updated", (updated) => {
      mergeAlert(updated);
      ws.send("alert.history.get", { id: updated.id });
    });
    const offNotes = ws.on("alert.notes", (payload) => {
      setNotes((prev) => ({ ...prev, [payload.alert_id]: payload.notes ?? [] }));
    });
    const offHistory = ws.on("alert.history", (payload) => {
      setHistory((prev) => ({ ...prev, [payload.alert_id]: payload.history ?? [] }));
    });
    const offNoteAdded = ws.on("alert.note.added", (note) => {
      setNotes((prev) => ({ ...prev, [note.alert_id]: [...(prev[note.alert_id] ?? []), note] }));
      ws.send("alert.history.get", { id: note.alert_id });
      setNoteDraft("");
    });
    const offErr = ws.on("error", (e) => {
      if (["alerts.get", "alert.update", "alert.note.add", "alert.notes.get"].includes(e.for ?? "")) {
        setError(e.message);
      }
    });
    if (ws.isReady) subscribe();
    return () => {
      offReady(); offAlerts(); offAlert(); offPage(); offUpdated(); offNotes(); offHistory(); offNoteAdded(); offErr();
      if (ws.isReady) ws.send("unsubscribe");
    };
  }, []);

  const filteredAlerts = alerts.filter((a) => {
    if (severityFilter && a.severity !== severityFilter) return false;
    if (statusFilter && a.status !== statusFilter) return false;
    if (search && !`${a.title} ${a.description} ${a.source} ${a.rule_id} ${a.source_ip ?? ""}`.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const updateAlert = (a: Alert, status: Alert["status"], assignee = a.assignee ?? "") => {
    setError("");
    ws.send("alert.update", { id: a.id, status, assignee });
  };

  const openAlert = (a: Alert) => {
    const next = expanded === a.id ? null : a.id;
    setExpanded(next);
    if (next) {
      setAssigneeDraft(a.assignee ?? "");
      setNoteDraft("");
      ws.send("alert.notes.get", { id: a.id });
      ws.send("alert.history.get", { id: a.id });
    }
  };

  const statuses = [...new Set(alerts.map((a) => a.status).filter(Boolean))];

  return (
    <Shell>
      <main className="discover-page">
        <div className="page-heading">
          <div>
            <p className="eyebrow">DETECTION</p>
            <h1>Alerts</h1>
            <p className="muted">Persistent detection alerts and analyst workflow.</p>
          </div>
          <span className="integration-count">{filteredAlerts.length} shown · {total || alerts.length} total</span>
        </div>
        <section className="discover-querybar">
          <input className="discover-search-input" placeholder="Search alerts…" value={search} onChange={(e) => setSearch(e.target.value)} />
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} aria-label="Severity filter">
            <option value="">All severities</option>
            {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} aria-label="Status filter">
            <option value="">All statuses</option>
            {statuses.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
          </select>
          <button type="button" className="ghost" onClick={() => ws.send("alerts.get", { search, severity: severityFilter, status: statusFilter, limit: 500, offset: 0 })}>Refresh</button>
        </section>
        {error && <p className="msg error" role="alert">{error}</p>}
        <section className="discover-results">
          <div className="table-wrap">
            <table>
              <thead><tr>
                <th style={{ width: 100 }}>Severity</th><th>Title</th><th style={{ width: 140 }}>Source</th>
                <th style={{ width: 80 }}>Count</th><th style={{ width: 160 }}>Last seen</th><th style={{ width: 130 }}>Status</th>
              </tr></thead>
              <tbody>
                {filteredAlerts.map((a) => {
                  const open = expanded === a.id;
                  return <Fragment key={a.id}>
                    <tr className={`discover-row ${open ? "expanded" : ""}`} onClick={() => openAlert(a)} tabIndex={0}
                      onKeyDown={(ev) => { if (ev.key === "Enter") openAlert(a); }}>
                      <td><span className={`sev sev-${a.severity.replace(/[^a-z]/g, "")}`}><i />{a.severity}</span></td>
                      <td>{a.title}</td><td><span className="source-tag">{a.source || "system"}</span></td>
                      <td>{a.count}</td><td className="time-cell">{a.last_seen ? new Date(a.last_seen).toLocaleString() : "—"}</td>
                      <td>{a.status.replace("_", " ")}</td>
                    </tr>
                    {open && <tr className="discover-doc"><td colSpan={6}>
                      <div className="alert-detail">
                        <p>{a.description}</p>
                        {a.source_ip && <p className="muted">Source IP: {a.source_ip}</p>}
                        {a.evidence?.length ? <pre>{a.evidence.join("\n")}</pre> : null}
                        <p className="muted">Rule: {a.rule_id} · First seen: {a.first_seen ? new Date(a.first_seen).toLocaleString() : "—"}</p>
                        <div className="discover-querybar">
                          <label>Status <select value={a.status} onChange={(e) => updateAlert(a, e.target.value as Alert["status"])}>
                            {STATUSES.map((status) => <option key={status} value={status}>{status.replace("_", " ")}</option>)}
                          </select></label>
                          <label>Assignee <input value={assigneeDraft} onChange={(e) => setAssigneeDraft(e.target.value)} placeholder="Analyst username" /></label>
                          <button type="button" onClick={() => updateAlert(a, a.status, assigneeDraft)}>Save assignment</button>
                        </div>
                        <section className="card">
                          <h3>Activity history</h3>
                          {(history[a.id] ?? []).map((entry) => <p key={entry.id} className="muted">
                            {entry.action === "status_changed" ? `${entry.from_status} → ${entry.to_status}` : entry.details || entry.action}
                            {entry.actor ? ` · ${entry.actor}` : ""} · {new Date(entry.created_at).toLocaleString()}
                          </p>)}
                          {(history[a.id] ?? []).length === 0 && <p className="muted">No activity recorded.</p>}
                        </section>
                        <section className="card">
                          <h3>Analyst notes</h3>
                          {(notes[a.id] ?? []).map((note) => <article key={note.id}>
                            <p>{note.body}</p><small className="muted">{note.author} · {new Date(note.created_at).toLocaleString()}</small>
                          </article>)}
                          {(notes[a.id] ?? []).length === 0 && <p className="muted">No notes yet.</p>}
                          <textarea value={noteDraft} onChange={(e) => setNoteDraft(e.target.value)} maxLength={10000} placeholder="Add investigation notes…" />
                          <button type="button" disabled={!noteDraft.trim()} onClick={() => ws.send("alert.note.add", { id: a.id, body: noteDraft })}>Add note</button>
                        </section>
                      </div>
                    </td></tr>}
                  </Fragment>;
                })}
              </tbody>
            </table>
            {filteredAlerts.length === 0 && <div className="empty-state"><strong>No alerts</strong><p>Alerts will appear here when detection rules fire.</p></div>}
          </div>
        </section>
      </main>
    </Shell>
  );
}