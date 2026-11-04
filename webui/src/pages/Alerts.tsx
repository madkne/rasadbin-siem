import { Fragment, useEffect, useMemo, useState } from "react";
import { ws } from "../lib/ws";
import type { Alert, AlertHistoryEntry, AlertNote } from "../lib/types";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";

const STATUSES: Alert["status"][] = [
  "new",
  "acknowledged",
  "investigating",
  "resolved",
  "false_positive",
];

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

const severityMeta: Record<string, { label: string; className: string }> = {
  critical: { label: "Critical", className: "sev sev-critical" },
  high: { label: "High", className: "sev sev-high" },
  medium: { label: "Medium", className: "sev sev-medium" },
  low: { label: "Low", className: "sev sev-low" },
  info: { label: "Info", className: "sev sev-info" },
};

const statusMeta: Record<string, { label: string; className: string }> = {
  new: { label: "New", className: "status-pill status-new" },
  acknowledged: {
    label: "Acknowledged",
    className: "status-pill status-ack",
  },
  investigating: {
    label: "Investigating",
    className: "status-pill status-investigating",
  },
  resolved: { label: "Resolved", className: "status-pill status-resolved" },
  false_positive: {
    label: "False positive",
    className: "status-pill status-fp",
  },
};

function formatRelativeTime(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return "Just now";
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}h ago`;
  const diffDay = Math.floor(diffHour / 24);
  if (diffDay < 7) return `${diffDay}d ago`;
  return date.toLocaleString();
}

function formatFullTime(value?: string) {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");
  const [notes, setNotes] = useState<Record<string, AlertNote[]>>({});
  const [history, setHistory] = useState<Record<string, AlertHistoryEntry[]>>(
    {},
  );
  const [noteDraft, setNoteDraft] = useState("");
  const [assigneeDraft, setAssigneeDraft] = useState("");
  const [total, setTotal] = useState(0);
  const [activeTab, setActiveTab] = useState<"overview" | "activity" | "notes">(
    "overview",
  );

  useEffect(() => {
    const subscribe = () => {
      ws.send("subscribe", { topic: "dashboard" });
      ws.send("alerts.get", { limit: 500, offset: 0 });
    };
    const mergeAlert = (updated: Alert) =>
      setAlerts((prev) => {
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
      setNotes((prev) => ({
        ...prev,
        [payload.alert_id]: payload.notes ?? [],
      }));
    });
    const offHistory = ws.on("alert.history", (payload) => {
      setHistory((prev) => ({
        ...prev,
        [payload.alert_id]: payload.history ?? [],
      }));
    });
    const offNoteAdded = ws.on("alert.note.added", (note) => {
      setNotes((prev) => ({
        ...prev,
        [note.alert_id]: [...(prev[note.alert_id] ?? []), note],
      }));
      ws.send("alert.history.get", { id: note.alert_id });
      setNoteDraft("");
    });
    const offErr = ws.on("error", (e) => {
      if (
        [
          "alerts.get",
          "alert.update",
          "alert.note.add",
          "alert.notes.get",
        ].includes(e.for ?? "")
      ) {
        setError(e.message);
      }
    });
    if (ws.isReady) subscribe();
    return () => {
      offReady();
      offAlerts();
      offAlert();
      offPage();
      offUpdated();
      offNotes();
      offHistory();
      offNoteAdded();
      offErr();
      if (ws.isReady) ws.send("unsubscribe");
    };
  }, []);

  const filteredAlerts = alerts.filter((a) => {
    if (severityFilter && a.severity !== severityFilter) return false;
    if (statusFilter && a.status !== statusFilter) return false;
    if (
      search &&
      !`${a.title} ${a.description} ${a.source} ${a.rule_id} ${a.source_ip ?? ""}`
        .toLowerCase()
        .includes(search.toLowerCase())
    )
      return false;
    return true;
  });

  const updateAlert = (
    a: Alert,
    status: Alert["status"],
    assignee = a.assignee ?? "",
  ) => {
    setError("");
    ws.send("alert.update", { id: a.id, status, assignee });
  };

  const openAlert = (a: Alert) => {
    const next = expanded === a.id ? null : a.id;
    setExpanded(next);
    setActiveTab("overview");
    if (next) {
      setAssigneeDraft(a.assignee ?? "");
      setNoteDraft("");
      ws.send("alert.notes.get", { id: a.id });
      ws.send("alert.history.get", { id: a.id });
    }
  };

  const statuses = useMemo(
    () => [...new Set(alerts.map((a) => a.status).filter(Boolean))],
    [alerts],
  );

  const stats = useMemo(() => {
    const base = { critical: 0, high: 0, new: 0, open: 0 };
    for (const a of alerts) {
      if (a.severity === "critical") base.critical += 1;
      if (a.severity === "high") base.high += 1;
      if (a.status === "new") base.new += 1;
      if (a.status !== "resolved" && a.status !== "false_positive") {
        base.open += 1;
      }
    }
    return base;
  }, [alerts]);

  const addNote = (a: Alert) => {
    const body = noteDraft.trim();
    if (!body) return;
    ws.send("alert.note.add", { id: a.id, body });
  };

  const totalCount = total || alerts.length;
  const shownCount = filteredAlerts.length;

  return (
    <main className="discover-page alerts-page">
      <header className="page-heading alerts-header">
        <div className="alerts-header-info">
          <p className="eyebrow">DETECTION</p>
          <h1>Alerts</h1>
          <p className="muted">
            Prioritize, investigate, and track detection alerts across your
            environment.
          </p>
        </div>
        <div className="alerts-header-meta">
          <div className="alerts-count-pill">
            <span className="alerts-count-pill-label">Showing</span>
            <span className="alerts-count-pill-value">
              {shownCount} / {totalCount}
            </span>
          </div>
          <Button
            type="button"
            className="ghost"
            onClick={() =>
              ws.send("alerts.get", {
                search,
                severity: severityFilter,
                status: statusFilter,
                limit: 500,
                offset: 0,
              })
            }
          >
            Refresh
          </Button>
        </div>
      </header>

      <section className="alerts-stats">
        <article className="alert-stat-card alert-stat-critical">
          <div>
            <p className="alert-stat-label">Critical</p>
            <p className="alert-stat-value">{stats.critical}</p>
          </div>
          <span className="alert-stat-dot" />
        </article>
        <article className="alert-stat-card alert-stat-high">
          <div>
            <p className="alert-stat-label">High</p>
            <p className="alert-stat-value">{stats.high}</p>
          </div>
          <span className="alert-stat-dot" />
        </article>
        <article className="alert-stat-card alert-stat-new">
          <div>
            <p className="alert-stat-label">New</p>
            <p className="alert-stat-value">{stats.new}</p>
          </div>
          <span className="alert-stat-dot" />
        </article>
        <article className="alert-stat-card alert-stat-open">
          <div>
            <p className="alert-stat-label">Open</p>
            <p className="alert-stat-value">{stats.open}</p>
          </div>
          <span className="alert-stat-dot" />
        </article>
      </section>

      <section className="alerts-filter-bar">
        <div className="alerts-filter-search">
          <Input
            className="alerts-search-input"
            placeholder="Search by title, description, source, rule, IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search alerts"
          />
        </div>
        <div className="alerts-filter-group">
          <select
            className="alerts-select"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            aria-label="Severity filter"
          >
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {severityMeta[s].label}
              </option>
            ))}
          </select>
          <select
            className="alerts-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Status filter"
          >
            <option value="">All statuses</option>
            {statuses.map((s) => (
              <option key={s} value={s}>
                {(statusMeta[s]?.label ?? s).replace("_", " ")}
              </option>
            ))}
          </select>
          {(severityFilter || statusFilter || search) && (
            <Button
              type="button"
              className="ghost"
              onClick={() => {
                setSeverityFilter("");
                setStatusFilter("");
                setSearch("");
              }}
            >
              Clear filters
            </Button>
          )}
        </div>
      </section>

      {error && (
        <div className="alerts-error" role="alert">
          <p>{error}</p>
        </div>
      )}

      <section className="discover-results alerts-results">
        <div className="table-wrap alerts-table-wrap">
          <table className="alerts-table">
            <thead>
              <tr>
                <th style={{ width: 130 }}>Severity</th>
                <th>Alert</th>
                <th style={{ width: 150 }}>Source</th>
                <th style={{ width: 90 }}>Count</th>
                <th style={{ width: 170 }}>Last seen</th>
                <th style={{ width: 150 }}>Status</th>
                <th style={{ width: 160 }}>Assignee</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((a) => {
                const open = expanded === a.id;
                const sev = severityMeta[a.severity] ?? {
                  label: a.severity,
                  className: "sev",
                };
                const st = statusMeta[a.status] ?? {
                  label: a.status.replace("_", " "),
                  className: "status-pill",
                };
                return (
                  <Fragment key={a.id}>
                    <tr
                      className={`alerts-row ${open ? "alerts-row-expanded" : ""}`}
                      onClick={() => openAlert(a)}
                      tabIndex={0}
                      aria-expanded={open}
                      onKeyDown={(ev) => {
                        if (ev.key === "Enter" || ev.key === " ") {
                          ev.preventDefault();
                          openAlert(a);
                        }
                      }}
                    >
                      <td>
                        <span className={sev.className}>
                          <i />
                          {sev.label}
                        </span>
                      </td>
                      <td>
                        <div className="alerts-title-cell">
                          <p className="alerts-title">{a.title}</p>
                          {a.source_ip && (
                            <p className="alerts-subtitle">SRC: {a.source_ip}</p>
                          )}
                        </div>
                      </td>
                      <td>
                        <span className="source-tag">
                          {a.source || "system"}
                        </span>
                      </td>
                      <td>
                        <span className="alerts-count-badge">{a.count}</span>
                      </td>
                      <td className="time-cell">
                        <div className="time-cell-inner">
                          <span>{formatRelativeTime(a.last_seen)}</span>
                          <span className="time-cell-subtle">
                            {formatFullTime(a.last_seen)}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className={st.className}>{st.label}</span>
                      </td>
                      <td>
                        <span className={a.assignee ? "assignee-pill" : "assignee-pill assignee-empty"}>
                          {a.assignee || "Unassigned"}
                        </span>
                      </td>
                    </tr>
                    {open && (
                      <tr className="alerts-detail-row">
                        <td colSpan={7}>
                          <div className="alert-detail-panel">
                            <div className="alert-detail-header">
                              <div>
                                <div className="alert-detail-header-row">
                                  <span className={sev.className}>
                                    <i />
                                    {sev.label}
                                  </span>
                                  <span className={st.className}>{st.label}</span>
                                  <span className="detail-meta-pill">
                                    Rule: {a.rule_id}
                                  </span>
                                  {a.source_ip && (
                                    <span className="detail-meta-pill">
                                      Src IP: {a.source_ip}
                                    </span>
                                  )}
                                </div>
                                <h2 className="alert-detail-title">{a.title}</h2>
                                <p className="alert-detail-subtitle">
                                  First seen {formatFullTime(a.first_seen)} ·
                                  Last seen {formatFullTime(a.last_seen)} · Source{" "}
                                  {a.source || "system"}
                                </p>
                              </div>
                              <div className="alert-detail-quickactions">
                                <Label className="quickaction-field">
                                  <span>Status</span>
                                  <select
                                    className="alerts-select compact"
                                    value={a.status}
                                    onChange={(e) =>
                                      updateAlert(
                                        a,
                                        e.target.value as Alert["status"],
                                      )
                                    }
                                  >
                                    {STATUSES.map((status) => (
                                      <option key={status} value={status}>
                                        {(statusMeta[status]?.label ??
                                          status).replace("_", " ")}
                                      </option>
                                    ))}
                                  </select>
                                </Label>
                                <div className="quickaction-group">
                                  <Input
                                    className="assignee-input"
                                    value={assigneeDraft}
                                    onChange={(e) =>
                                      setAssigneeDraft(e.target.value)
                                    }
                                    placeholder="Assign to analyst"
                                  />
                                  <Button
                                    type="button"
                                    onClick={() =>
                                      updateAlert(a, a.status, assigneeDraft)
                                    }
                                  >
                                    Save
                                  </Button>
                                </div>
                              </div>
                            </div>

                            <div className="alert-detail-tabs">
                              <button
                                type="button"
                                className={`alert-detail-tab ${activeTab === "overview" ? "active" : ""}`}
                                onClick={() => setActiveTab("overview")}
                              >
                                Overview
                              </button>
                              <button
                                type="button"
                                className={`alert-detail-tab ${activeTab === "activity" ? "active" : ""}`}
                                onClick={() => setActiveTab("activity")}
                              >
                                Activity ({(history[a.id] ?? []).length})
                              </button>
                              <button
                                type="button"
                                className={`alert-detail-tab ${activeTab === "notes" ? "active" : ""}`}
                                onClick={() => setActiveTab("notes")}
                              >
                                Notes ({(notes[a.id] ?? []).length})
                              </button>
                            </div>

                            {activeTab === "overview" && (
                              <div className="alert-detail-grid">
                                <section className="alert-detail-card">
                                  <header className="alert-detail-card-header">
                                    <h3>Description</h3>
                                  </header>
                                  <div className="alert-detail-card-body">
                                    <p className="alert-description">
                                      {a.description}
                                    </p>
                                  </div>
                                </section>
                                {a.evidence?.length ? (
                                  <section className="alert-detail-card">
                                    <header className="alert-detail-card-header">
                                      <h3>Evidence</h3>
                                    </header>
                                    <div className="alert-detail-card-body">
                                      <pre className="alert-evidence">
                                        {a.evidence.join("\n")}
                                      </pre>
                                    </div>
                                  </section>
                                ) : null}
                                <section className="alert-detail-card alert-detail-card-compact">
                                  <header className="alert-detail-card-header">
                                    <h3>Metadata</h3>
                                  </header>
                                  <div className="alert-detail-card-body alert-meta-grid">
                                    <div>
                                      <p className="alert-meta-label">Alert ID</p>
                                      <p className="alert-meta-value mono">
                                        {a.id}
                                      </p>
                                    </div>
                                    <div>
                                      <p className="alert-meta-label">Rule ID</p>
                                      <p className="alert-meta-value mono">
                                        {a.rule_id}
                                      </p>
                                    </div>
                                    <div>
                                      <p className="alert-meta-label">Source</p>
                                      <p className="alert-meta-value">
                                        {a.source || "system"}
                                      </p>
                                    </div>
                                    <div>
                                      <p className="alert-meta-label">
                                        Source IP
                                      </p>
                                      <p className="alert-meta-value mono">
                                        {a.source_ip || "—"}
                                      </p>
                                    </div>
                                    <div>
                                      <p className="alert-meta-label">Count</p>
                                      <p className="alert-meta-value">
                                        {a.count}
                                      </p>
                                    </div>
                                    <div>
                                      <p className="alert-meta-label">Assignee</p>
                                      <p className="alert-meta-value">
                                        {a.assignee || "Unassigned"}
                                      </p>
                                    </div>
                                  </div>
                                </section>
                              </div>
                            )}

                            {activeTab === "activity" && (
                              <section className="alert-detail-card">
                                <header className="alert-detail-card-header">
                                  <h3>Investigation timeline</h3>
                                  <p className="muted">
                                    Status changes, assignments, and updates
                                  </p>
                                </header>
                                <div className="alert-detail-card-body">
                                  {(history[a.id] ?? []).length === 0 ? (
                                    <div className="timeline-empty">
                                      <strong>No activity yet</strong>
                                      <p className="muted">
                                        Updates to status, assignee, or notes
                                        will appear here.
                                      </p>
                                    </div>
                                  ) : (
                                    <ol className="timeline">
                                      {(history[a.id] ?? []).map((entry) => (
                                        <li
                                          key={entry.id}
                                          className="timeline-item"
                                        >
                                          <div className="timeline-dot" />
                                          <div className="timeline-content">
                                            <p className="timeline-title">
                                              {entry.action === "status_changed"
                                                ? `Status changed: ${entry.from_status?.replace("_", " ") || "—"} → ${entry.to_status?.replace("_", " ")}`
                                                : entry.details || entry.action.replace("_", " ")}
                                            </p>
                                            <p className="timeline-meta">
                                              {entry.actor ? `${entry.actor} · ` : ""}
                                              {formatFullTime(
                                                entry.created_at,
                                              )}
                                            </p>
                                          </div>
                                        </li>
                                      ))}
                                    </ol>
                                  )}
                                </div>
                              </section>
                            )}

                            {activeTab === "notes" && (
                              <div className="alert-detail-grid">
                                <section className="alert-detail-card">
                                  <header className="alert-detail-card-header">
                                    <h3>Analyst notes</h3>
                                    <p className="muted">
                                      Share findings and investigation context
                                    </p>
                                  </header>
                                  <div className="alert-detail-card-body">
                                    {(notes[a.id] ?? []).length === 0 ? (
                                      <div className="notes-empty">
                                        <strong>No notes yet</strong>
                                        <p className="muted">
                                          Add the first investigation note below.
                                        </p>
                                      </div>
                                    ) : (
                                      <div className="notes-list">
                                        {(notes[a.id] ?? []).map((note) => (
                                          <article
                                            key={note.id}
                                            className="note-card"
                                          >
                                            <p className="note-body">
                                              {note.body}
                                            </p>
                                            <footer className="note-footer">
                                              <span className="note-author">
                                                {note.author || "Analyst"}
                                              </span>
                                              <span className="note-time">
                                                {formatFullTime(
                                                  note.created_at,
                                                )}
                                              </span>
                                            </footer>
                                          </article>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                </section>
                                <section className="alert-detail-card">
                                  <header className="alert-detail-card-header">
                                    <h3>Add note</h3>
                                    <p className="muted">
                                      Notes are visible to all analysts
                                    </p>
                                  </header>
                                  <div className="alert-detail-card-body alert-note-form">
                                    <textarea
                                      className="note-textarea"
                                      value={noteDraft}
                                      onChange={(e) =>
                                        setNoteDraft(e.target.value)
                                      }
                                      maxLength={10000}
                                      placeholder="Document observations, IOCs, steps taken, next actions..."
                                    />
                                    <div className="note-form-footer">
                                      <span className="note-char-count">
                                        {noteDraft.length}/10000
                                      </span>
                                      <Button
                                        type="button"
                                        disabled={!noteDraft.trim()}
                                        onClick={() => addNote(a)}
                                      >
                                        Add note
                                      </Button>
                                    </div>
                                  </div>
                                </section>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
          {filteredAlerts.length === 0 && (
            <div className="empty-state alerts-empty-state">
              <strong>No alerts match your filters</strong>
              <p>
                Try adjusting severity/status filters or clearing the search
                query.
              </p>
              <Button
                type="button"
                className="ghost"
                onClick={() => {
                  setSeverityFilter("");
                  setStatusFilter("");
                  setSearch("");
                }}
              >
                Clear all filters
              </Button>
            </div>
          )}
        </div>
      </section>
    </main>
  );
}
