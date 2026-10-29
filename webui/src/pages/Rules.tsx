import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import TopBar from "../components/TopBar";
import { ws } from "../lib/ws";
import type { DetectionRule, ErrorPayload } from "../lib/types";


const blankRule = (): DetectionRule => ({
  id: "",
  title: "",
  description: "",
  severity: "medium",
  enabled: true,
  sources: [],
  match_any: [],
  threshold: 5,
  window_seconds: 60,
  dedup_seconds: 300,
  kind: "threshold",
});
const severities = ["info", "low", "medium", "high", "critical"] as const;
const kinds = ["threshold", "ssh_brute_force", "port_scan", "auth_failures"];

export default function Rules() {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [draft, setDraft] = useState<DetectionRule>(blankRule);
  const [editing, setEditing] = useState(false);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [validated, setValidated] = useState<boolean | null>(null);
  const [matchTerms, setMatchTerms] = useState<string[]>([]);

  const availableMatchTerms = useMemo(() => {
    const seen = new Set<string>(matchTerms);
    for (const t of draft.match_any ?? []) seen.add(t);
    return [...seen].sort((a, b) => a.localeCompare(b));
  }, [matchTerms, draft.match_any]);
  const refresh = useCallback(() => ws.send("rules.get"), []);
  useEffect(() => {
    const offReady = ws.on("ready", () => {
      refresh();
      ws.send("match_terms.get");
    });
    const offRules = ws.on("rules", (items) =>
      setRules((items as DetectionRule[]) ?? []),
    );
    const offSaved = ws.on("rule.saved", (data) => {
      const result = data as { rules: DetectionRule[] };
      setRules(result.rules ?? []);
      setBusy(false);
      setEditing(false);
      setNotice("Rule saved and loaded by the detection engine.");
      setError("");
      setValidated(null);
      ws.send("match_terms.get");
    });
    const offDeleted = ws.on("rule.deleted", (data) => {
      const result = data as { rules: DetectionRule[] };
      setRules(result.rules ?? []);
      setBusy(false);
      setNotice("Rule deleted.");
      setError("");
    });
  const offMatchTerms = ws.on("match_terms", (items) =>
    setMatchTerms((items as string[]) ?? []),
  );
  const offValidated = ws.on("rule.validated", (data) => {
    const result = data as { valid: boolean; message: string };
    setValidated(result.valid);
    setNotice(result.message);
    setError(result.valid ? "" : result.message);
    setBusy(false);
  });
    const offError = ws.on("error", (data) => {
      const e = data as ErrorPayload;
      if (
        ["rules.get", "rule.save", "rule.delete", "rule.validate"].includes(
          e.for ?? "",
        )
      ) {
        setError(e.message);
        setBusy(false);
      }
    });
    if (ws.isReady) {
      refresh();
      ws.send("match_terms.get");
    }
    return () => {
      offReady();
      offRules();
      offSaved();
      offDeleted();
      offMatchTerms();
      offValidated();
      offError();
    };
  }, [refresh]);

  const visibleRules = useMemo(
    () =>
      rules.filter((r) =>
        `${r.id} ${r.title} ${r.description} ${r.kind}`
          .toLowerCase()
          .includes(filter.toLowerCase()),
      ),
    [rules, filter],
  );
  const update = <K extends keyof DetectionRule>(
    key: K,
    value: DetectionRule[K],
  ) => {
    setDraft((old) => ({ ...old, [key]: value }));
    setValidated(null);
    setError("");
    setNotice("");
  };
  function startNew() {
    setDraft(blankRule());
    setEditing(true);
    setError("");
    setNotice("");
    setValidated(null);
  }
  function startEdit(rule: DetectionRule) {
    setDraft({
      ...rule,
      enabled: rule.enabled ?? true,
      sources: rule.sources ?? [],
      match_any: rule.match_any ?? [],
    });
    setEditing(true);
    setError("");
    setNotice("");
    setValidated(null);
  }
  function validate() {
    setBusy(true);
    setError("");
    setNotice("");
    ws.send("rule.validate", draft);
  }
  function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    ws.send("rule.save", draft);
  }
  function toggle(rule: DetectionRule) {
    setBusy(true);
    ws.send("rule.save", { ...rule, enabled: !rule.enabled });
  }
  function remove(rule: DetectionRule) {
    if (
      !window.confirm(
        `Delete detection rule “${rule.title || rule.id}”? This cannot be undone.`,
      )
    )
      return;
    setBusy(true);
    setError("");
    setNotice("");
    ws.send("rule.delete", { id: rule.id });
  }

  return (
    <>
      <TopBar />
      <main className="rules-page">
        <div className="page-heading">
          <div>
            <p className="eyebrow">DETECTION ENGINE</p>
            <h1>Detection rules</h1>
            <p className="muted">
              Create, validate, enable and maintain the rules that turn
              telemetry into deduplicated alerts.
            </p>
          </div>
          <button onClick={startNew}>＋ New rule</button>
        </div>
        <div className="rules-summary">
          <div>
            <strong>{rules.length}</strong>
            <span>Total rules</span>
          </div>
          <div>
            <strong>{rules.filter((r) => r.enabled !== false).length}</strong>
            <span>Enabled</span>
          </div>
          <div>
            <strong>{rules.filter((r) => r.enabled === false).length}</strong>
            <span>Disabled</span>
          </div>
        </div>
        {error && (
          <p className="msg error" role="alert">
            {error}
          </p>
        )}
        {notice && !error && (
          <p
            className={`rules-notice${validated === true ? " valid" : ""}`}
            role="status"
          >
            {notice}
          </p>
        )}
        {editing && (
          <section className="rules-editor panel">
            <div className="rules-editor-heading">
              <div>
                <p className="eyebrow">RULE CONFIGURATION</p>
                <h2>
                  {rules.some((r) => r.id === draft.id)
                    ? "Edit rule"
                    : "Create rule"}
                </h2>
              </div>
              <button
                className="ghost"
                type="button"
                onClick={() => setEditing(false)}
              >
                Cancel
              </button>
            </div>
            <form onSubmit={save}>
              <div className="rules-form-grid">
                <label>
                  Rule ID
                  <input
                    required
                    pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,99}"
                    maxLength={100}
                    disabled={rules.some((r) => r.id === draft.id)}
                    value={draft.id}
                    placeholder="ssh_brute_force"
                    onChange={(e) => update("id", e.target.value)}
                  />
                  <small>
                    Stable identifier; letters, numbers, dot, underscore and
                    hyphen.
                  </small>
                </label>
                <label>
                  Display title
                  <input
                    required
                    maxLength={160}
                    value={draft.title}
                    placeholder="SSH brute-force attempt"
                    onChange={(e) => update("title", e.target.value)}
                  />
                </label>
                <label>
                  Rule kind
                  <select
                    value={draft.kind}
                    onChange={(e) => update("kind", e.target.value)}
                  >
                    {kinds.map((k) => (
                      <option key={k} value={k}>
                        {k}
                      </option>
                    ))}
                  </select>
                  <small>
                    Detection behavior supported by the current engine.
                  </small>
                </label>
                <label>
                  Severity
                  <select
                    value={draft.severity}
                    onChange={(e) =>
                      update(
                        "severity",
                        e.target.value as DetectionRule["severity"],
                      )
                    }
                  >
                    {severities.map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Threshold
                  <input
                    type="number"
                    min={1}
                    max={1000000}
                    required
                    value={draft.threshold}
                    onChange={(e) =>
                      update("threshold", Number(e.target.value))
                    }
                  />
                </label>
                <label>
                  Window (seconds)
                  <input
                    type="number"
                    min={1}
                    max={86400}
                    required
                    value={draft.window_seconds}
                    onChange={(e) =>
                      update("window_seconds", Number(e.target.value))
                    }
                  />
                </label>
                <label>
                  Deduplication (seconds)
                  <input
                    type="number"
                    min={1}
                    max={604800}
                    required
                    value={draft.dedup_seconds}
                    onChange={(e) =>
                      update("dedup_seconds", Number(e.target.value))
                    }
                  />
                </label>
                <label>
                  Sources{" "}
                  <input
                    value={draft.sources.join(", ")}
                    placeholder="syslog-files, network-packets"
                    onChange={(e) =>
                      update(
                        "sources",
                        e.target.value
                          .split(",")
                          .map((v) => v.trim())
                          .filter(Boolean),
                      )
                    }
                  />
                  <small>
                    Comma-separated source IDs; leave empty for any source.
                  </small>
                </label>
                <label className="rules-wide" htmlFor="match_any">
                  Match terms
                  <select
                    id="match_any"
                    multiple
                    size={Math.min(Math.max(availableMatchTerms.length, 4), 8)}
                    value={draft.match_any}
                    onChange={(e) =>
                      update(
                        "match_any",
                        Array.from(e.target.selectedOptions, (o) => o.value),
                      )
                    }
                  >
                    {availableMatchTerms.map((term) => (
                      <option key={term} value={term}>
                        {term}
                      </option>
                    ))}
                  </select>
                  <small>
                    Select one or more available terms. An event matching any
                    selected term can contribute to the threshold.
                  </small>
                </label>
                <label className="rules-wide">
                  Description
                  <textarea
                    rows={3}
                    maxLength={2000}
                    value={draft.description}
                    placeholder="Explain what this rule detects and why it matters."
                    onChange={(e) => update("description", e.target.value)}
                  />
                </label>
              </div>
              <label className="rules-enabled">
                <input
                  type="checkbox"
                  checked={draft.enabled}
                  onChange={(e) => update("enabled", e.target.checked)}
                />{" "}
                Rule is enabled
              </label>
              <div className="rules-form-actions">
                <button
                  type="button"
                  className="ghost"
                  disabled={busy}
                  onClick={validate}
                >
                  Validate rule
                </button>
                <button type="submit" disabled={busy}>
                  {busy ? "Working…" : "Save rule"}
                </button>
              </div>
            </form>
          </section>
        )}
        <section className="rules-list-section">
          <div className="rules-list-heading">
            <div>
              <h2>Configured rules</h2>
              <p className="muted">
                Changes are persisted under the server data directory and take
                effect immediately.
              </p>
            </div>
            <input
              className="rules-search"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Search rules…"
              aria-label="Search rules"
            />
          </div>
          {visibleRules.length === 0 ? (
            <div className="rules-empty">
              <span>⌕</span>
              <h3>
                {rules.length ? "No matching rules" : "No rules configured yet"}
              </h3>
              <p className="muted">
                {rules.length
                  ? "Try a different search term."
                  : "Create your first rule to start generating alerts from incoming telemetry."}
              </p>
              {!rules.length && (
                <button onClick={startNew}>Create your first rule</button>
              )}
            </div>
          ) : (
            <div className="rules-table-wrap">
              <table className="rules-table">
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Threshold</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleRules.map((rule) => (
                    <tr key={rule.id}>
                      <td>
                        <strong>{rule.title || rule.id}</strong>
                        <code>{rule.id}</code>
                        {rule.description && <p>{rule.description}</p>}
                      </td>
                      <td>
                        <span className="rule-kind">
                          {rule.kind || "threshold"}
                        </span>
                      </td>
                      <td>
                        <span className={`severity severity-${rule.severity}`}>
                          {rule.severity}
                        </span>
                      </td>
                      <td>
                        <strong>{rule.threshold}</strong>
                        <small>in {rule.window_seconds}s</small>
                      </td>
                      <td>
                        <span
                          className={`rule-state ${rule.enabled === false ? "off" : "on"}`}
                        >
                          {rule.enabled === false ? "Disabled" : "Enabled"}
                        </span>
                      </td>
                      <td>
                        <div className="rule-actions">
                          <button
                            className="ghost"
                            disabled={busy}
                            onClick={() => startEdit(rule)}
                          >
                            Edit
                          </button>
                          <button
                            className="ghost"
                            disabled={busy}
                            onClick={() => toggle(rule)}
                          >
                            {rule.enabled === false ? "Enable" : "Disable"}
                          </button>
                          <button
                            className="danger-ghost"
                            disabled={busy}
                            onClick={() => remove(rule)}
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <p className="muted rules-footnote">
          Rule format is compatible with YAML/JSON files. The current UI editor
          exposes the detection engine’s supported rule fields; advanced custom
          detection logic requires an engine implementation for that rule kind.
        </p>
      </main>
    </>
  );
}
