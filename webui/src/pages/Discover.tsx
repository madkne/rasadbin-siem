import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import TopBar from "../components/TopBar";
import { ws } from "../lib/ws";
import type { SearchQuery, SearchResult } from "../lib/types";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const REFRESH_OPTIONS = [
  { label: "Off", ms: 0 },
  { label: "2s", ms: 2000 },
  { label: "10s", ms: 10000 },
  { label: "30s", ms: 30000 },
];

export default function Discover() {
  // Query state
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<string>("");
  const [sources, setSources] = useState<string[]>([]);
  const [selectedSources, setSelectedSources] = useState<string[]>([]);
  const [sortDesc, setSortDesc] = useState(true);
  const [from, setFrom] = useState("");     // datetime-local string
  const [to, setTo] = useState("");

  // Result state
  const [result, setResult] = useState<SearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  // Auto-refresh
  const [refreshMs, setRefreshMs] = useState(0);
  const inFlight = useRef(false);

  const buildQuery = useCallback((): SearchQuery => ({
    query: query.trim() || undefined,
    severity: severity || undefined,
    sources: selectedSources.length ? selectedSources : undefined,
    from: from ? new Date(from).toISOString() : undefined,
    to: to ? new Date(to).toISOString() : undefined,
    limit: 200,
    sort_desc: sortDesc,
  }), [query, severity, selectedSources, from, to, sortDesc]);

  const runSearch = useCallback(() => {
    if (!ws.isReady || inFlight.current) return;
    inFlight.current = true;
    setLoading(true);
    setError("");
    ws.send("discover.search", buildQuery());
  }, [buildQuery]);

  useEffect(() => {
    const offReady = ws.on("ready", () => {
      ws.send("discover.sources");
      runSearch();
    });
    const offResults = ws.on("discover.results", (r) => {
      inFlight.current = false;
      setLoading(false);
      setResult(r);
    });
    const offSources = ws.on("discover.sources", setSources);
    const offErr = ws.on("error", (e) => {
      if (e.for === "discover.search") {
        inFlight.current = false;
        setLoading(false);
        setError(e.message);
      }
    });
    // Live updates: new events arriving via the existing feed are appended
    // client-side, so Discover feels live without re-querying.
    const offEvent = ws.on("event", (e) => {
      setResult((prev) => prev ? { ...prev, events: [e, ...prev.events], total: prev.total + 1 } : prev);
    });
    if (ws.isReady) { ws.send("discover.sources"); runSearch(); }
    return () => { offReady(); offResults(); offSources(); offErr(); offEvent(); };
  }, [runSearch]);

  // Auto-refresh timer
  useEffect(() => {
    if (!refreshMs) return;
    const id = window.setInterval(runSearch, refreshMs);
    return () => window.clearInterval(id);
  }, [refreshMs, runSearch]);

  const maxBucket = useMemo(
    () => Math.max(1, ...(result?.buckets ?? []).map((b) => b.count)),
    [result],
  );

  function toggleSource(s: string) {
    setSelectedSources((prev) =>
      prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s],
    );
  }

  return (
    <>
      <TopBar />
      <main className="discover-page">
        <div className="page-heading">
          <div>
            <p className="eyebrow">LOG EXPLORATION</p>
            <h1>Discover</h1>
            <p className="muted">Search, filter and inspect collected events.</p>
          </div>
          <label className="refresh-label">
            Refresh
            <select value={refreshMs} onChange={(e) => setRefreshMs(Number(e.target.value))}>
              {REFRESH_OPTIONS.map((o) => (
                <option key={o.ms} value={o.ms}>{o.label}</option>
              ))}
            </select>
          </label>
        </div>

        {/* Query bar */}
        <section className="discover-querybar">
          <input
            className="discover-search-input"
            placeholder='Search message or source…'
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") runSearch(); }}
          />
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
            <option value="">All severities</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} aria-label="From" />
          <input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} aria-label="To" />
          <button type="button" onClick={runSearch} disabled={loading}>
            {loading ? "Searching…" : "Search"}
          </button>
          <button type="button" className="ghost" onClick={() => {
            setQuery(""); setSeverity(""); setSelectedSources([]); setFrom(""); setTo("");
          }}>Reset</button>
        </section>

        {/* Source filter chips */}
        {sources.length > 0 && (
          <section className="discover-sources" aria-label="Source filters">
            <span className="filter-label-text">Sources:</span>
            {sources.map((s) => (
              <button
                key={s}
                type="button"
                className={`chip ${selectedSources.includes(s) ? "chip-on" : ""}`}
                onClick={() => toggleSource(s)}
                aria-pressed={selectedSources.includes(s)}
              >
                {s || "system"}
              </button>
            ))}
            <label className="sort-toggle">
              <input type="checkbox" checked={sortDesc} onChange={(e) => setSortDesc(e.target.checked)} />
              Newest first
            </label>
          </section>
        )}

        {error && <p className="msg error" role="alert">{error}</p>}

        {/* Histogram */}
        <section className="discover-histogram" aria-label="Event histogram">
          {result?.buckets?.length ? (
            <div className="bars">
              {result.buckets.map((b, i) => (
                <div key={i} className="bar-wrap" title={`${new Date(b.time).toLocaleTimeString()} · ${b.count}`}>
                  <div className="bar" style={{ height: `${(b.count / maxBucket) * 100}%` }} />
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">No events in the selected window.</p>
          )}
          <div className="histogram-meta">
            <span>{result ? `${result.total} matching events` : "—"}</span>
            {result && <span>{result.took_ms.toFixed(1)} ms · showing {result.events.length}</span>}
          </div>
        </section>

        {/* Results table */}
        <section className="discover-results">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 140 }}>Time</th>
                  <th style={{ width: 140 }}>Source</th>
                  <th style={{ width: 100 }}>Severity</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {result?.events.map((e, i) => {
                  const key = `${e.time}-${i}`;
                  const open = expanded === key;
                   return (
                     <Fragment key={key}>
                       <tr
                        className={`discover-row ${open ? "expanded" : ""}`}
                        onClick={() => setExpanded(open ? null : key)}
                        tabIndex={0}
                        onKeyDown={(ev) => { if (ev.key === "Enter") setExpanded(open ? null : key); }}
                      >
                        <td className="time-cell">{new Date(e.time).toLocaleString()}</td>
                        <td><span className="source-tag">{e.source || "system"}</span></td>
                        <td><span className={`sev sev-${e.severity.replace(/[^a-z]/g, "")}`}><i />{e.severity}</span></td>
                        <td className="event-message">{e.message}</td>
                      </tr>
                      {open && (
                        <tr key={key + "-doc"} className="discover-doc">
                          <td colSpan={4}>
                            <pre>{JSON.stringify(e, null, 2)}</pre>
                          </td>
                        </tr>
                       )}
                     </Fragment>
                   );
                })}
              </tbody>
            </table>
            {result && result.events.length === 0 && (
              <div className="empty-state">
                <strong>No matching events</strong>
                <p>Adjust the query, severity, sources or time range.</p>
              </div>
            )}
          </div>
        </section>
      </main>
    </>
  );
}