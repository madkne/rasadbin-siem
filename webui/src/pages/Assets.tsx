import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { ws } from "../lib/ws";
import type { Asset, AssetDraft } from "../lib/types";
import AssetEditor from "../components/AssetEditor";
import Dialog from "../components/Dialog";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";

const ACTIVE_WINDOW_MS = 15 * 60 * 1000;

const sortAssets = (list: Asset[]) =>
  [...list].sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen));

const SOURCE_LABEL: Record<string, string> = {
  "network-packets": "network",
  "syslog-files": "syslog",
  manual: "manual",
};

export default function Assets() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [source, setSource] = useState("");
  const [origin, setOrigin] = useState("");
  const [archived, setArchived] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());
  const [editor, setEditor] = useState<
    { mode: "new" } | { mode: "edit"; asset: Asset } | null
  >(null);
  const [savingId, setSavingId] = useState<string | null>(null);

  const load = useCallback(() => {
    setError("");
    ws.send("assets.get", { limit: 2000, archived });
  }, [archived]);

  useEffect(() => {
    const offReady = ws.on("ready", load);
    const offAssets = ws.on("assets", (p) => {
      setAssets(sortAssets(p.assets ?? []));
      setTotal(p.total);
    });

    const offErr = ws.on("error", (e) => {
      if (e.for === "assets.get" || e.for === "asset.save") {
        setError(e.message);
        if (e.for === "asset.save") setSavingId(null);
      }
    });
    if (ws.isReady) load();
    const timer = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => {
      offReady();
      offAssets();
      offChanged();
      offErr();
      window.clearInterval(timer);
    };
  }, [load]);

  const saveAsset = useCallback(
    (draft: AssetDraft) => {
      const editing = editor?.mode === "edit" ? editor.asset : undefined;

      setSavingId(editing?.id ?? "new");
      setError("");

      ws.send("asset.save", {
        id: editing?.id,

        // Only used when creating a new asset.
        ips: draft.ips
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean),

        hostname: draft.hostname.trim(),
        name: draft.name.trim(),
        tags: draft.tags,
        criticality: draft.criticality,

        device_type: draft.device_type,
        device_role: draft.device_role,
        manufacturer: draft.manufacturer,
        model: draft.model,
        operating_system: draft.operating_system,
        os_version: draft.os_version,
      });
    },
    [editor],
  );

  const offChanged = ws.on("assets.changed", (batch) => {
    setAssets((prev) => {
      const byId = new Map(prev.map((a) => [a.id, a]));
      for (const a of batch ?? []) byId.set(a.id, a);
      return sortAssets([...byId.values()]);
    });
    if (batch?.length) {
      const saved = editor?.mode === "edit" ? editor.asset : undefined;
      const matched = saved
        ? batch.some((a) => a.id === saved.id)
        : savingId === "new";
      if (matched) {
        setSavingId(null);
        setEditor(null);
      }
    }
  });

  const isActive = (a: Asset) =>
    now - Date.parse(a.last_seen) < ACTIVE_WINDOW_MS;

  const sources = useMemo(
    () => [...new Set(assets.flatMap((a) => a.sources ?? []))].sort(),
    [assets],
  );

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return assets.filter((a) => {
      if (source && !(a.sources ?? []).includes(source)) return false;
      if (origin && a.origin !== origin) return false;
      if (!q) return true;
      return `${a.name} ${a.hostname ?? ""} ${(a.ips ?? []).join(" ")} ${(a.mac_addresses ?? []).join(" ")} ${(a.services ?? []).map((v) => v.name).join(" ")} ${(a.protocols ?? []).join(" ")} ${(a.tags ?? []).join(" ")}`
        .toLowerCase()
        .includes(q);
    });
  }, [assets, search, source, origin]);

  const count = (s: string) =>
    assets.filter((a) => (a.sources ?? []).includes(s)).length;

  return (
    <main className="discover-page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">INVENTORY</p>
          <h1>Assets</h1>
          <p className="muted">
            Hosts discovered from network traffic and syslog. Private-range
            addresses only; manual entries will appear here too.
          </p>
        </div>
        <span className="integration-count">
          {visible.length} shown · {Math.max(total, assets.length)} total
        </span>
      </div>

      <section className="metric-grid" aria-label="Asset summary">
        <article className="metric-card">
          <div className="metric-top">
            <span>Known assets</span>
          </div>
          <strong className="metric-value">{assets.length}</strong>
          <span className="metric-detail">In the inventory</span>
        </article>
        <article className="metric-card">
          <div className="metric-top">
            <span>Active now</span>
          </div>
          <strong className="metric-value">
            {assets.filter(isActive).length}
          </strong>
          <span className="metric-detail">Seen in the last 15 minutes</span>
        </article>
        <article className="metric-card">
          <div className="metric-top">
            <span>From network</span>
          </div>
          <strong className="metric-value">{count("network-packets")}</strong>
          <span className="metric-detail">Seen in packet metadata</span>
        </article>
        <article className="metric-card">
          <div className="metric-top">
            <span>From syslog</span>
          </div>
          <strong className="metric-value">{count("syslog-files")}</strong>
          <span className="metric-detail">Named in log lines</span>
        </article>
      </section>

      <section className="discover-querybar">
        <Input
          className="discover-search-input"
          placeholder="Search by name, hostname, IP or tag…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          value={source}
          onChange={(e) => setSource(e.target.value)}
          aria-label="Source filter"
        >
          <option value="">All sources</option>
          {sources.map((s) => (
            <option key={s} value={s}>
              {SOURCE_LABEL[s] ?? s}
            </option>
          ))}
        </select>
        <select
          value={origin}
          onChange={(e) => setOrigin(e.target.value)}
          aria-label="Origin filter"
        >
          <option value="">Discovered and manual</option>
          <option value="discovered">Discovered</option>
          <option value="manual">Manual</option>
        </select>
        <Button
          type="button"
          className={archived ? "ghost active" : "ghost"}
          onClick={() => setArchived((v) => !v)}
          aria-pressed={archived}
        >
          {archived ? "Show active" : "Show archived"}
        </Button>
        <Button type="button" className="ghost" onClick={load}>
          Refresh
        </Button>
        <Button
          type="button"
          className="ghost"
          onClick={() => ws.send("assets.archive_duplicates")}
        >
          Archive duplicates
        </Button>
        <Button
          type="button"
          onClick={() => setEditor({ mode: "new" })}
          disabled={editor?.mode === "new"}
        >
          ＋ Add asset
        </Button>
      </section>

      {error && (
        <p className="msg error" role="alert">
          {error}
        </p>
      )}

      {editor && (
        <Dialog
          open
          title={editor.mode === "edit" ? "Edit asset" : "Add new asset"}
          subtitle={
            editor.mode === "edit"
              ? "Update the classification and enrichment details for this asset."
              : "Add a manual asset to the inventory. Provide an IP address or hostname."
          }
          onClose={() => setEditor(null)}
        >
          <AssetEditor
            key={editor.mode === "edit" ? editor.asset.id : "new-asset"}
            asset={editor.mode === "edit" ? editor.asset : undefined}
            busy={!!savingId}
            onSubmit={saveAsset}
            onCancel={() => setEditor(null)}
          />
        </Dialog>
      )}

      <section className="discover-results">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th style={{ width: 90 }}>Status</th>
                <th>Asset</th>
                <th>IP addresses</th>
                <th>Services</th>
                <th>Seen via</th>
                <th style={{ width: 160 }}>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((a) => {
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
                        <span
                          className={`asset-status ${isActive(a) ? "on" : ""}`}
                        >
                          {isActive(a) ? "Active" : "Idle"}
                        </span>
                      </td>
                      <td>
                        <span className="asset-name">
                          <strong>{a.name}</strong>
                          {a.hostname && a.hostname !== a.name && (
                            <small>{a.hostname}</small>
                          )}
                          {a.origin === "manual" && (
                            <small className="asset-origin-manual">
                              Added manually
                            </small>
                          )}
                        </span>
                      </td>
                      <td>
                        <span className="asset-chips">
                          {(a.ips ?? []).slice(0, 3).map((ip) => (
                            <span key={ip} className="asset-chip">
                              {ip}
                            </span>
                          ))}
                          {(a.ips ?? []).length > 3 && (
                            <span className="muted">+{a.ips.length - 3}</span>
                          )}
                        </span>
                      </td>
                      <td>
                        <span className="asset-chips">
                          {(a.services ?? []).length > 0
                            ? (a.services ?? []).slice(0, 4).map((svc) => (
                                <span
                                  key={`${svc.transport}-${svc.port}-${svc.name}`}
                                  className="asset-chip"
                                  title={`${svc.protocol ?? "unknown"} · confidence ${Math.round(svc.confidence * 100)}%`}
                                >
                                  {svc.name} :{svc.port}
                                </span>
                              ))
                            : (a.ports ?? []).slice(0, 5).map((p) => (
                                <span key={p} className="asset-chip">
                                  {p}
                                </span>
                              ))}
                          {(a.services ?? []).length === 0 &&
                            (a.ports ?? []).length === 0 && (
                              <span className="muted">—</span>
                            )}
                        </span>
                      </td>
                      <td>
                        {(a.sources ?? []).map((s) => (
                          <span key={s} className="source-tag">
                            {SOURCE_LABEL[s] ?? s}
                          </span>
                        ))}
                      </td>
                      <td className="time-cell">
                        {new Date(a.last_seen).toLocaleString()}
                      </td>
                    </tr>
                    {open && (
                      <tr className="discover-doc">
                        <td colSpan={6}>
                          <div className="asset-details">
                            <div className="asset-details-head">
                              <div>
                                <h3>{a.name}</h3>
                                <p className="muted">
                                  {a.origin === "manual"
                                    ? "Added manually"
                                    : "Discovered"}{" "}
                                  · {isActive(a) ? "Active" : "Idle"}
                                  {a.criticality
                                    ? ` · ${a.criticality} criticality`
                                    : ""}
                                </p>
                              </div>
                              <div className="asset-chips">
                                {(a.ips ?? []).map((ip) => (
                                  <span key={ip} className="asset-chip">
                                    {ip}
                                  </span>
                                ))}
                                {(a.sources ?? []).map((s) => (
                                  <span key={s} className="source-tag">
                                    {SOURCE_LABEL[s] ?? s}
                                  </span>
                                ))}
                              </div>
                              <Button
                                type="button"
                                className="ghost"
                                onClick={(ev) => {
                                  ev.stopPropagation();
                                  setEditor({ mode: "edit", asset: a });
                                }}
                              >
                                Edit asset
                              </Button>
                            </div>

                            <div className="asset-details-grid">
                              <section className="asset-details-section">
                                <h4>Identity</h4>
                                {a.hostname ? (
                                  <div className="detail-row">
                                    <span>Hostname</span>
                                    <strong>{a.hostname}</strong>
                                  </div>
                                ) : null}
                                {a.device_type ? (
                                  <div className="detail-row">
                                    <span>Device type</span>
                                    <strong>{a.device_type}</strong>
                                  </div>
                                ) : null}
                                {a.device_role ? (
                                  <div className="detail-row">
                                    <span>Device role</span>
                                    <strong>{a.device_role}</strong>
                                  </div>
                                ) : null}
                                {a.manufacturer ? (
                                  <div className="detail-row">
                                    <span>Manufacturer</span>
                                    <strong>{a.manufacturer}</strong>
                                  </div>
                                ) : null}
                                {a.model ? (
                                  <div className="detail-row">
                                    <span>Model</span>
                                    <strong>{a.model}</strong>
                                  </div>
                                ) : null}
                                {a.operating_system ? (
                                  <div className="detail-row">
                                    <span>Operating system</span>
                                    <strong>
                                      {a.operating_system}
                                      {a.os_version ? ` ${a.os_version}` : ""}
                                    </strong>
                                  </div>
                                ) : null}
                                {a.criticality ? (
                                  <div className="detail-row">
                                    <span>Criticality</span>
                                    <strong>{a.criticality}</strong>
                                  </div>
                                ) : null}
                                <div className="detail-row">
                                  <span>Origin</span>
                                  <strong>
                                    {a.origin === "manual"
                                      ? "Manual"
                                      : "Discovered"}
                                  </strong>
                                </div>
                                <div className="detail-row">
                                  <span>Archived</span>
                                  <strong>{a.archived ? "Yes" : "No"}</strong>
                                </div>
                              </section>

                              <section className="asset-details-section">
                                <h4>Network</h4>
                                <div className="detail-row">
                                  <span>IP addresses</span>
                                  <strong>
                                    {(a.ips ?? []).join(", ") || "—"}
                                  </strong>
                                </div>
                                {a.mac_addresses?.length ? (
                                  <div className="detail-row">
                                    <span>MAC addresses</span>
                                    <strong>
                                      {a.mac_addresses.join(", ")}
                                    </strong>
                                  </div>
                                ) : null}
                                {(a.ports ?? []).length > 0 ? (
                                  <div className="detail-row">
                                    <span>Ports</span>
                                    <strong>
                                      {(a.ports ?? []).join(", ")}
                                    </strong>
                                  </div>
                                ) : null}
                                {a.protocols?.length ? (
                                  <div className="detail-row">
                                    <span>Protocols</span>
                                    <strong>
                                      {a.protocols.join(", ")}
                                    </strong>
                                  </div>
                                ) : null}
                                {(a.sources ?? []).length > 0 ? (
                                  <div className="detail-row">
                                    <span>Seen via</span>
                                    <strong>
                                      {(a.sources ?? [])
                                        .map((s) => SOURCE_LABEL[s] ?? s)
                                        .join(", ")}
                                    </strong>
                                  </div>
                                ) : null}
                                <div className="detail-row">
                                  <span>First seen</span>
                                  <strong>
                                    {new Date(a.first_seen).toLocaleString()}
                                  </strong>
                                </div>
                                <div className="detail-row">
                                  <span>Last seen</span>
                                  <strong>
                                    {new Date(a.last_seen).toLocaleString()}
                                  </strong>
                                </div>
                                <div className="detail-row">
                                  <span>Event count</span>
                                  <strong>{a.event_count}</strong>
                                </div>
                              </section>
                            </div>

                            {a.tags?.length ? (
                              <section className="asset-details-section">
                                <h4>Tags</h4>
                                <div className="asset-chips">
                                  {a.tags.map((tag) => (
                                    <span key={tag} className="asset-chip">
                                      {tag}
                                    </span>
                                  ))}
                                </div>
                              </section>
                            ) : null}

                            {(a.services ?? []).length > 0 ? (
                              <section className="asset-details-section">
                                <h4>
                                  Services ({(a.services ?? []).length})
                                </h4>
                                <div className="asset-service-list">
                                  {(a.services ?? []).map((svc) => (
                                    <div
                                      key={`${svc.transport}-${svc.port}-${svc.name}`}
                                      className="asset-service-row"
                                    >
                                      <strong>
                                        {svc.name} :{svc.port}
                                      </strong>
                                      <span>
                                        {svc.transport.toUpperCase()}
                                        {svc.protocol
                                          ? ` · ${svc.protocol}`
                                          : ""}
                                        {" · "}
                                        {Math.round(svc.confidence * 100)}%
                                        confidence
                                      </span>
                                      <small className="muted">
                                        {svc.source} ·{" "}
                                        {new Date(
                                          svc.observed_at,
                                        ).toLocaleString()}
                                      </small>
                                    </div>
                                  ))}
                                </div>
                              </section>
                            ) : null}

                            <section className="asset-details-section">
                              <h4>Enrichment</h4>
                              <div className="detail-row">
                                <span>Status</span>
                                <strong>
                                  {a.enrichment_status || "not started"}
                                </strong>
                              </div>
                              <div className="detail-row">
                                <span>Attempts</span>
                                <strong>{a.enrichment_attempts}</strong>
                              </div>
                              {a.last_enriched_at ? (
                                <div className="detail-row">
                                  <span>Last enriched</span>
                                  <strong>
                                    {new Date(
                                      a.last_enriched_at,
                                    ).toLocaleString()}
                                  </strong>
                                </div>
                              ) : null}
                              {a.next_enrichment_at ? (
                                <div className="detail-row">
                                  <span>Next enrichment</span>
                                  <strong>
                                    {new Date(
                                      a.next_enrichment_at,
                                    ).toLocaleString()}
                                  </strong>
                                </div>
                              ) : null}
                              {a.enrichment_error ? (
                                <p className="msg error">
                                  {a.enrichment_error}
                                </p>
                              ) : null}
                              {a.enrichment_evidence?.length ? (
                                <div className="asset-evidence-list">
                                  {a.enrichment_evidence.map((ev, i) => (
                                    <div
                                      key={`${ev.field}-${i}`}
                                      className="asset-evidence-row"
                                    >
                                      <strong>{ev.field}</strong>: {ev.value}
                                      <small className="muted">
                                        {ev.source} ·{" "}
                                        {Math.round(ev.confidence * 100)}% ·{" "}
                                        {new Date(
                                          ev.observed_at,
                                        ).toLocaleString()}
                                      </small>
                                    </div>
                                  ))}
                                </div>
                              ) : null}
                            </section>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
          {visible.length === 0 && (
            <div className="empty-state">
              <strong>
                {assets.length
                  ? "No assets match these filters"
                  : "No assets discovered yet"}
              </strong>
              <p>
                {assets.length
                  ? "Clear the search or filters to see the full inventory."
                  : "Enable the Network packets or Syslog files integration under Integrations. Hosts appear here as their traffic and log lines arrive."}
              </p>
            </div>
          )}
        </div>
      </section>
    </main>
  );
}
