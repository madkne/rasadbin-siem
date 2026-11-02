import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import Shell from "../components/Shell";
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
    <Shell>
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
            footer={
              <Button
                type="button"
                className="ghost"
                onClick={() => setEditor(null)}
                disabled={!!savingId}
              >
                Cancel
              </Button>
            }
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
                          if (ev.key === "Enter")
                            setExpanded(open ? null : a.id);
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
                            <div className="asset-enrichment-summary">
                              <strong>
                                Enrichment:{" "}
                                {a.enrichment_status || "not started"}
                              </strong>
                              {a.mac_addresses?.length ? (
                                <p>MAC: {a.mac_addresses.join(", ")}</p>
                              ) : null}
                              {a.protocols?.length ? (
                                <p>Protocols: {a.protocols.join(", ")}</p>
                              ) : null}
                              {a.enrichment_error ? (
                                <p className="msg error">
                                  {a.enrichment_error}
                                </p>
                              ) : null}
                              {a.enrichment_evidence?.length ? (
                                <p>
                                  Evidence: {a.enrichment_evidence.length}{" "}
                                  records
                                </p>
                              ) : null}
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
                            <pre>{JSON.stringify(a, null, 2)}</pre>
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
    </Shell>
  );
}
