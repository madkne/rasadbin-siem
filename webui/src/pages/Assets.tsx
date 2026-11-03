import { useCallback, useEffect, useMemo, useState, Fragment } from "react";
import { ws } from "../lib/ws";
import { cn } from "../lib/utils";
import type { Asset, AssetDraft } from "../lib/types";
import AssetEditor from "../components/AssetEditor";
import Dialog from "../components/Dialog";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import {
  Copy,
  Cpu,
  Gauge,
  HelpCircle,
  Monitor,
  Network,
  Router,
  Server,
  Shield,
  Tag,
  Thermometer,
  type LucideIcon,
} from "lucide-react";
import { resolveAssetVisual } from "../components/AssetIcons";

const ACTIVE_WINDOW_MS = 15 * 60 * 1000;

const sortAssets = (list: Asset[]) =>
  [...list].sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen));

const SOURCE_LABEL: Record<string, string> = {
  "network-packets": "network",
  "syslog-files": "syslog",
  manual: "manual",
};

const VISUAL_ICONS: Record<string, LucideIcon> = {
  workstation: Monitor,
  server: Server,
  plc: Cpu,
  firewall: Shield,
  switch: Network,
  router: Router,
  hmi: Gauge,
  sensor: Thermometer,
  unknown: HelpCircle,
};

const CRITICALITY_VARIANT: Record<string, string> = {
  low: "ok",
  medium: "warning",
  high: "bad",
  critical: "bad",
};

const ENRICHMENT_VARIANT: Record<string, string> = {
  pending: "accent",
  enriching: "accent",
  enriched: "ok",
  partial: "warning",
  failed: "bad",
};

function relativeTime(ts: string, now: number): string {
  const d = Date.parse(ts);
  if (Number.isNaN(d)) return "-";
  const delta = Math.max(0, now - d);
  const sec = Math.floor(delta / 1000);
  if (sec < 10) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h}h ago`;
  const days = Math.floor(h / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(d).toLocaleString();
}

function isActiveNow(a: Asset, now: number) {
  return now - Date.parse(a.last_seen) < ACTIVE_WINDOW_MS;
}

function badgeClass(variant: string): string {
  switch (variant) {
    case "ok":
      return "asset-badge--ok";
    case "warning":
      return "asset-badge--warning";
    case "bad":
      return "asset-badge--bad";
    case "accent":
    default:
      return "asset-badge--accent";
  }
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button
      className="asset-copy-btn"
      onClick={copy}
      aria-label="Copy to clipboard"
      title={copied ? "Copied to clipboard" : "Copy to clipboard"}
    >
      {copied ? "Copied" : <Copy size={13} strokeWidth={1.6} />}
    </button>
  );
}

function AssetSection({
  icon: Icon,
  title,
  children,
}: {
  icon: LucideIcon;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="asset-section">
      <div className="asset-section-head">
        <Icon className="asset-section-icon" size={16} strokeWidth={1.5} />
        <h3>{title}</h3>
      </div>
      <div className="asset-section-body">{children}</div>
    </section>
  );
}

function DetailRow({
  label,
  value,
  sub,
  copy,
  badge,
  badgeVariant,
  valueVariant,
  className,
  children,
}: {
  label: string;
  value?: string;
  sub?: string;
  copy?: string;
  badge?: string;
  badgeVariant?: string;
  valueVariant?: string;
  className?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="asset-detail-row">
      <span className="asset-detail-label">{label}</span>
      <div className={cn("asset-detail-value", className, valueVariant && `asset-detail-value--${valueVariant}`)}>
        {children ?? (value != null ? value : "—")}
        {sub && <span className="asset-detail-sub">{sub}</span>}
      </div>
      {copy && <CopyButton value={copy} />}
      {badge && (
        <span className={cn("asset-badge", badgeClass(badgeVariant ?? "accent"))}>
          {badge}
        </span>
      )}
    </div>
  );
}

export default function Assets() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [source, setSource] = useState("");
  const [origin, setOrigin] = useState("");
  const [archived, setArchived] = useState(false);
  const [selected, setSelected] = useState<Asset | null>(null);
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

    if (ws.isReady) load();
    const timer = window.setInterval(() => setNow(Date.now()), 30_000);
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") setSelected(null);
    };
    window.addEventListener("keydown", onKey);
    return () => {
      offReady();
      offAssets();
      offChanged();
      offErr();
      window.removeEventListener("keydown", onKey);
      window.clearInterval(timer);
    };
  }, [load, editor, savingId]);

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

  const handleEdit = (a: Asset) => {
    setSelected(null);
    setEditor({ mode: "edit", asset: a });
  };

  const handleArchive = (a: Asset) => {
    setSelected(null);
    ws.send("asset.save", {
      id: a.id,
      ips: a.ips,
      hostname: a.hostname ?? "",
      name: a.name,
      tags: a.tags,
      criticality: a.criticality ?? "",
      device_type: a.device_type ?? "",
      device_role: a.device_role ?? "",
      manufacturer: a.manufacturer ?? "",
      model: a.model ?? "",
      operating_system: a.operating_system ?? "",
      os_version: a.os_version ?? "",
      archived: !a.archived,
    });
  };

  return (
    <Fragment>
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
            onClick={ws.send.bind(ws, "assets.archive_duplicates")}
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
          <p className="msg error" role="alert">{error}</p>
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
                  const open = selected?.id === a.id;
                  return (
                    <Fragment key={a.id}>
                      <tr
                        className={`discover-row ${open ? "selected" : ""}`}
                        onClick={() => setSelected(open ? null : a)}
                        tabIndex={0}
                        onKeyDown={(ev) => {
                          if (ev.key === "Enter") setSelected(open ? null : a);
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
                              <span key={ip} className="asset-chip">{ip}</span>
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

      {selected && (
        <AssetDetailsPanel
          asset={selected}
          now={now}
          onEdit={handleEdit}
          onArchive={handleArchive}
          onClose={() => setSelected(null)}
        />
      )}
    </Fragment>
  );
}

function AssetDetailsPanel({
  asset,
  now,
  onEdit,
  onArchive,
  onClose,
}: {
  asset: Asset;
  now: number;
  onEdit: (a: Asset) => void;
  onArchive: (a: Asset) => void;
  onClose: () => void;
}) {
  const visual = resolveAssetVisual(asset);
  const Icon = VISUAL_ICONS[visual] ?? HelpCircle;
  const critVariant = asset.criticality
    ? CRITICALITY_VARIANT[asset.criticality]
    : undefined;
  const enrichVariant =
    ENRICHMENT_VARIANT[asset.enrichment_status] ?? undefined;

  const ips = asset.ips ?? [];
  const macs = asset.mac_addresses ?? [];
  const services = asset.services ?? [];
  const tags = asset.tags ?? [];
  const protocols = asset.protocols ?? [];

  const hasIdentity =
    asset.hostname ||
    asset.device_type ||
    asset.device_role ||
    asset.manufacturer ||
    asset.model ||
    asset.operating_system;
  const hasNetwork =
    ips.length ||
    macs.length ||
    (asset.ports ?? []).length ||
    protocols.length ||
    (asset.sources ?? []).length;

  return (
    <div
      className="asset-details-panel"
      role="dialog"
      aria-modal="true"
      aria-label={`Details for ${asset.name}`}
    >
      <div className="asset-details-panel-backdrop" onClick={onClose} />
      <div className="asset-details-panel-sheet">
        <button
          className="asset-details-panel-close"
          onClick={onClose}
          aria-label="Close details"
        >
          ×
        </button>
        <div className="asset-details-panel-body">
          <div className="asset-details-panel-head">
            <div className="asset-visual">
              <div className={`asset-visual-bg asset-visual--${visual}`}>
                <Icon className="asset-visual-icon" size={30} strokeWidth={1.6} />
              </div>
            </div>
            <div className="asset-identity">
              <h2>{asset.name}</h2>
              <p className="asset-subtitle">
                {asset.hostname ? asset.hostname + " · " : ""}
                {asset.origin === "manual" ? "Added manually" : "Discovered"}
              </p>
              <div className="asset-status-line">
                <span className={`asset-status ${isActiveNow(asset, now) ? "on" : ""}`}>
                  {isActiveNow(asset, now) ? "Active" : "Idle"}
                </span>
                {asset.criticality && critVariant && (
                  <span className={cn("asset-badge", badgeClass(critVariant))}>
                    {asset.criticality} criticality
                  </span>
                )}
              </div>
            </div>
            <div className="asset-details-panel-actions">
              <Button type="button" className="ghost" onClick={(ev) => {
                ev.stopPropagation();
                onClose();
                onEdit(asset);
              }}>
                Edit asset
              </Button>
              <Button type="button" className="ghost" onClick={(ev) => {
                ev.stopPropagation();
                onArchive(asset);
              }}>
                {asset.archived ? "Restore" : "Archive"}
              </Button>
            </div>
          </div>

          <div className="asset-details-panel-scroll">
            <AssetSection icon={Monitor} title="Identity">
              {asset.hostname ? (
                <DetailRow label="Hostname" value={asset.hostname} copy={asset.hostname} />
              ) : null}
              {asset.device_type ? (
                <DetailRow label="Device type" value={asset.device_type} />
              ) : null}
              {asset.device_role ? (
                <DetailRow label="Device role" value={asset.device_role} />
              ) : null}
              {asset.manufacturer ? (
                <DetailRow label="Manufacturer" value={asset.manufacturer} />
              ) : null}
              {asset.model ? (
                <DetailRow label="Model" value={asset.model} />
              ) : null}
              {asset.operating_system ? (
                <DetailRow
                  label="Operating system"
                  value={asset.os_version
                    ? `${asset.operating_system} ${asset.os_version}`
                    : asset.operating_system}
                />
              ) : null}
              <DetailRow label="Origin" value={asset.origin === "manual" ? "Manual" : "Discovered"} />
              <DetailRow
                label="Archived"
                value={asset.archived ? "Yes" : "No"}
                badge={asset.archived ? "Archived" : "Active"}
                badgeVariant={asset.archived ? "bad" : "ok"}
              />
              {!hasIdentity && (
                <p className="asset-empty">No identity details recorded.</p>
              )}
            </AssetSection>

            <AssetSection icon={Network} title="Network">
              {ips.length > 0 ? (
                <div className="asset-chip-field">
                  <span className="asset-detail-label">IP addresses</span>
                  <div className="asset-chips asset-chips--copy">
                    {ips.map((ip) => (
                      <Fragment key={ip}>
                        <span className="asset-chip asset-chip--copy" title={ip}>
                          {ip}
                        </span>
                        <CopyButton value={ip} />
                      </Fragment>
                    ))}
                  </div>
                </div>
              ) : (
                <DetailRow label="IP addresses" value="—" />
              )}
              {macs.length ? (
                <div className="asset-chip-field">
                  <span className="asset-detail-label">MAC addresses</span>
                  <div className="asset-chips asset-chips--copy">
                    {macs.map((mac) => (
                      <Fragment key={mac}>
                        <span className="asset-chip asset-chip--copy" title={mac}>
                          {mac}
                        </span>
                        <CopyButton value={mac} />
                      </Fragment>
                    ))}
                  </div>
                </div>
              ) : null}
              {(asset.ports ?? []).length > 0 ? (
                <DetailRow
                  label="Ports"
                  value={(asset.ports ?? []).join(", ")}
                  className="mono-value"
                />
              ) : null}
              {protocols.length ? (
                <DetailRow label="Protocols" value={protocols.join(", ")} />
              ) : null}
              {(asset.sources ?? []).length > 0 ? (
                <DetailRow
                  label="Seen via"
                  value={(asset.sources ?? [])
                    .map((s) => SOURCE_LABEL[s] ?? s)
                    .join(", ")}
                />
              ) : null}
              <DetailRow
                label="First seen"
                value={new Date(asset.first_seen).toLocaleString()}
                copy={asset.first_seen}
              />
              <DetailRow
                label="Last seen"
                value={relativeTime(asset.last_seen, now)}
                sub={new Date(asset.last_seen).toLocaleString()}
                copy={asset.last_seen}
              />
              <DetailRow label="Event count" value={String(asset.event_count)} />
              {!hasNetwork && (
                <p className="asset-empty">No network data observed.</p>
              )}
            </AssetSection>

            {tags.length ? (
              <AssetSection icon={Tag} title="Tags">
                <div className="asset-chips">
                  {tags.map((tag) => (
                    <span key={tag} className="asset-chip">{tag}</span>
                  ))}
                </div>
              </AssetSection>
            ) : null}

            {services.length > 0 ? (
              <AssetSection
                icon={Server}
                title={`Services (${services.length})`}
              >
                <div className="asset-service-list">
                  {services.map((svc) => (
                    <div
                      key={`${svc.transport}-${svc.port}-${svc.name}`}
                      className="asset-service-row"
                    >
                      <div className="asset-service-main">
                        <strong>{svc.name} :{svc.port}</strong>
                        <span className="asset-service-meta">
                          {svc.transport.toUpperCase()}
                          {svc.protocol ? ` · ${svc.protocol}` : ""}
                          · {Math.round(svc.confidence * 100)}% confidence
                        </span>
                      </div>
                      <small className="asset-service-foot">
                        {svc.source} · {new Date(svc.observed_at).toLocaleString()}
                      </small>
                    </div>
                  ))}
                </div>
              </AssetSection>
            ) : null}

            <AssetSection icon={Shield} title="Enrichment">
              <DetailRow
                label="Status"
                value={asset.enrichment_status || "not started"}
                valueVariant={enrichVariant}
              />
              <DetailRow label="Attempts" value={String(asset.enrichment_attempts)} />
              {asset.last_enriched_at ? (
                <DetailRow
                  label="Last enriched"
                  value={relativeTime(asset.last_enriched_at, now)}
                  sub={new Date(asset.last_enriched_at).toLocaleString()}
                />
              ) : null}
              {asset.next_enrichment_at ? (
                <DetailRow
                  label="Next enrichment"
                  value={relativeTime(asset.next_enrichment_at, now)}
                  sub={new Date(asset.next_enrichment_at).toLocaleString()}
                />
              ) : null}
              {asset.enrichment_error ? (
                <p className="msg error">{asset.enrichment_error}</p>
              ) : null}
              {asset.enrichment_evidence?.length ? (
                <div className="asset-evidence-list">
                  {asset.enrichment_evidence.map((ev, i) => (
                    <div
                      key={`${ev.field}-${i}`}
                      className="asset-evidence-row"
                    >
                      <strong>{ev.field}</strong>: {ev.value}
                      <small className="asset-evidence-foot">
                        {ev.source} · {Math.round(ev.confidence * 100)}% ·{" "}
                        {new Date(ev.observed_at).toLocaleString()}
                      </small>
                    </div>
                  ))}
                </div>
              ) : null}
              <p className="asset-empty">No enrichment data available.</p>
            </AssetSection>
          </div>
        </div>
      </div>
    </div>
  );
}
