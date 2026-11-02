import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { PointerEvent as RPointerEvent } from "react";
import Shell from "../components/Shell";
import { ws } from "../lib/ws";
import type { Asset, TopologyLink } from "../lib/types";
import { AssetGlyph, resolveAssetVisual } from "../components/AssetIcons";

const LIVE_MS = 30_000; // a link is "live" if traffic was seen this recently
const ACTIVE_MS = 15 * 60_000; // an asset is "active" within this window

const REPULSION = 1800;
const SPRING = 0.03;
const REST_LENGTH = 90;
const GRAVITY = 0.012;
const DAMPING = 0.78;

interface SimNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  pinned: boolean;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(1)} GB`;
}

export default function Topology() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [links, setLinks] = useState<TopologyLink[]>([]);
  const [search, setSearch] = useState("");
  const [liveOnly, setLiveOnly] = useState(false);
  const [hideIsolated, setHideIsolated] = useState(false);
  const [labels, setLabels] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [now, setNow] = useState(Date.now());

  const svgRef = useRef<SVGSVGElement>(null);
  const viewRef = useRef<SVGGElement>(null);
  const nodeEls = useRef(new Map<string, SVGGElement>());
  const linkEls = useRef(new Map<string, SVGLineElement>());
  const tickRef = useRef<() => void>(() => {});
  const prevLinkCount = useRef(0);
  const graphLinks = useRef<TopologyLink[]>([]);
  const sim = useRef({
    nodes: new Map<string, SimNode>(),
    alpha: 1,
    raf: 0,
    view: { k: 1, x: 0, y: 0 },
    drag: null as null | { id: string; moved: boolean },
    pan: null as null | { sx: number; sy: number; vx: number; vy: number },
  });

  /* ---------- data ---------- */
  const load = useCallback(() => {
    setError("");
    ws.send("topology.get");
    ws.send("topology.subscribe");
  }, []);

  useEffect(() => {
    const offReady = ws.on("ready", load);
    const offTopo = ws.on("topology", (p) => {
      setAssets(p.assets ?? []);
      setLinks(p.links ?? []);
    });
    const offChanged = ws.on("topology.changed", (p) =>
      setLinks((prev) => {
        const byId = new Map(prev.map((l) => [l.id, l]));
        for (const id of p.removed ?? []) byId.delete(id);
        for (const l of p.links ?? []) byId.set(l.id, l);
        return [...byId.values()];
      }),
    );
    const offAssets = ws.on("assets.changed", (batch) =>
      setAssets((prev) => {
        const byId = new Map(prev.map((a) => [a.id, a]));
        for (const a of batch ?? []) byId.set(a.id, a);
        return [...byId.values()];
      }),
    );
    const offErr = ws.on("error", (e) => {
      if (e.for === "topology.get") setError(e.message);
    });
    if (ws.isReady) load();
    const timer = window.setInterval(() => setNow(Date.now()), 5_000);
    return () => {
      offReady();
      offTopo();
      offChanged();
      offAssets();
      offErr();
      window.clearInterval(timer);
      if (ws.isReady) ws.send("topology.unsubscribe");
    };
  }, [load]);

  const byId = useMemo(() => new Map(assets.map((a) => [a.id, a])), [assets]);

  const visibleLinks = useMemo(
    () =>
      links.filter(
        (l) =>
          byId.has(l.source) &&
          byId.has(l.target) &&
          (!liveOnly || now - Date.parse(l.last_seen) < LIVE_MS),
      ),
    [links, byId, liveOnly, now],
  );

  const visibleAssets = useMemo(() => {
    if (!hideIsolated) return assets;
    const linked = new Set<string>();
    for (const l of visibleLinks) {
      linked.add(l.source);
      linked.add(l.target);
    }
    return assets.filter((a) => linked.has(a.id));
  }, [assets, visibleLinks, hideIsolated]);

  const matches = useCallback(
    (a: Asset) => {
      const q = search.trim().toLowerCase();
      if (!q) return true;
      return `${a.name} ${a.hostname ?? ""} ${(a.ips ?? []).join(" ")} ${(a.tags ?? []).join(" ")}`
        .toLowerCase()
        .includes(q);
    },
    [search],
  );

  const liveCount = useMemo(
    () => links.filter((l) => now - Date.parse(l.last_seen) < LIVE_MS).length,
    [links, now],
  );

  /* ---------- force simulation (DOM is updated directly, not via React state) ---------- */
  const paint = useCallback(() => {
    const s = sim.current;
    s.nodes.forEach((n, id) => {
      nodeEls.current
        .get(id)
        ?.setAttribute(
          "transform",
          `translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})`,
        );
    });
    for (const l of graphLinks.current) {
      const el = linkEls.current.get(l.id);
      const a = s.nodes.get(l.source);
      const b = s.nodes.get(l.target);
      if (!el || !a || !b) continue;
      el.setAttribute("x1", a.x.toFixed(1));
      el.setAttribute("y1", a.y.toFixed(1));
      el.setAttribute("x2", b.x.toFixed(1));
      el.setAttribute("y2", b.y.toFixed(1));
    }
  }, []);

  useEffect(() => {
    tickRef.current = function step() {
      const s = sim.current;
      s.raf = 0;
      if (s.alpha < 0.01 && !s.drag) {
        paint();
        return; // settled: sleep until the graph changes again
      }
      const a = s.alpha;
      const arr = [...s.nodes.values()];
      for (let i = 0; i < arr.length; i++) {
        const ni = arr[i];
        for (let j = i + 1; j < arr.length; j++) {
          const nj = arr[j];
          let dx = ni.x - nj.x;
          let dy = ni.y - nj.y;
          let d2 = dx * dx + dy * dy;
          if (d2 < 1) {
            dx = Math.random() - 0.5;
            dy = Math.random() - 0.5;
            d2 = 1;
          }
          if (d2 > 250_000) continue;
          const f = (REPULSION * a) / d2;
          ni.vx += dx * f;
          ni.vy += dy * f;
          nj.vx -= dx * f;
          nj.vy -= dy * f;
        }
      }
      for (const l of graphLinks.current) {
        const n1 = s.nodes.get(l.source);
        const n2 = s.nodes.get(l.target);
        if (!n1 || !n2) continue;
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const d = Math.hypot(dx, dy) || 1;
        const f = (d - REST_LENGTH) * SPRING * a;
        n1.vx += (dx / d) * f;
        n1.vy += (dy / d) * f;
        n2.vx -= (dx / d) * f;
        n2.vy -= (dy / d) * f;
      }
      for (const n of arr) {
        if (n.pinned) continue;
        n.vx = (n.vx - n.x * GRAVITY * a) * DAMPING;
        n.vy = (n.vy - n.y * GRAVITY * a) * DAMPING;
        n.vx = Math.max(-30, Math.min(30, n.vx));
        n.vy = Math.max(-30, Math.min(30, n.vy));
        n.x += n.vx;
        n.y += n.vy;
      }
      s.alpha = s.drag ? Math.max(0.3, s.alpha * 0.99) : s.alpha * 0.99;
      paint();
      s.raf = requestAnimationFrame(() => tickRef.current());
    };
  }, [paint]);

  const wake = useCallback((alpha: number) => {
    const s = sim.current;
    s.alpha = Math.max(s.alpha, alpha);
    if (!s.raf) s.raf = requestAnimationFrame(() => tickRef.current());
  }, []);

  // Keep simulation nodes in step with what is visible.
  useEffect(() => {
    const s = sim.current;
    graphLinks.current = visibleLinks;
    const ids = new Set(visibleAssets.map((a) => a.id));
    let changed = false;
    for (const id of [...s.nodes.keys()]) {
      if (!ids.has(id)) {
        s.nodes.delete(id);
        changed = true;
      }
    }
    for (const a of visibleAssets) {
      if (!s.nodes.has(a.id)) {
        const ang = Math.random() * 2 * Math.PI;
        const r = 40 + Math.random() * 140;
        s.nodes.set(a.id, {
          x: Math.cos(ang) * r,
          y: Math.sin(ang) * r,
          vx: 0,
          vy: 0,
          pinned: false,
        });
        changed = true;
      }
    }
    if (changed) wake(0.8);
    else if (visibleLinks.length !== prevLinkCount.current) wake(0.35);
    else wake(0.001); // still paint once so new DOM elements get positions
    prevLinkCount.current = visibleLinks.length;
  }, [visibleAssets, visibleLinks, wake]);

  /* ---------- view: pan / zoom / drag ---------- */
  const applyView = useCallback(() => {
    const { k, x, y } = sim.current.view;
    viewRef.current?.setAttribute(
      "transform",
      `translate(${x} ${y}) scale(${k})`,
    );
  }, []);

  const resetView = useCallback(() => {
    const svg = svgRef.current;
    if (!svg) return;
    sim.current.view = {
      k: 1,
      x: svg.clientWidth / 2,
      y: svg.clientHeight / 2,
    };
    applyView();
  }, [applyView]);

  useEffect(() => {
    resetView();
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const v = sim.current.view;
      const rect = svg.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      const k2 = Math.max(0.2, Math.min(4, v.k * Math.exp(-e.deltaY * 0.0015)));
      v.x = mx - (mx - v.x) * (k2 / v.k);
      v.y = my - (my - v.y) * (k2 / v.k);
      v.k = k2;
      applyView();
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => {
      svg.removeEventListener("wheel", onWheel);
      cancelAnimationFrame(sim.current.raf);
      sim.current.raf = 0;
    };
  }, [applyView, resetView]);

  const onBackgroundDown = (e: RPointerEvent<SVGSVGElement>) => {
    const v = sim.current.view;
    sim.current.pan = { sx: e.clientX, sy: e.clientY, vx: v.x, vy: v.y };
    e.currentTarget.setPointerCapture(e.pointerId);
  };
  const onMove = (e: RPointerEvent<SVGSVGElement>) => {
    const s = sim.current;
    if (s.drag) {
      const rect = e.currentTarget.getBoundingClientRect();
      const n = s.nodes.get(s.drag.id);
      if (n) {
        n.x = (e.clientX - rect.left - s.view.x) / s.view.k;
        n.y = (e.clientY - rect.top - s.view.y) / s.view.k;
        n.vx = n.vy = 0;
        s.drag.moved = true;
        wake(0.3);
      }
    } else if (s.pan) {
      s.view.x = s.pan.vx + (e.clientX - s.pan.sx);
      s.view.y = s.pan.vy + (e.clientY - s.pan.sy);
      applyView();
    }
  };
  const onUp = () => {
    const s = sim.current;
    if (s.drag) {
      const n = s.nodes.get(s.drag.id);
      if (n) n.pinned = false;
      if (!s.drag.moved)
        setSelected((cur) => (cur === s.drag!.id ? null : s.drag!.id));
      s.drag = null;
    } else if (s.pan) {
      const moved =
        Math.abs(s.pan.vx - s.view.x) + Math.abs(s.pan.vy - s.view.y) > 3;
      if (!moved) setSelected(null);
    }
    s.pan = null;
  };
  const onNodeDown = (id: string) => (e: RPointerEvent<SVGGElement>) => {
    e.stopPropagation();
    const svg = svgRef.current;
    if (!svg) return;
    svg.setPointerCapture(e.pointerId);
    const n = sim.current.nodes.get(id);
    if (n) n.pinned = true;
    sim.current.drag = { id, moved: false };
    wake(0.3);
  };

  /* ---------- selection panel ---------- */
  const selectedAsset = selected ? byId.get(selected) : undefined;
  const connections = useMemo(() => {
    if (!selected) return [];
    return links
      .filter((l) => l.source === selected || l.target === selected)
      .sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen));
  }, [links, selected]);
  const selectedLinkIds = useMemo(
    () => new Set(connections.map((c) => c.id)),
    [connections],
  );

  const nodeRadius = (a: Asset) =>
    6 + Math.min(8, Math.log2(1 + a.event_count) / 2);

  return (
    <Shell>
      <main className="topology-page">
        <div className="page-heading">
          <div>
            <p className="eyebrow">NETWORK</p>
            <h1>Network topology</h1>
            <p className="muted">
              Assets and the connections observed between them. Dashed, moving
              lines carry traffic seen in the last 30 seconds and point from
              client to server.
            </p>
          </div>
          <span className="integration-count">
            {visibleAssets.length} assets · {visibleLinks.length} links ·{" "}
            {liveCount} live
          </span>
        </div>

        <section className="discover-querybar">
          <input
            className="discover-search-input"
            placeholder="Highlight assets by name, IP or tag…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <label className="sort-toggle" style={{ marginLeft: 0 }}>
            <input
              type="checkbox"
              checked={liveOnly}
              onChange={(e) => setLiveOnly(e.target.checked)}
            />
            Live links only
          </label>
          <label className="sort-toggle" style={{ marginLeft: 0 }}>
            <input
              type="checkbox"
              checked={hideIsolated}
              onChange={(e) => setHideIsolated(e.target.checked)}
            />
            Hide assets without connections
          </label>
          <label className="sort-toggle" style={{ marginLeft: 0 }}>
            <input
              type="checkbox"
              checked={labels}
              onChange={(e) => setLabels(e.target.checked)}
            />
            Labels
          </label>
        </section>

        {error && (
          <p className="msg error" role="alert">
            {error}
          </p>
        )}

        <div className={`topology-stage ${selectedAsset ? "has-panel" : ""}`}>
          <section className="topology-canvas" aria-label="Network graph">
            <svg
              ref={svgRef}
              className="topo-svg"
              onPointerDown={onBackgroundDown}
              onPointerMove={onMove}
              onPointerUp={onUp}
              onPointerCancel={onUp}
            >
              <g ref={viewRef}>
                <g>
                  {visibleLinks.map((l) => {
                    const live = now - Date.parse(l.last_seen) < LIVE_MS;
                    return (
                      <line
                        key={l.id}
                        ref={(el) => {
                          if (el) linkEls.current.set(l.id, el);
                          else linkEls.current.delete(l.id);
                        }}
                        className={`topo-link${live ? " live" : ""}${selectedLinkIds.has(l.id) ? " selected" : ""}`}
                        strokeWidth={Math.min(
                          5,
                          1 + Math.log10(1 + l.packets) * 0.8,
                        )}
                      />
                    );
                  })}
                </g>
                <g>
                  {visibleAssets.map((a) => {
                    const active = now - Date.parse(a.last_seen) < ACTIVE_MS;
                    const cls = [
                      "topo-node",
                      active ? "active" : "",
                      a.origin === "manual" ? "manual" : "",
                      a.criticality ? `crit-${a.criticality}` : "",
                      selected === a.id ? "selected" : "",
                      search.trim() && !matches(a) ? "dim" : "",
                    ]
                      .filter(Boolean)
                      .join(" ");
                    const r = nodeRadius(a);
                    return (
                      <g
                        key={a.id}
                        ref={(el) => {
                          if (el) nodeEls.current.set(a.id, el);
                          else nodeEls.current.delete(a.id);
                        }}
                        className={cls}
                        onPointerDown={onNodeDown(a.id)}
                      >
                        <rect
                          className="topo-node-background"
                          x="-27"
                          y="-27"
                          width="54"
                          height="54"
                          rx="12"
                        />

                        <circle
                          className="topo-node-status"
                          cx="19"
                          cy="-19"
                          r="4"
                        />

                        <AssetGlyph type={resolveAssetVisual(a)} />

                        {labels && (
                          <>
                            <text className="topo-node-label" y="43">
                              {a.name}
                            </text>
                            <text className="topo-node-ip" y="56">
                              {a.ips?.[0] ?? ""}
                            </text>
                          </>
                        )}

                        {labels && <text y={r + 13}>{a.name}</text>}
                        <title>{`${a.name}${a.ips?.length ? " · " + a.ips.join(", ") : ""}`}</title>
                      </g>
                    );
                  })}
                </g>
              </g>
            </svg>

            <div className="topology-toolbar">
              <button type="button" className="ghost" onClick={resetView}>
                Reset view
              </button>
              <button type="button" className="ghost" onClick={() => wake(1)}>
                Re-layout
              </button>
            </div>
            <div className="topology-legend" aria-hidden>
              <span className="lg-active">Active asset</span>
              <span>Idle asset</span>
              <span className="lg-live">Live connection</span>
            </div>
            {assets.length === 0 && (
              <div className="topology-empty">
                <div className="empty-state">
                  <strong>No assets to draw yet</strong>
                  <p>
                    Enable the Network packets integration. Connections between
                    private-range hosts appear here as soon as their packets are
                    captured.
                  </p>
                </div>
              </div>
            )}
          </section>

          {selectedAsset && (
            <aside className="topology-panel" aria-label="Selected asset">
              <div>
                <h2>{selectedAsset.name}</h2>
                <p className="muted">
                  {selectedAsset.origin === "manual"
                    ? "Added manually"
                    : "Discovered"}
                </p>
              </div>
              <dl>
                {selectedAsset.hostname && (
                  <>
                    <dt>Hostname</dt>
                    <dd>{selectedAsset.hostname}</dd>
                  </>
                )}
                <dt>IP addresses</dt>
                <dd>{(selectedAsset.ips ?? []).join(", ") || "—"}</dd>
                <dt>Services</dt>
                <dd>{(selectedAsset.ports ?? []).join(", ") || "—"}</dd>
                <dt>Seen via</dt>
                <dd>{(selectedAsset.sources ?? []).join(", ")}</dd>
                {(selectedAsset.tags ?? []).length > 0 && (
                  <>
                    <dt>Tags</dt>
                    <dd>{selectedAsset.tags.join(", ")}</dd>
                  </>
                )}
                <dt>Last seen</dt>
                <dd>{new Date(selectedAsset.last_seen).toLocaleString()}</dd>
              </dl>
              <h3>Connections ({connections.length})</h3>
              {connections.length === 0 && (
                <p className="muted">No connections observed for this asset.</p>
              )}
              {connections.map((l) => {
                const outgoing = l.source === selectedAsset.id;
                const peerId = outgoing ? l.target : l.source;
                const peer = byId.get(peerId);
                const live = now - Date.parse(l.last_seen) < LIVE_MS;
                return (
                  <button
                    key={l.id}
                    type="button"
                    className={`topology-conn${live ? " live" : ""}`}
                    onClick={() => setSelected(peerId)}
                  >
                    <strong>
                      {outgoing ? "→" : "←"} {peer?.name ?? peerId}
                    </strong>
                    <small>
                      {l.protocols.join("/")}
                      {l.ports.length ? ` · port ${l.ports.join(", ")}` : ""}
                    </small>
                    <small>
                      {l.packets.toLocaleString()} packets · {fmtBytes(l.bytes)}
                      {live ? " · live" : ""}
                    </small>
                  </button>
                );
              })}
            </aside>
          )}
        </div>
      </main>
    </Shell>
  );
}
