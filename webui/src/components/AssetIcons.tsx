import type { Asset } from "../lib/types";
import {
  Monitor,
  Server,
  Cpu,
  Shield,
  Network,
  Router,
  Gauge,
  Thermometer,
  HelpCircle,
  type LucideIcon,
} from "lucide-react";

export type AssetVisualType =
  | "workstation"
  | "server"
  | "plc"
  | "firewall"
  | "switch"
  | "router"
  | "hmi"
  | "sensor"
  | "unknown";

// Order matters: first match wins.
const RULES: [AssetVisualType, RegExp][] = [
  ["firewall", /firewall|fortigate|palo.?alto|checkpoint/],
  ["plc", /\bplc\b|\brtu\b|scada|programmable.?logic|modbus|dnp3|s7comm|iec.?104|logix/],
  ["hmi", /\bhmi\b|human.?machine/],
  ["switch", /switch|network.?device/],
  ["router", /router|gateway/],
  ["sensor", /sensor|\biot\b|io.?module/],
  ["server", /server|linux.?host|database/],
  ["workstation", /workstation|desktop|laptop|windows.?client/],
];

function classify(text: string): AssetVisualType | null {
  const value = text.trim().toLowerCase();
  if (!value) return null;
  for (const [type, re] of RULES) if (re.test(value)) return type;
  return null;
}

export function resolveAssetVisual(a: Asset): AssetVisualType {
  // 1. Analyst-set classification wins: device type, then role.
  const explicit = classify(a.device_type ?? "") ?? classify(a.device_role ?? "");
  if (explicit) return explicit;

  // 2. Discovered metadata.
  const fromMeta = classify(
    [
      a.name,
      a.hostname,
      ...(a.tags ?? []),
      ...(a.protocols ?? []),
      ...(a.services ?? []).map((s) => `${s.name} ${s.protocol ?? ""}`),
    ]
      .filter(Boolean)
      .join(" "),
  );
  if (fromMeta) return fromMeta;

  // 3. Well-known ports.
  const ports = a.ports ?? [];
  if (ports.some((p) => [502, 102, 20000, 2404, 44818, 4840].includes(p))) return "plc";
  if (ports.some((p) => [3389, 445, 139].includes(p))) return "workstation";
  if (ports.some((p) => [3306, 5432, 6379, 9200, 22, 80, 443].includes(p))) return "server";

  return "unknown";
}

const ICONS: Record<AssetVisualType, LucideIcon> = {
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

const SIZE = 28;

/** Renders a Lucide icon centered on (0,0) so it can sit inside an SVG node. */
export function AssetGlyph({ type }: { type: AssetVisualType }) {
  const Icon = ICONS[type] ?? HelpCircle;
  return (
    <g className={`asset-glyph glyph-${type}`}>
      <Icon
        className="asset-glyph-svg"
        x={-SIZE / 2}
        y={-SIZE / 2}
        width={SIZE}
        height={SIZE}
        strokeWidth={1.8}
      />
    </g>
  );
}