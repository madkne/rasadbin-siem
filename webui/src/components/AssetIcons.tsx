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
  Apple,
  AppWindow,
  Smartphone,
  Terminal,
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
  [
    "plc",
    /\bplc\b|\brtu\b|scada|programmable.?logic|modbus|dnp3|s7comm|iec.?104|logix/,
  ],
  ["hmi", /\bhmi\b|human.?machine/],
  ["switch", /switch|network.?device/],
  ["router", /router|gateway/],
  ["sensor", /sensor|\biot\b|io.?module/],
  ["server", /server|linux.?host|database/],
  ["workstation", /workstation|desktop|laptop|windows.?client/],
];

// Order matters: first match wins. Network OSes and Android must be checked
// before the generic Apple / Linux rules, or they get misclassified.
const OS_RULES: [RegExp, LucideIcon][] = [
  // Network device operating systems
  [
    /\bcisco\b|\bios[- ]?x[er]\b|\bnx-?os\b|\bjunos\b|\brouteros\b|\bfortios\b|\bpan-?os\b|\barubaos\b|\bsonic\b|\bopenwrt\b|\bdd-?wrt\b|\bedgeos\b|\bcomware\b|\bsr ?os\b|\beos\b/,
    Network,
  ],
  // Android before Linux ("Android (Linux 5.x)")
  [/\bandroid\b/, Smartphone],
  [/\bwindows\b|\bwin[ -]?(xp|7|8|10|11|ce|nt|server)\b/, AppWindow],
  [/\bmac ?os\b|\bos ?x\b|\bdarwin\b|\bmacintosh\b/, Apple],
  [/\bipados\b|\bios\b|\biphone\b|\bipad\b/, Smartphone],
  // Embedded / industrial RTOS
  [
    /\bvxworks\b|\bqnx\b|\bfreertos\b|\brtos\b|\bthreadx\b|\bzephyr\b|\bwind river\b|\bembedded\b|\bfirmware\b|\bsimatic\b|\bcodesys\b/,
    Cpu,
  ],
  // Linux / Unix / BSD
  [
    /\blinux\b|\bgnu\b|\bubuntu\b|\bdebian\b|\bcentos\b|\brhel\b|\bred ?hat\b|\bfedora\b|\balpine\b|\barch\b|\bmanjaro\b|\bopensuse\b|\bsuse\b|\brocky\b|\balma ?linux\b|\boracle linux\b|\bamazon linux\b|\bkali\b|\braspbian\b|\braspberry pi os\b|\bmint\b|\b(free|open|net|dragonfly)bsd\b|\bbsd\b|\bpfsense\b|\bopnsense\b|\bsolaris\b|\billumos\b|\baix\b|\bhp-?ux\b|\bunix\b/,
    Terminal,
  ],
];
function classify(text: string): AssetVisualType | null {
  const value = text.trim().toLowerCase();
  if (!value) return null;
  for (const [type, re] of RULES) if (re.test(value)) return type;
  return null;
}

export function resolveAssetVisual(a: Asset): AssetVisualType {
  // 1. Analyst-set classification wins: device type, then role.
  const explicit =
    classify(a.device_type ?? "") ?? classify(a.device_role ?? "");
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
  if (ports.some((p) => [502, 102, 20000, 2404, 44818, 4840].includes(p)))
    return "plc";
  if (ports.some((p) => [3389, 445, 139].includes(p))) return "workstation";
  if (ports.some((p) => [3306, 5432, 6379, 9200, 22, 80, 443].includes(p)))
    return "server";

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

/** Maps an operating system string to a small platform icon, or null when unknown. */
export function resolveOsIcon(os?: string | null): LucideIcon | null {
  const v = (os ?? "").trim().toLowerCase();
  if (!v) return null;
  for (const [re, icon] of OS_RULES) if (re.test(v)) return icon;
  return null;
}

const OS_ICON_SIZE = 10;

export function OsBadge({ os }: { os: string }) {
  const Icon = resolveOsIcon(os);
  if (!Icon) return null;
  return (
    <g className="asset-os">
      <Icon
        className="asset-os-svg"
        x={-OS_ICON_SIZE / 2}
        y={-OS_ICON_SIZE / 2}
        width={OS_ICON_SIZE}
        height={OS_ICON_SIZE}
        strokeWidth={1.2}
      />
    </g>
  );
}

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
