import { Asset } from "../lib/types";
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
} from "lucide-react";

type AssetVisualType =
  | "workstation"
  | "server"
  | "plc"
  | "firewall"
  | "switch"
  | "router"
  | "hmi"
  | "sensor"
  | "unknown";

export function resolveAssetVisual(a: Asset): AssetVisualType {
  const explicit =
    `${a.device_type ?? ""} ${a.device_role ?? ""}`.toLowerCase();

  const metadata = [
    a.name,
    a.hostname,
    ...(a.tags ?? []),
    ...(a.protocols ?? []),
    ...(a.services ?? []).map((s) => `${s.name} ${s.protocol}`),
  ]
    .join(" ")
    .toLowerCase();

  const value = explicit || metadata;

  if (/firewall|fortigate|palo.?alto|checkpoint/.test(value)) return "firewall";

  if (
    /plc|programmable.?logic|controller|modbus|dnp3|s7comm|iec104/.test(value)
  )
    return "plc";

  if (/\bhmi\b|human.?machine/.test(value)) return "hmi";

  if (/switch|ethernet.?switch/.test(value)) return "switch";

  if (/router|gateway/.test(value)) return "router";

  if (/sensor|temperature.?sensor|io.?module/.test(value)) return "sensor";

  if (/server|linux.?host|database|web.?server/.test(value)) return "server";

  if (/workstation|desktop|laptop|windows.?client/.test(value))
    return "workstation";

  const ports = a.ports ?? [];

  if (ports.some((p) => [502, 102, 20000, 2404, 44818, 4840].includes(p)))
    return "plc";

  if (ports.some((p) => [3389, 445, 139].includes(p))) return "workstation";

  if (ports.some((p) => [3306, 5432, 6379, 9200].includes(p))) return "server";

  return "unknown";
}

const ICONS: Record<AssetVisualType, any> = {
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

export function AssetGlyph({ type }: { type: AssetVisualType }) {
  const Icon = ICONS[type] ?? HelpCircle;
  return <Icon size={28} strokeWidth={1.8} />;
}
