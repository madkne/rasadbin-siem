import { Asset } from "../lib/types";

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

  // Explicit device classification has priority.
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

export function AssetGlyph({ type }: { type: AssetVisualType }) {
  const common = {
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };

  return (
    <g className={`asset-glyph glyph-${type}`} {...common}>
      {type === "workstation" && (
        <>
          <rect x="5" y="3" width="30" height="21" rx="3" />
          <path d="M20 24v5m-7 0h14" />
          <path d="M10 8h20v11H10z" />
          <rect x="14" y="30" width="12" height="7" rx="1.5" />
          <circle cx="23" cy="33.5" r=".8" />
        </>
      )}

      {type === "server" && (
        <>
          <rect x="7" y="2" width="26" height="36" rx="3" />
          {[7, 19, 31].map((y) => (
            <g key={y}>
              <rect x="11" y={y} width="18" height="7" rx="1.5" />
              <circle cx="15" cy={y + 3.5} r="1" />
              <path d={`M20 ${y + 3.5}h5`} />
            </g>
          ))}
        </>
      )}

      {type === "plc" && (
        <>
          <rect x="3" y="5" width="34" height="29" rx="3" />
          <rect x="7" y="9" width="10" height="12" rx="1" />
          <path d="M10 13h4m-4 4h4" />
          <path d="M21 10v17m5-17v17m5-17v17" />
          <circle cx="10" cy="27" r="1.5" />
          <circle cx="16" cy="27" r="1.5" />
        </>
      )}

      {type === "firewall" && (
        <>
          <path d="M20 2 35 8v11c0 9-7 14-15 18C12 33 5 28 5 19V8z" />
          <path d="M5 14h30M8 23h24" />
          <path d="M13 14v9m14-9v9m-7 0v9" />
        </>
      )}

      {type === "switch" && (
        <>
          <rect x="2" y="10" width="36" height="20" rx="3" />
          {Array.from({ length: 8 }, (_, i) => (
            <rect key={i} x={5 + i * 4} y="16" width="2.5" height="5" rx=".5" />
          ))}
          <path d="M8 25h24" />
        </>
      )}

      {type === "router" && (
        <>
          <rect x="4" y="13" width="32" height="20" rx="3" />
          <path d="M11 13V5m-3 3 3-3 3 3M29 13V5m-3 3 3-3 3 3" />
          <circle cx="11" cy="23" r="1.5" />
          <circle cx="19" cy="23" r="1.5" />
          <circle cx="27" cy="23" r="1.5" />
        </>
      )}

      {type === "hmi" && (
        <>
          <rect x="3" y="3" width="34" height="30" rx="3" />
          <rect x="8" y="8" width="24" height="15" rx="1" />
          <path d="M12 18v-4m6 4v-7m6 7v-5m-11 15h12" />
        </>
      )}

      {type === "sensor" && (
        <>
          <path d="M20 4v8m-6-2a9 9 0 1 0 12 0" />
          <circle cx="20" cy="25" r="3" />
          <path d="M10 6 6 2m24 4 4-4" />
        </>
      )}

      {type === "unknown" && (
        <>
          <rect x="4" y="5" width="32" height="28" rx="4" />
          <circle cx="20" cy="19" r="8" />
          <path d="M20 14v6m0 4h.01" />
        </>
      )}
    </g>
  );
}
