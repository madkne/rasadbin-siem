import { useEffect, useState } from "react";
import TagsInput from "./TagsInput";
import type { Asset, AssetDraft, Criticality } from "../lib/types";

const CRITICALITIES: { value: Criticality; label: string }[] = [
  { value: "", label: "Unset" },
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "critical", label: "Critical" },
];

export function emptyDraft(): AssetDraft {
  return {
    ips: "",
    hostname: "",
    name: "",
    criticality: "",
    tags: [],

    device_type: "",
    device_role: "",
    manufacturer: "",
    model: "",
    operating_system: "",
    os_version: "",
  };
}

export function draftFromAsset(a: Asset): AssetDraft {
  return {
    ips: (a.ips ?? []).join(", "),
    hostname: a.hostname ?? "",
    name: a.name ?? "",
    criticality: (a.criticality as Criticality) ?? "",
    tags: a.tags ?? [],

    device_type: a.device_type ?? "",
    device_role: a.device_role ?? "",
    manufacturer: a.manufacturer ?? "",
    model: a.model ?? "",
    operating_system: a.operating_system ?? "",
    os_version: a.os_version ?? "",
  };
}

interface Props {
  /** Editing an existing asset when set; creating a new one otherwise. */
  asset?: Asset;
  /** Tag values suggested across the inventory (e.g. common tags). */
  tagSuggestions?: string[];
  busy?: boolean;
  onSubmit: (draft: AssetDraft) => void;
  onCancel: () => void;
}

export default function AssetEditor({
  asset,
  tagSuggestions = [],
  busy = false,
  onSubmit,
  onCancel,
}: Props) {
  const [draft, setDraft] = useState<AssetDraft>(() =>
    asset ? draftFromAsset(asset) : emptyDraft(),
  );
  const [error, setError] = useState("");

  // Reset when the target asset changes.
  useEffect(() => {
    setDraft(asset ? draftFromAsset(asset) : emptyDraft());
    setError("");
  }, [asset]);

  const isEdit = Boolean(asset);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const ips = draft.ips
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const hostname = draft.hostname.trim();
    if (ips.length === 0 && !hostname) {
      setError("An IP address or hostname is required.");
      return;
    }
    // Cheap client-side IP sanity check; the server validates fully.
    const badIp = ips.find(
      (ip) => !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && !ip.includes(":"),
    );
    if (badIp) {
      setError(`"${badIp}" does not look like an IP address.`);
      return;
    }
    setError("");
    onSubmit({ ...draft, ips: ips.join(", "), hostname });
  }

  return (
    <form className="asset-editor" onSubmit={submit}>
      <div className="asset-editor-grid">
        {!isEdit && (
          <>
            <label>
              IP addresses
              <input
                value={draft.ips}
                onChange={(e) => setDraft({ ...draft, ips: e.target.value })}
                placeholder="10.0.0.5, 10.0.0.6"
                autoComplete="off"
              />
              <small>
                Comma or space separated. The first IP becomes the asset ID.
              </small>
            </label>
            <label>
              Hostname
              <input
                value={draft.hostname}
                onChange={(e) =>
                  setDraft({ ...draft, hostname: e.target.value })
                }
                placeholder="plc-line1.example"
                autoComplete="off"
              />
              <small>Required if no IP address is provided.</small>
            </label>
          </>
        )}

        <label>
          Display name
          <input
            value={draft.name}
            maxLength={128}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            placeholder={asset?.ips?.[0] ?? asset?.hostname ?? "PLC Line 1"}
          />
          <small>Overrides the auto-derived name shown in the inventory.</small>
        </label>
        <div className="asset-editor-section">
          <div className="asset-editor-section-heading">
            <h3>Asset classification</h3>
            <small>General information about this device</small>
          </div>

          <div className="asset-editor-grid">
            <label>
              Device Type
              <select
                value={draft.device_type}
                onChange={(e) =>
                  setDraft({ ...draft, device_type: e.target.value })
                }
              >
                <option value="">Unknown</option>
                <option value="workstation">Workstation</option>
                <option value="server">Server</option>
                <option value="plc">PLC</option>
                <option value="rtu">RTU</option>
                <option value="hmi">HMI</option>
                <option value="scada">SCADA</option>
                <option value="firewall">Firewall</option>
                <option value="router">Router</option>
                <option value="switch">Switch</option>
                <option value="iot">IoT Device</option>
                <option value="network_device">Network Device</option>
                <option value="other">Other</option>
              </select>
            </label>

            <label>
              Device Role
              <input
                value={draft.device_role}
                maxLength={128}
                onChange={(e) =>
                  setDraft({ ...draft, device_role: e.target.value })
                }
                placeholder="Domain Controller, Engineering Station..."
              />
            </label>

            <label>
              Manufacturer
              <input
                value={draft.manufacturer}
                maxLength={128}
                onChange={(e) =>
                  setDraft({ ...draft, manufacturer: e.target.value })
                }
                placeholder="Siemens, Schneider Electric, Dell..."
              />
            </label>

            <label>
              Model
              <input
                value={draft.model}
                maxLength={128}
                onChange={(e) => setDraft({ ...draft, model: e.target.value })}
                placeholder="S7-1500, PowerEdge R750..."
              />
            </label>
          </div>
        </div>

        <div className="asset-editor-section">
          <div className="asset-editor-section-heading">
            <h3>Operating System</h3>
            <small>Manually maintained operating system information</small>
          </div>

          <div className="asset-editor-grid">
            <label>
              Operating System
              <input
                value={draft.operating_system}
                maxLength={128}
                onChange={(e) =>
                  setDraft({ ...draft, operating_system: e.target.value })
                }
                placeholder="Windows Server, Ubuntu, VxWorks..."
              />
            </label>

            <label>
              OS Version
              <input
                value={draft.os_version}
                maxLength={128}
                onChange={(e) =>
                  setDraft({ ...draft, os_version: e.target.value })
                }
                placeholder="2022, 22.04, 7.5..."
              />
            </label>
          </div>
        </div>
        <label>
          Criticality
          <select
            value={draft.criticality}
            onChange={(e) =>
              setDraft({ ...draft, criticality: e.target.value as Criticality })
            }
          >
            {CRITICALITIES.map((c) => (
              <option key={c.value || "unset"} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <label className="asset-editor-tags">
        Tags
        <TagsInput
          value={draft.tags}
          onChange={(tags) => setDraft({ ...draft, tags })}
          suggestions={tagSuggestions}
          placeholder="Add a tag and press Enter"
          maxLength={64}
        />
        <small>
          Up to 16 tags, 64 characters each. Free-form labels used for
          filtering.
        </small>
      </label>

      {error && (
        <p className="msg error" role="alert">
          {error}
        </p>
      )}

      <div className="asset-editor-actions">
        <button
          type="button"
          className="ghost"
          onClick={onCancel}
          disabled={busy}
        >
          Cancel
        </button>
        <button type="submit" disabled={busy}>
          {busy ? "Saving…" : isEdit ? "Save changes" : "Add asset"}
        </button>
      </div>
    </form>
  );
}
