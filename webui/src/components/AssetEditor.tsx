import { useEffect, useState } from "react";
import TagsInput from "./TagsInput";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import type { Asset, AssetDraft, Criticality } from "../lib/types";

const CRITICALITIES: { value: Criticality; label: string }[] = [
  { value: "", label: "Unset" },
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "critical", label: "Critical" },
];

const SELECT_CLASS =
  "flex h-10 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50";

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
            <Label htmlFor="asset-ips">
              IP addresses
              <Input
                id="asset-ips"
                value={draft.ips}
                onChange={(e) => setDraft({ ...draft, ips: e.target.value })}
                placeholder="10.0.0.5, 10.0.0.6"
                autoComplete="off"
                disabled={busy}
                autoFocus
              />
              <small>
                Comma or space separated. The first IP becomes the asset ID.
              </small>
            </Label>
            <Label htmlFor="asset-hostname">
              Hostname
              <Input
                id="asset-hostname"
                value={draft.hostname}
                onChange={(e) =>
                  setDraft({ ...draft, hostname: e.target.value })
                }
                placeholder="plc-line1.example"
                autoComplete="off"
                disabled={busy}
              />
              <small>Required if no IP address is provided.</small>
            </Label>
          </>
        )}

        <Label htmlFor="asset-name">
          Display name
          <Input
            id="asset-name"
            value={draft.name}
            maxLength={128}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            placeholder={asset?.ips?.[0] ?? asset?.hostname ?? "PLC Line 1"}
            disabled={busy}
            autoFocus={isEdit}
          />
          <small>Overrides the auto-derived name shown in the inventory.</small>
        </Label>
        <div className="asset-editor-section">
          <div className="asset-editor-section-heading">
            <h3>Asset classification</h3>
            <small>General information about this device</small>
          </div>

          <div className="asset-editor-grid">
            <Label htmlFor="asset-device-type">
              Device Type
              <select
                id="asset-device-type"
                className={SELECT_CLASS}
                value={draft.device_type}
                onChange={(e) =>
                  setDraft({ ...draft, device_type: e.target.value })
                }
                disabled={busy}
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
            </Label>

            <Label htmlFor="asset-device-role">
              Device Role
              <Input
                id="asset-device-role"
                value={draft.device_role}
                maxLength={128}
                onChange={(e) =>
                  setDraft({ ...draft, device_role: e.target.value })
                }
                placeholder="Domain Controller, Engineering Station..."
                disabled={busy}
              />
            </Label>

            <Label htmlFor="asset-manufacturer">
              Manufacturer
              <Input
                id="asset-manufacturer"
                value={draft.manufacturer}
                maxLength={128}
                onChange={(e) =>
                  setDraft({ ...draft, manufacturer: e.target.value })
                }
                placeholder="Siemens, Schneider Electric, Dell..."
                disabled={busy}
              />
            </Label>

            <Label htmlFor="asset-model">
              Model
              <Input
                id="asset-model"
                value={draft.model}
                maxLength={128}
                onChange={(e) => setDraft({ ...draft, model: e.target.value })}
                placeholder="S7-1500, PowerEdge R750..."
                disabled={busy}
              />
            </Label>
          </div>
        </div>

        <div className="asset-editor-section">
          <div className="asset-editor-section-heading">
            <h3>Operating System</h3>
            <small>Manually maintained operating system information</small>
          </div>

          <div className="asset-editor-grid">
            <Label htmlFor="asset-os">
              Operating System
              <Input
                id="asset-os"
                value={draft.operating_system}
                maxLength={128}
                onChange={(e) =>
                  setDraft({ ...draft, operating_system: e.target.value })
                }
                placeholder="Windows Server, Ubuntu, VxWorks..."
                disabled={busy}
              />
            </Label>

            <Label htmlFor="asset-os-version">
              OS Version
              <Input
                id="asset-os-version"
                value={draft.os_version}
                maxLength={128}
                onChange={(e) =>
                  setDraft({ ...draft, os_version: e.target.value })
                }
                placeholder="2022, 22.04, 7.5..."
                disabled={busy}
              />
            </Label>
          </div>
        </div>
        <Label htmlFor="asset-criticality">
          Criticality
          <select
            id="asset-criticality"
            className={SELECT_CLASS}
            value={draft.criticality}
            onChange={(e) =>
              setDraft({ ...draft, criticality: e.target.value as Criticality })
            }
            disabled={busy}
          >
            {CRITICALITIES.map((c) => (
              <option key={c.value || "unset"} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
        </Label>
      </div>

      <Label className="asset-editor-tags" htmlFor="asset-tags">
        Tags
        <TagsInput
          id="asset-tags"
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
      </Label>

      {error && (
        <p className="msg error" role="alert">
          {error}
        </p>
      )}

      <div className="asset-editor-actions">
        <Button
          type="button"
          className="ghost"
          onClick={onCancel}
          disabled={busy}
        >
          Cancel
        </Button>
        <Button type="submit" disabled={busy}>
          {busy ? "Saving…" : isEdit ? "Save changes" : "Add asset"}
        </Button>
      </div>
    </form>
  );
}
