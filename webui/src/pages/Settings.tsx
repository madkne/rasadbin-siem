import { useEffect, useState } from "react";
import Shell from "../components/Shell";
import { ws } from "../lib/ws";
import type { Settings as SettingsT } from "../lib/types";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";

export default function Settings() {
  const [settings, setSettings] = useState<SettingsT | null>(null);
  const [settingsMsg, setSettingsMsg] = useState<{
    text: string;
    ok: boolean;
  } | null>(null);
  const [pwMsg, setPwMsg] = useState<{ text: string; ok: boolean } | null>(
    null,
  );
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [changing, setChanging] = useState(false);

  useEffect(() => {
    const offReady = ws.on("ready", () => ws.send("settings.get"));
    const offSettings = ws.on("settings", setSettings);
    const offSaved = ws.on("settings_saved", (s) => {
      setSettings(s);
      setSaving(false);
      setDirty(false);
      setSettingsMsg({ text: "Settings saved.", ok: true });
    });
    const offErr = ws.on("error", (e) => {
      const msg = { text: e.message, ok: false };
      if (e.for === "settings.update") {
        setSaving(false);
        setSettingsMsg(msg);
      } else if (e.for === "password.change") {
        setChanging(false);
        setPwMsg(msg);
      }
    });
    if (ws.isReady) ws.send("settings.get");
    return () => {
      offReady();
      offSettings();
      offSaved();
      offErr();
    };
  }, []);

  function saveSettings(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!settings || saving) return;
    const f = new FormData(e.currentTarget);
    setSaving(true);
    setSettingsMsg(null);
    ws.send("settings.update", {
      instance_name: String(f.get("instance_name")).trim(),
      log_level: f.get("log_level"),
      session_minutes: Number(f.get("session_minutes")),
      retention_days: Number(f.get("retention_days")),
      refresh_seconds: Number(f.get("refresh_seconds")),
      active_enrichment_enabled: f.get("active_enrichment_enabled") === "on",
      active_enrichment_cidrs: String(f.get("active_enrichment_cidrs") || "")
        .split(/[\n,]+/)
        .map((v) => v.trim())
        .filter(Boolean),
    });
  }

  function changePassword(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    if (f.get("new") !== f.get("repeat")) {
      setPwMsg({ text: "New passwords do not match.", ok: false });
      return;
    }
    setPwMsg(null);
    setChanging(true);
    ws.send("password.change", {
      current: f.get("current"),
      new: f.get("new"),
    });
    form.reset();
  }

  return (
    <Shell>
      <main className="settings-page">
        <section className="page-heading">
          <div>
            <p className="eyebrow">ADMINISTRATION</p>
            <h1>Settings</h1>
            <p className="muted">
              Configure instance identity, runtime logging, session policy and
              account security. Changes apply immediately.
            </p>
          </div>
        </section>

        {settings === null ? (
          <section className="panel">
            <p className="muted">Loading…</p>
          </section>
        ) : (
          <>
            <section className="panel settings-panel">
              <div className="panel-heading settings-panel-head">
                <div>
                  <p className="eyebrow">INSTANCE</p>
                  <h2>General</h2>
                </div>
                {dirty && (
                  <span className="settings-dirty">Unsaved changes</span>
                )}
              </div>
              <form
                onSubmit={saveSettings}
                onChange={() => setDirty(true)}
                key={
                  settings.instance_name +
                  settings.log_level +
                  String(settings.active_enrichment_enabled) +
                  (settings.active_enrichment_cidrs ?? []).join(",")
                }
              >
                <div className="settings-grid">
                  <div className="settings-field">
                    <Label htmlFor="instance_name">Instance name</Label>
                    <Input
                      id="instance_name"
                      name="instance_name"
                      maxLength={64}
                      required
                      defaultValue={settings.instance_name}
                      placeholder="Rasadbin"
                    />
                    <span className="settings-hint">
                      Shown in the top bar and browser title. 1–64 characters.
                    </span>
                  </div>

                  <div className="settings-field">
                    <Label htmlFor="log_level">Log level</Label>
                    <select
                      id="log_level"
                      name="log_level"
                      defaultValue={settings.log_level}
                    >
                      <option value="debug">debug</option>
                      <option value="info">info</option>
                      <option value="warn">warn</option>
                      <option value="error">error</option>
                    </select>
                    <span className="settings-hint">
                      Controls verbosity of server logs.
                    </span>
                  </div>

                  <div className="settings-field">
                    <Label htmlFor="session_minutes">
                      Session timeout (minutes)
                    </Label>
                    <Input
                      id="session_minutes"
                      name="session_minutes"
                      type="number"
                      min={5}
                      max={1440}
                      required
                      defaultValue={settings.session_minutes}
                    />
                    <span className="settings-hint">
                      5–1440 minutes of inactivity.
                    </span>
                  </div>

                  <div className="settings-field">
                    <Label htmlFor="retention_days">
                      Event retention (days)
                    </Label>
                    <Input
                      id="retention_days"
                      name="retention_days"
                      type="number"
                      min={1}
                      max={3650}
                      required
                      defaultValue={settings.retention_days}
                    />
                    <span className="settings-hint">
                      1–3650 days. Older events are deleted automatically every
                      hour.
                    </span>
                  </div>

                  <div className="settings-field">
                    <Label htmlFor="refresh_seconds">
                      Dashboard refresh (seconds)
                    </Label>
                    <Input
                      id="refresh_seconds"
                      name="refresh_seconds"
                      type="number"
                      min={1}
                      max={60}
                      required
                      defaultValue={settings.refresh_seconds}
                    />
                    <span className="settings-hint">
                      1–60 seconds between pushes.
                    </span>
                  </div>
                </div>

                <div
                  className="settings-panel-head"
                  style={{ marginTop: "1.5rem" }}
                >
                  <div>
                    <p className="eyebrow">OT / IT SAFETY</p>
                    <h2>Active enrichment permission</h2>
                    <p className="muted settings-note">
                      Passive enrichment is always preferred. Active probes are
                      disabled by default and may only target IPs inside the
                      explicit CIDR allowlist below. No active probes are
                      enabled by this release.
                    </p>
                  </div>
                </div>
                <div className="settings-grid">
                  <div className="settings-field">
                    <Label htmlFor="active_enrichment_enabled">
                      Allow active enrichment
                    </Label>
                    <Input
                      id="active_enrichment_enabled"
                      name="active_enrichment_enabled"
                      type="checkbox"
                      defaultChecked={settings.active_enrichment_enabled}
                    />
                    <span className="settings-hint">
                      Explicit administrative permission for future active
                      providers. Default: disabled.
                    </span>
                  </div>
                  <div className="settings-field">
                    <Label htmlFor="active_enrichment_cidrs">
                      Allowed target CIDRs
                    </Label>
                    <textarea
                      id="active_enrichment_cidrs"
                      name="active_enrichment_cidrs"
                      rows={3}
                      defaultValue={(
                        settings.active_enrichment_cidrs || []
                      ).join("\n")}
                      placeholder="192.168.10.0/24\n10.20.0.0/16"
                    />
                    <span className="settings-hint">
                      One CIDR per line. Enabling active enrichment without an
                      allowlist is rejected.
                    </span>
                  </div>
                </div>

                <div className="settings-actions">
                  <Button type="submit" disabled={!dirty || saving}>
                    {saving ? "Saving…" : "Save settings"}
                  </Button>
                  {settingsMsg && (
                    <p
                      className={`msg ${settingsMsg.ok ? "ok" : "error"}`}
                      role="status"
                    >
                      {settingsMsg.text}
                    </p>
                  )}
                </div>
              </form>
            </section>

            <section className="panel settings-panel">
              <div className="panel-heading settings-panel-head">
                <div>
                  <p className="eyebrow">SECURITY</p>
                  <h2>Change password</h2>
                </div>
              </div>
              <p className="muted settings-note">
                Changing your password revokes all active sessions, including
                this one. You will be signed out afterwards.
              </p>
              <form onSubmit={changePassword}>
                <div className="settings-grid">
                  <div className="settings-field">
                    <Label htmlFor="current">Current password</Label>
                    <Input
                      id="current"
                      name="current"
                      type="password"
                      autoComplete="current-password"
                      maxLength={128}
                      required
                    />
                  </div>
                  <div className="settings-field">
                    <Label htmlFor="new">New password</Label>
                    <Input
                      id="new"
                      name="new"
                      type="password"
                      autoComplete="new-password"
                      minLength={10}
                      maxLength={128}
                      required
                    />
                    <span className="settings-hint">
                      Minimum 10 characters.
                    </span>
                  </div>
                  <div className="settings-field">
                    <Label htmlFor="repeat">Repeat new password</Label>
                    <Input
                      id="repeat"
                      name="repeat"
                      type="password"
                      autoComplete="new-password"
                      minLength={10}
                      maxLength={128}
                      required
                    />
                  </div>
                </div>

                <div className="settings-actions">
                  <Button type="submit" disabled={changing}>
                    {changing ? "Changing…" : "Change password"}
                  </Button>
                  {pwMsg && (
                    <p
                      className={`msg ${pwMsg.ok ? "ok" : "error"}`}
                      role="status"
                    >
                      {pwMsg.text}
                    </p>
                  )}
                </div>
              </form>
            </section>
          </>
        )}
      </main>
    </Shell>
  );
}
