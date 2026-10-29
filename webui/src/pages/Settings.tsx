import { useEffect, useState } from "react";
import Shell from "../components/Shell";
import { ws } from "../lib/ws";
import type { Settings as SettingsT } from "../lib/types";

export default function Settings() {
  const [settings, setSettings] = useState<SettingsT | null>(null);
  const [settingsMsg, setSettingsMsg] = useState<{ text: string; ok: boolean } | null>(null);
  const [pwMsg, setPwMsg] = useState<{ text: string; ok: boolean } | null>(null);
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
                {dirty && <span className="settings-dirty">Unsaved changes</span>}
              </div>
              <form
                onSubmit={saveSettings}
                onChange={() => setDirty(true)}
                key={settings.instance_name + settings.log_level}
              >
                <div className="settings-grid">
                  <div className="settings-field">
                    <label htmlFor="instance_name">Instance name</label>
                    <input
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
                    <label htmlFor="log_level">Log level</label>
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
                    <label htmlFor="session_minutes">Session timeout (minutes)</label>
                    <input
                      id="session_minutes"
                      name="session_minutes"
                      type="number"
                      min={5}
                      max={1440}
                      required
                      defaultValue={settings.session_minutes}
                    />
                    <span className="settings-hint">5–1440 minutes of inactivity.</span>
                  </div>

                  <div className="settings-field">
                    <label htmlFor="retention_days">Event retention (days)</label>
                    <input
                      id="retention_days"
                      name="retention_days"
                      type="number"
                      min={1}
                      max={3650}
                      required
                      defaultValue={settings.retention_days}
                    />
                    <span className="settings-hint">1–3650 days of stored events.</span>
                  </div>

                  <div className="settings-field">
                    <label htmlFor="refresh_seconds">Dashboard refresh (seconds)</label>
                    <input
                      id="refresh_seconds"
                      name="refresh_seconds"
                      type="number"
                      min={1}
                      max={60}
                      required
                      defaultValue={settings.refresh_seconds}
                    />
                    <span className="settings-hint">1–60 seconds between pushes.</span>
                  </div>
                </div>

                <div className="settings-actions">
                  <button type="submit" disabled={!dirty || saving}>
                    {saving ? "Saving…" : "Save settings"}
                  </button>
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
                    <label htmlFor="current">Current password</label>
                    <input
                      id="current"
                      name="current"
                      type="password"
                      autoComplete="current-password"
                      maxLength={128}
                      required
                    />
                  </div>
                  <div className="settings-field">
                    <label htmlFor="new">New password</label>
                    <input
                      id="new"
                      name="new"
                      type="password"
                      autoComplete="new-password"
                      minLength={10}
                      maxLength={128}
                      required
                    />
                    <span className="settings-hint">Minimum 10 characters.</span>
                  </div>
                  <div className="settings-field">
                    <label htmlFor="repeat">Repeat new password</label>
                    <input
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
                  <button type="submit" disabled={changing}>
                    {changing ? "Changing…" : "Change password"}
                  </button>
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
