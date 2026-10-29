import { useEffect, useState } from "react";
import TopBar from "../components/TopBar";
import { ws } from "../lib/ws";
import type { ErrorPayload, Settings as SettingsT } from "../lib/types";

export default function Settings() {
  const [settings, setSettings] = useState<SettingsT | null>(null);
  const [settingsMsg, setSettingsMsg] = useState<{ text: string; ok: boolean } | null>(null);
  const [pwMsg, setPwMsg] = useState<{ text: string; ok: boolean } | null>(null);

  useEffect(() => {
    const offReady = ws.on("ready", () => ws.send("settings.get"));
    const offSettings = ws.on<SettingsT>("settings", setSettings);
    const offSaved = ws.on<SettingsT>("settings_saved", (s) => {
      setSettings(s);
      setSettingsMsg({ text: "Settings saved.", ok: true });
    });
    const offErr = ws.on<ErrorPayload>("error", (e) => {
      const msg = { text: e.message, ok: false };
      if (e.for === "settings.update") setSettingsMsg(msg);
      else if (e.for === "password.change") setPwMsg(msg);
    });
    return () => {
      offReady();
      offSettings();
      offSaved();
      offErr();
    };
  }, []);

  function saveSettings(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!settings) return;
    const f = new FormData(e.currentTarget);
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
    ws.send("password.change", {
      current: f.get("current"),
      new: f.get("new"),
    });
    form.reset();
  }

  return (
    <>
      <TopBar />
      <main>
        {settings === null ? (
          <p className="muted">Loading…</p>
        ) : (
          <>
            <section className="card">
              <h2>General</h2>
              <form onSubmit={saveSettings} key={settings.instance_name + settings.log_level}>
                <div className="row">
                  <label>
                    Instance name
                    <input name="instance_name" maxLength={64} required defaultValue={settings.instance_name} />
                  </label>
                  <label>
                    Log level
                    <select name="log_level" defaultValue={settings.log_level}>
                      <option value="debug">debug</option>
                      <option value="info">info</option>
                      <option value="warn">warn</option>
                      <option value="error">error</option>
                    </select>
                  </label>
                  <label>
                    Session timeout (minutes)
                    <input name="session_minutes" type="number" min={5} max={1440} required defaultValue={settings.session_minutes} />
                  </label>
                  <label>
                    Event retention (days)
                    <input name="retention_days" type="number" min={1} max={3650} required defaultValue={settings.retention_days} />
                  </label>
                  <label>
                    Dashboard refresh (seconds)
                    <input name="refresh_seconds" type="number" min={1} max={60} required defaultValue={settings.refresh_seconds} />
                  </label>
                </div>
                <div>
                  <button type="submit">Save settings</button>
                </div>
                {settingsMsg && (
                  <p className={`msg ${settingsMsg.ok ? "ok" : "error"}`} role="status">
                    {settingsMsg.text}
                  </p>
                )}
              </form>
            </section>

            <section className="card">
              <h2>Change password</h2>
              <form onSubmit={changePassword}>
                <div className="row">
                  <label>
                    Current password
                    <input name="current" type="password" autoComplete="current-password" maxLength={128} required />
                  </label>
                  <label>
                    New password (min. 10 characters)
                    <input name="new" type="password" autoComplete="new-password" minLength={10} maxLength={128} required />
                  </label>
                  <label>
                    Repeat new password
                    <input name="repeat" type="password" autoComplete="new-password" minLength={10} maxLength={128} required />
                  </label>
                </div>
                <div>
                  <button type="submit">Change password</button>
                </div>
                {pwMsg && (
                  <p className={`msg ${pwMsg.ok ? "ok" : "error"}`} role="status">
                    {pwMsg.text}
                  </p>
                )}
              </form>
            </section>
          </>
        )}
      </main>
    </>
  );
}