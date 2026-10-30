import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Shell from "../components/Shell";
import { ws } from "../lib/ws";
import type {
  ErrorPayload,
  InstalledProfile,
  ProfilePreview,
} from "../lib/types";

const MAX_ZIP_BYTES = 20 * 1024 * 1024;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function toBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function ProfileIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 3 20 6v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6l8-3Z" />
      <path d="m8.5 12 2.2 2.2 4.8-5" />
    </svg>
  );
}

export default function Profiles() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [profiles, setProfiles] = useState<InstalledProfile[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<ProfilePreview | null>(null);
  const [busy, setBusy] = useState<"validate" | "install" | string | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [dragging, setDragging] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const refresh = useCallback(() => ws.send("profiles.get"), []);

  useEffect(() => {
    const offReady = ws.on("ready", refresh);
    const offProfiles = ws.on("profiles", (items) => setProfiles(items ?? []));
    const offValidated = ws.on("profile.validated", (result) => {
      setPreview(result);
      setBusy(null);
      setError("");
      setNotice("Profile archive validated. Review the contents before installing.");
    });
    const offInstalled = ws.on("profile.installed", (result) => {
      setProfiles((old) => {
        const item = result.profile;
        return [...old.filter((p) => p.manifest.metadata.id !== item.manifest.metadata.id), item]
          .sort((a, b) => a.manifest.metadata.name.localeCompare(b.manifest.metadata.name));
      });
      setBusy(null);
      setPreview(null);
      setFile(null);
      if (inputRef.current) inputRef.current.value = "";
      setNotice("Security profile installed successfully.");
      setError("");
    });
    const offDeleted = ws.on("profile.deleted", (result) => {
      setProfiles(result.profiles ?? []);
      setBusy(null);
      setConfirmDelete(null);
      setNotice(`Profile "${result.id}" removed.`);
      setError("");
    });
    const offError = ws.on("error", (payload: ErrorPayload) => {
      if (!["profiles.get", "profile.validate", "profile.install", "profile.delete"].includes(payload.for ?? "")) return;
      setError(payload.message || "The profile operation failed.");
      setBusy(null);
    });

    if (ws.isReady) refresh();
    return () => {
      offReady();
      offProfiles();
      offValidated();
      offInstalled();
      offDeleted();
      offError();
    };
  }, [refresh]);

  const enabledIntegrations = useMemo(
    () => (preview?.integrations ?? []).filter((item) => item.enabled).length,
    [preview],
  );

  function acceptFile(candidate?: File) {
    if (!candidate) return;
    setError("");
    setNotice("");
    setPreview(null);
    if (!candidate.name.toLowerCase().endsWith(".zip")) {
      setFile(null);
      setError("Choose a .zip security profile archive.");
      return;
    }
    if (candidate.size === 0 || candidate.size > MAX_ZIP_BYTES) {
      setFile(null);
      setError(`ZIP size must be between 1 byte and ${formatBytes(MAX_ZIP_BYTES)}.`);
      return;
    }
    setFile(candidate);
  }

  async function validate() {
    if (!file || busy) return;
    setBusy("validate");
    setError("");
    setNotice("");
    try {
      const zip = await toBase64(file);
      ws.send("profile.validate", { zip });
    } catch {
      setBusy(null);
      setError("Could not read the selected ZIP file.");
    }
  }

  async function install() {
    if (!file || !preview || busy) return;
    setBusy("install");
    setError("");
    try {
      const zip = await toBase64(file);
      ws.send("profile.install", { zip });
    } catch {
      setBusy(null);
      setError("Could not read the selected ZIP file.");
    }
  }

  function remove(id: string) {
    if (busy) return;
    setBusy(id);
    setError("");
    ws.send("profile.delete", { id });
  }

  return (
    <Shell>
      <main className="profiles-page">
        <div className="profiles-heading">
          <div>
            <p className="eyebrow">SECURITY CONFIGURATION</p>
            <h1>Security profiles</h1>
            <p className="muted">
              Package detection rules, telemetry integrations and profile configuration into
              reusable ZIP bundles.
            </p>
          </div>
          <div className="profiles-total">
            <strong>{profiles.length.toString().padStart(2, "0")}</strong>
            <span>Installed profiles</span>
          </div>
        </div>

        {error && <div className="msg error profiles-message" role="alert">{error}</div>}
        {notice && <div className="msg ok profiles-message" role="status">{notice}</div>}

        <section className="profile-import card">
          <div className="profile-section-heading">
            <div className="profile-section-icon"><ProfileIcon /></div>
            <div>
              <p className="eyebrow">IMPORT PROFILE</p>
              <h2>Deploy a security baseline</h2>
              <p className="muted">Upload a profile ZIP, inspect its contents, then install it.</p>
            </div>
          </div>

          <div
            className={`profile-dropzone${dragging ? " is-dragging" : ""}${file ? " has-file" : ""}`}
            onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
            onDragLeave={(event) => {
              if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false);
            }}
            onDrop={(event) => {
              event.preventDefault();
              setDragging(false);
              acceptFile(event.dataTransfer.files[0]);
            }}
          >
            <input
              ref={inputRef}
              type="file"
              accept=".zip,application/zip"
              hidden
              onChange={(event) => acceptFile(event.target.files?.[0])}
            />
            <div className="profile-upload-symbol"><span>↑</span></div>
            {file ? (
              <>
                <strong>{file.name}</strong>
                <span className="muted">{formatBytes(file.size)} · ZIP archive</span>
                <button type="button" className="text-button" onClick={() => { setFile(null); setPreview(null); if (inputRef.current) inputRef.current.value = ""; }}>
                  Remove selected file
                </button>
              </>
            ) : (
              <>
                <strong>Drop your profile archive here</strong>
                <span className="muted">or select a ZIP file from your computer</span>
                <button type="button" className="secondary-button" onClick={() => inputRef.current?.click()}>
                  Browse files
                </button>
              </>
            )}
            <small>ZIP archive · Maximum {formatBytes(MAX_ZIP_BYTES)}</small>
          </div>

          <div className="profile-import-footer">
            <div className="profile-security-note">
              <span className="profile-note-mark">!</span>
              <span>Archives are validated before installation. Scripts and executable files are not run.</span>
            </div>
            <button type="button" disabled={!file || !!busy} onClick={validate}>
              {busy === "validate" ? <><span className="button-spinner" /> Validating…</> : "Validate archive"}
              {busy !== "validate" && <span aria-hidden="true">→</span>}
            </button>
          </div>
        </section>

        {preview && (
          <section className="profile-preview card">
            <div className="profile-preview-head">
              <div>
                <p className="eyebrow">VALIDATION COMPLETE</p>
                <h2>{preview.manifest.metadata.name}</h2>
                <p className="muted">{preview.manifest.metadata.description || "No description provided."}</p>
              </div>
              <span className="profile-valid-state"><span /> Valid archive</span>
            </div>
            <div className="profile-meta-row">
              <span><small>PROFILE ID</small><strong>{preview.manifest.metadata.id}</strong></span>
              <span><small>VERSION</small><strong>{preview.manifest.metadata.version}</strong></span>
              <span><small>AUTHOR</small><strong>{preview.manifest.metadata.author || "—"}</strong></span>
            </div>

            <div className="profile-preview-grid">
              <div className="profile-preview-stat">
                <span className="profile-stat-icon rules-icon">≡</span>
                <div><strong>{(preview.rules ?? []).length}</strong><span>Detection rules</span></div>
              </div>
              <div className="profile-preview-stat">
                <span className="profile-stat-icon integrations-icon">⌘</span>
                <div><strong>{(preview.integrations ?? []).length}</strong><span>Integrations</span></div>
              </div>
              <div className="profile-preview-stat">
                <span className="profile-stat-icon config-icon">▤</span>
                <div><strong>{(preview.config_files ?? []).length}</strong><span>Config files</span></div>
              </div>
            </div>

            <div className="profile-preview-columns">
              <div>
                <h3>Detection rules <span>{(preview.rules ?? []).length}</span></h3>
                {(preview.rules ?? []).length ? (
                  <ul className="profile-chip-list">{(preview.rules ?? []).map((id) => <li key={id}>{id}</li>)}</ul>
                ) : <p className="muted profile-empty-line">No rules included.</p>}
              </div>
              <div>
                <h3>Integrations <span>{(preview.integrations ?? []).length}</span></h3>
                {(preview.integrations ?? []).length ? (
                  <ul className="profile-integration-list">
                    {(preview.integrations ?? []).map((item) => (
                      <li key={item.id}>
                        <span className="profile-integration-dot" />
                        <span>{item.id}</span>
                        <small>{item.enabled ? "Enabled in profile" : "Disabled"}</small>
                      </li>
                    ))}
                  </ul>
                ) : <p className="muted profile-empty-line">No integrations included.</p>}
              </div>
            </div>

            {(preview.config_files ?? []).length > 0 && (
              <div className="profile-config-list">
                <h3>Configuration files</h3>
                {(preview.config_files ?? []).map((name) => <code key={name}>{name}</code>)}
              </div>
            )}
            {(preview.warnings ?? []).length > 0 && (
              <div className="profile-warnings">
                <strong>Notes</strong>
                {(preview.warnings ?? []).map((warning, index) => <p key={index}>{warning}</p>)}
              </div>
            )}
            <div className="profile-install-footer">
              <p className="muted">
                {enabledIntegrations} integration{enabledIntegrations === 1 ? "" : "s"} marked enabled.
                Existing resources may conflict with this profile.
              </p>
              <div>
                <button type="button" className="ghost" disabled={!!busy} onClick={() => { setPreview(null); setNotice(""); }}>
                  Cancel
                </button>
                <button type="button" disabled={!!busy} onClick={install}>
                  {busy === "install" ? <><span className="button-spinner" /> Installing…</> : "Install profile"}
                  {busy !== "install" && <span aria-hidden="true">→</span>}
                </button>
              </div>
            </div>
          </section>
        )}

        <section className="installed-profiles">
          <div className="installed-heading">
            <div><p className="eyebrow">PROFILE LIBRARY</p><h2>Installed profiles</h2></div>
            <button type="button" className="ghost" onClick={refresh} disabled={!!busy}>Refresh</button>
          </div>
          {profiles.length === 0 ? (
            <div className="profiles-empty card">
              <div className="profiles-empty-icon"><ProfileIcon /></div>
              <strong>No security profiles installed</strong>
              <p className="muted">Import a ZIP profile to deploy a reusable set of detection rules and integrations.</p>
            </div>
          ) : (
            <div className="installed-profile-grid">
              {profiles.map((item: InstalledProfile) => {
                const meta = item.manifest.metadata;
                return (
                  <article className="installed-profile-card card" key={meta.id}>
                    <div className="installed-profile-top">
                      <div className="installed-profile-icon"><ProfileIcon /></div>
                      <span className="profile-installed-label"><span /> Installed</span>
                    </div>
                    <h3>{meta.name}</h3>
                    <p className="muted">{meta.description || "Security profile"}</p>
                    <div className="installed-profile-tags">
                      <span>v{meta.version}</span>
                      <span>{(item.rule_ids ?? []).length} rules</span>
                      <span>{(item.integrations ?? []).length} integrations</span>
                    </div>
                    <div className="installed-profile-details">
                      <span>Profile ID</span><code>{meta.id}</code>
                      <span>Installed</span><span>{new Date(item.installed_at).toLocaleString()}</span>
                    </div>
                    {confirmDelete === meta.id ? (
                      <div className="profile-delete-confirm">
                        <p>Remove this profile and its owned rules?</p>
                        <div>
                          <button type="button" className="ghost" disabled={!!busy} onClick={() => setConfirmDelete(null)}>Cancel</button>
                          <button type="button" className="danger-button" disabled={!!busy} onClick={() => remove(meta.id)}>
                            {busy === meta.id ? "Removing…" : "Confirm remove"}
                          </button>
                        </div>
                      </div>
                    ) : (
                      <button type="button" className="danger-ghost profile-remove" disabled={!!busy} onClick={() => setConfirmDelete(meta.id)}>
                        Remove profile
                      </button>
                    )}
                  </article>
                );
              })}
            </div>
          )}
        </section>
      </main>
    </Shell>
  );
}
