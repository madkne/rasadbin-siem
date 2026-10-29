"use strict";
(() => {
  const $ = (s) => document.querySelector(s);
  const form = $("#settings-form");
  const pwForm = $("#password-form");

  function say(sel, text, ok) {
    const el = $(sel);
    el.className = "msg " + (ok ? "ok" : "error");
    el.textContent = text;
  }

  function fill(s) {
    for (const [k, v] of Object.entries(s)) {
      if (form.elements[k]) form.elements[k].value = v;
    }
  }

  RB.on("ready", (me) => {
    if (me.role !== "admin") { $("#denied").hidden = false; return; }
    $("#general").hidden = false;
    $("#password").hidden = false;
    RB.send("settings.get");
  });

  RB.on("settings", fill);
  RB.on("settings_saved", (s) => { fill(s); say("#settings-msg", "Settings saved.", true); });

  RB.on("error", (e) => {
    if (e.for === "settings.update") say("#settings-msg", e.message, false);
    else if (e.for === "password.change") say("#password-msg", e.message, false);
    else if (e.for === "settings.get") $("#denied").hidden = false;
  });

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const f = form.elements;
    RB.send("settings.update", {
      instance_name: f.instance_name.value.trim(),
      log_level: f.log_level.value,
      session_minutes: Number(f.session_minutes.value),
      retention_days: Number(f.retention_days.value),
      refresh_seconds: Number(f.refresh_seconds.value),
    });
  });

  pwForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const f = pwForm.elements;
    if (f.new.value !== f.repeat.value) {
      say("#password-msg", "New passwords do not match.", false);
      return;
    }
    RB.send("password.change", { current: f.current.value, new: f.new.value });
  });

  RB.connect({ auth: true });
})();
