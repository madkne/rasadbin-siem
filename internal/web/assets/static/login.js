"use strict";
(() => {
  const form = document.querySelector("#login-form");
  const btn = document.querySelector("#submit");
  const msg = document.querySelector("#msg");

  RB.on("open", () => { btn.disabled = false; btn.textContent = "Sign in"; });
  RB.on("close", () => { btn.disabled = true; btn.textContent = "Reconnecting…"; });

  RB.on("login_ok", (d) => {
    RB.setToken(d.token);
    location.replace("/dashboard");
  });
  RB.on("login_failed", (d) => {
    msg.className = "msg error";
    msg.textContent = d.message;
    btn.disabled = false;
    form.elements.password.value = "";
    form.elements.password.focus();
  });

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    msg.textContent = "";
    btn.disabled = true;
    RB.send("login", {
      username: form.elements.username.value.trim(),
      password: form.elements.password.value,
    });
  });

  RB.connect({ auth: false });
})();
