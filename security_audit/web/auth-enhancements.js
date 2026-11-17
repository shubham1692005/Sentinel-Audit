/* Adds account flows and administrative user management while using the existing API/session. */
(function () {
  let pendingChallenge = "";
  let originalRender = window.render;
  let originalShell = window.shell;
  let originalInit = window.init;
  const captchaKey = window.AUDIT_CAPTCHA_SITE_KEY || "";
  const captchaReady = window.AUDIT_ACCOUNT_CAPTCHA_READY ?? Boolean(captchaKey);
  const emailReady = window.AUDIT_ACCOUNT_EMAIL_READY ?? false;
  const h = value => esc(value);

  function accountSetupNote() {
    const missing = [];
    if (!emailReady) missing.push("SMTP_HOST and SMTP_FROM for email-based password recovery");
    if (!captchaReady) missing.push("CAPTCHA_SITE_KEY and CAPTCHA_SECRET_KEY for verification-email resend");
    return missing.length ? `<div class="bottom-note">${missing.map(h).join("; ")}. Ask your administrator to configure these in .env and restart Sentinel Audit. New accounts can still be created without email verification.</div>` : "";
  }
  function captchaBox(showSetupNote = true) {
    const note = showSetupNote ? accountSetupNote() : "";
    if (!captchaReady || !captchaKey) return note;
    return `<div id="captcha-box"></div><input type="hidden" name="captcha_token" id="captcha-token">${note}`;
  }
  function disableUnavailableAccountForm(form) {
    if (captchaReady && emailReady) return;
    const button = form?.querySelector("button[type=submit], button:not([type])");
    if (button) { button.disabled = true; button.title = "Administrator setup is required before email account services can be used."; }
  }
  function disableForgotForm(form) {
    if (emailReady) return;
    const button = form?.querySelector("button[type=submit], button:not([type])");
    if (button) { button.disabled = true; button.title = "Configure SMTP or ask your administrator to reset this account."; }
  }
  function mountCaptcha() {
    if (!captchaReady || !captchaKey || !document.querySelector("#captcha-box")) return;
    const render = () => {
      const box = document.querySelector("#captcha-box");
      if (box && window.turnstile && !box.dataset.widget) {
        box.dataset.widget = String(window.turnstile.render(box, {sitekey: captchaKey, callback: token => { const input = document.querySelector("#captcha-token"); if (input) input.value = token; }}));
      }
    };
    if (window.turnstile) return render();
    let script = document.querySelector("#turnstile-script");
    if (!script) { script = document.createElement("script"); script.id = "turnstile-script"; script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"; script.async = true; script.defer = true; script.onload = render; document.head.appendChild(script); }
    else script.addEventListener("load", render, {once: true});
  }
  function authPage(mode, options = {}) {
    document.body.className = "auth-body";
    const token = options.token || "";
    const pages = {
      login: `<h1>Welcome back</h1><p>Sign in to continue to your security workspace.</p><form id="auth-login"><label>Email address<input type="email" name="email" autocomplete="username" required autofocus></label><label>Password<input type="password" name="password" autocomplete="current-password" required></label>${captchaBox(false)}<button class="primary full">Sign in <span>→</span></button></form><div class="auth-links"><button data-auth="forgot">Forgot password?</button><button data-auth="register">Create account</button></div>`,
      register: `<h1>Create account</h1><p>Use your email address and create a password to get started.</p><form id="auth-register"><label>Email address<input type="email" name="email" maxlength="254" autocomplete="email" required></label><label>Password<input type="password" name="password" minlength="6" maxlength="256" autocomplete="new-password" required><small>Minimum 6 characters.</small></label><label>Confirm password<input type="password" name="confirm_password" minlength="6" maxlength="256" required></label><button class="primary full">Create account</button></form><div class="auth-links"><button data-auth="login">Back to sign in</button></div>`,
      verify: `<h1>Verify email</h1><p>Paste the single-use code sent to your email. It expires after 24 hours.</p><form id="auth-verify"><label>Verification code<input name="token" maxlength="256" required value="${h(token)}"></label><button class="primary full">Verify email</button></form><form id="auth-resend"><label>Email address<input type="email" name="email" required></label>${captchaBox()}<button class="button full">Resend verification email</button></form><div class="auth-links"><button data-auth="login">Back to sign in</button></div>`,
      forgot: `<h1>Reset password</h1><p>If an eligible account exists, we’ll send a time-limited reset code.</p><form id="auth-forgot"><label>Email address<input type="email" name="email" required autocomplete="email"></label>${!emailReady ? `<div class="bottom-note">Password reset email is unavailable until an administrator configures SMTP. Contact your administrator to reset the account.</div>` : ""}<button class="primary full">Send reset code</button></form><div class="auth-links"><button data-auth="login">Back to sign in</button></div>`,
      reset: `<h1>Choose a new password</h1><p>Reset links expire in 30 minutes and work once.</p><form id="auth-reset"><input type="hidden" name="token" value="${h(token)}"><label>New password<input type="password" name="password" minlength="6" maxlength="256" required autocomplete="new-password"></label><label>Confirm password<input type="password" name="confirm_password" minlength="6" maxlength="256" required></label><button class="primary full">Reset password</button></form>`,
      invite: `<h1>Accept invitation</h1><p>Create a password to activate your invited Sentinel Audit account.</p><form id="auth-invite"><input type="hidden" name="token" value="${h(token)}"><label>New password<input type="password" name="password" minlength="6" maxlength="256" required></label><label>Confirm password<input type="password" name="confirm_password" minlength="6" maxlength="256" required></label><button class="primary full">Accept invitation</button></form>`,
      mfa: `<h1>Two-factor verification</h1><p>Enter your six-digit authenticator code or a one-time recovery code.</p><form id="auth-mfa"><label>Verification code<input name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus></label><button class="primary full">Verify and sign in</button></form>`,
      verified: `<h1>Email verified</h1><p>Your account is ready. Sign in to continue.</p><button class="primary full" id="verified-login">Sign in</button>`
    };
    $("#app").innerHTML = `<main class="auth-wrap"><div class="auth-brand"><span class="logo">S</span><div><b>Sentinel</b><small>SECURITY ASSURANCE</small></div></div><section class="auth-card"><div class="eyebrow">SECURE WORKSPACE</div>${pages[mode] || pages.login}<div id="auth-toast" class="toast" role="status" aria-live="polite"></div></section><div class="auth-hint">Self-hosted · Server-side security controls · Existing workspace data</div></main>`;
    document.querySelectorAll("[data-auth]").forEach(button => button.onclick = () => authPage(button.dataset.auth));
    const notify = message => { const el = $("#auth-toast"); if (el) { el.textContent = message; el.className = "toast show"; } };
    const captchaToken = form => form.elements.captcha_token?.value || "";
    if (["login", "register", "forgot", "verify"].includes(mode)) mountCaptcha();
    if (mode === "login") $("#auth-login").onsubmit = async event => {
      event.preventDefault(); const form = event.currentTarget; const values = Object.fromEntries(new FormData(form));
      try {
        const result = await api("/auth/login", {method: "POST", body: JSON.stringify({...values, captcha_token: captchaToken(form)})});
        if (result.mfa_required) { pendingChallenge = result.challenge; authPage("mfa"); return; }
        state.csrf = result.csrf_token || ""; sessionStorage.setItem("audit_csrf", state.csrf);
        if (result.mfa_setup_required) notify("Set up MFA to continue.");
        await init();
      } catch (error) { notify(error.message); if (window.turnstile) { const box = $("#captcha-box"); if (box?.dataset.widget) window.turnstile.reset(box.dataset.widget); } }
    };
    if (mode === "mfa") $("#auth-mfa").onsubmit = async event => {
      event.preventDefault(); const code = new FormData(event.currentTarget).get("code");
      try { const result = await api("/auth/mfa/verify", {method: "POST", body: JSON.stringify({challenge: pendingChallenge, code})}); pendingChallenge = ""; state.csrf = result.csrf_token; sessionStorage.setItem("audit_csrf", state.csrf); await init(); }
      catch (error) { notify(error.message); }
    };
    if (mode === "register") {
      $("#auth-register").onsubmit = async event => {
      event.preventDefault(); const form = event.currentTarget; const values = Object.fromEntries(new FormData(form));
      if (values.password !== values.confirm_password) { notify("Passwords do not match."); form.elements.confirm_password.focus(); return; }
      try { await api("/auth/register", {method: "POST", body: JSON.stringify(values)}); authPage("login"); setTimeout(() => notify("Account created. You can sign in now."), 0); }
      catch (error) { notify(error.message); }
      };
    }
    if (mode === "verify") {
      if (options.email) $("#auth-resend input[name=email]").value = options.email;
      disableUnavailableAccountForm($("#auth-resend"));
      $("#auth-verify").onsubmit = async event => { event.preventDefault(); try { await api("/auth/verify-email", {method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(event.currentTarget)))}); authPage("verified"); } catch (error) { notify(error.message); } };
      $("#auth-resend").onsubmit = async event => { event.preventDefault(); const values = Object.fromEntries(new FormData(event.currentTarget)); values.captcha_token = captchaToken(event.currentTarget); try { const result = await api("/auth/resend-verification", {method: "POST", body: JSON.stringify(values)}); notify(result.message); } catch (error) { notify(error.message); } };
    }
    if (mode === "forgot") { disableForgotForm($("#auth-forgot")); $("#auth-forgot").onsubmit = async event => { disableForgotForm(event.currentTarget); event.preventDefault(); const values = Object.fromEntries(new FormData(event.currentTarget)); try { const result = await api("/auth/forgot-password", {method: "POST", body: JSON.stringify(values)}); notify(result.message); } catch (error) { notify(error.message); } }; }
    if (mode === "reset" || mode === "invite") $(mode === "reset" ? "#auth-reset" : "#auth-invite").onsubmit = async event => {
      event.preventDefault(); const data = Object.fromEntries(new FormData(event.currentTarget));
      if (data.password !== data.confirm_password) { notify("Passwords do not match."); event.currentTarget.elements.confirm_password.focus(); return; }
      try { await api(mode === "reset" ? "/auth/reset-password" : "/auth/accept-invite", {method: "POST", body: JSON.stringify(data)}); authPage("login"); setTimeout(() => notify(mode === "reset" ? "Password reset. Sign in with your new password." : "Invitation accepted. Sign in to continue."), 0); }
      catch (error) { notify(error.message); }
    };
    if (mode === "verified") $("#verified-login").onclick = () => authPage("login");
  }

  window.login = () => authPage("login");
  window.init = async function () {
    const params = new URLSearchParams(location.search);
    if (params.has("verify_email")) { const token = params.get("verify_email"); history.replaceState({}, "", location.pathname); try { await api("/auth/verify-email", {method: "POST", body: JSON.stringify({token})}); authPage("verified"); } catch (error) { authPage("verify", {token}); setTimeout(() => { const toast = $("#auth-toast"); if (toast) { toast.textContent = error.message; toast.className = "toast show"; } }, 0); } return; }
    if (params.has("reset_password") || params.has("invite")) { const invite = params.has("invite"); const token = params.get(invite ? "invite" : "reset_password"); history.replaceState({}, "", location.pathname); authPage(invite ? "invite" : "reset", {token}); return; }
    return originalInit();
  };

  window.securitySettingsView = async function () {
    const current = await api("/auth/me"); state.user = current.user;
    const [sessionData, eventData] = await Promise.all([api("/auth/sessions"), api("/auth/security-events")]);
    $("#view").innerHTML = head("ACCOUNT", "Security settings", "Review account protection, sessions, and recent security events.") + `<section class="panel settings-panel"><div class="panel-head"><div><h2>Account security</h2><p>${h(state.user.email)} · ${state.user.email_verification_skipped ? "Email verification not required" : state.user.is_email_verified ? "Email verified" : "Email not verified"} · Last sign-in ${h(state.user.last_login_at || "not recorded")}</p></div><span class="pill ${state.user.mfa_enabled ? "low" : "neutral"}">${state.user.mfa_enabled ? "MFA ENABLED" : "MFA DISABLED"}</span></div><div class="setting-row"><div><b>Authenticator app</b><span>Use a TOTP authenticator and keep recovery codes offline.</span></div><div>${state.user.mfa_enabled ? `<button id="mfa-recovery" class="button">Regenerate recovery codes</button> <button id="mfa-disable" class="button danger-outline">Disable MFA</button>` : `<button id="mfa-enable" class="primary">Enable MFA</button>`}</div></div><div class="setting-row"><div><b>Password</b><span>Change your current password and revoke other sessions.</span></div><button id="change-password" class="button">Change password</button></div></section><section class="panel table-panel"><div class="panel-head"><div><h2>Active sessions</h2><p>Session identifiers are never displayed.</p></div><button id="revoke-others" class="button">Sign out other sessions</button></div><div class="table-scroll"><table><thead><tr><th>DEVICE</th><th>IP</th><th>LAST SEEN</th><th>EXPIRES</th><th></th></tr></thead><tbody>${sessionData.sessions.map(s => `<tr><td>${h(s.user_agent)} ${s.current ? "· This device" : ""}</td><td>${h(s.ip_address)}</td><td>${h(s.last_seen_at)}</td><td>${h(new Date(s.expires_at * 1000).toLocaleString())}</td><td>${s.current ? "Current" : `<button class="text-btn session-revoke" data-id="${s.id}">Revoke</button>`}</td></tr>`).join("") || `<tr><td colspan="5">No active sessions</td></tr>`}</tbody></table></div></section><section class="panel table-panel"><div class="panel-head"><div><h2>Security activity</h2><p>Authentication events for this account.</p></div></div><div class="table-scroll"><table><thead><tr><th>EVENT</th><th>RESULT</th><th>IP</th><th>TIME</th></tr></thead><tbody>${eventData.events.map(e => `<tr><td>${h(e.event)}</td><td>${e.success ? "Success" : "Failed"}</td><td>${h(e.ip_address)}</td><td>${h(e.created_at)}</td></tr>`).join("") || `<tr><td colspan="4">No security activity recorded</td></tr>`}</tbody></table></div></section>`;
    $("#change-password").onclick = () => { modal("Change password", `<form id="change-password-form" class="form-grid"><label class="span2">Current password<input type="password" name="current_password" required></label><label class="span2">New password<input type="password" name="new_password" minlength="6" required></label><label class="span2">Confirm new password<input type="password" name="confirm_password" minlength="6" required></label><div class="modal-actions span2"><button class="button cancel" type="button">Cancel</button><button class="primary">Save password</button></div></form>`); $("#change-password-form").onsubmit = async e => { e.preventDefault(); try { await api("/auth/change-password", {method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(e.currentTarget)))}); closeModal(); toast("Password changed; other sessions were revoked."); } catch (error) { toast(error.message, true); } }; };
    $("#mfa-enable")?.addEventListener("click", async () => { try { const setup = await api("/auth/mfa/setup", {method: "POST", body: "{}"}); modal("Set up authenticator", `<p>Scan the QR code, or add the key manually. The key is shown only during setup.</p>${setup.qr_data_uri ? `<img alt="Authenticator setup QR code" width="220" height="220" src="${setup.qr_data_uri}">` : ""}<p><code>${h(setup.secret)}</code></p><form id="mfa-enable-form"><label>Six-digit code<input name="code" inputmode="numeric" required></label><div class="modal-actions"><button type="button" class="button cancel">Cancel</button><button class="primary">Verify and enable</button></div></form>`); $("#mfa-enable-form").onsubmit = async e => { e.preventDefault(); try { const result = await api("/auth/mfa/enable", {method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(e.currentTarget)))}); closeModal(); modal("Save recovery codes", `<p>Each code works once. Store them somewhere private.</p><pre>${result.recovery_codes.map(h).join("\n")}</pre><div class="modal-actions"><button class="primary cancel">Done</button></div>`); state.user.mfa_enabled = true; } catch (error) { toast(error.message, true); } }; } catch (error) { toast(error.message, true); } });
    $("#mfa-disable")?.addEventListener("click", () => { modal("Disable MFA", `<form id="mfa-disable-form"><label>Current password<input type="password" name="password" required></label><label>Authenticator code<input name="code" required></label><div class="modal-actions"><button type="button" class="button cancel">Cancel</button><button class="primary danger-button">Disable MFA</button></div></form>`); $("#mfa-disable-form").onsubmit = async e => { e.preventDefault(); try { await api("/auth/mfa/disable", {method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(e.currentTarget)))}); closeModal(); toast("MFA disabled."); await securitySettingsView(); } catch (error) { toast(error.message, true); } }; });
    $("#mfa-recovery")?.addEventListener("click", () => { modal("Regenerate recovery codes", `<form id="mfa-recovery-form"><label>Authenticator code<input name="code" required></label><div class="modal-actions"><button type="button" class="button cancel">Cancel</button><button class="primary">Regenerate codes</button></div></form>`); $("#mfa-recovery-form").onsubmit = async e => { e.preventDefault(); try { const result = await api("/auth/mfa/recovery-codes", {method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(e.currentTarget)))}); closeModal(); modal("Save new recovery codes", `<pre>${result.recovery_codes.map(h).join("\n")}</pre><div class="modal-actions"><button class="primary cancel">Done</button></div>`); } catch (error) { toast(error.message, true); } }; });
    $("#revoke-others").onclick = async () => { try { const result = await api("/auth/sessions/revoke-others", {method: "POST", body: "{}"}); toast(`${result.revoked} session(s) revoked`); await securitySettingsView(); } catch (error) { toast(error.message, true); } };
    $$(".session-revoke").forEach(button => button.onclick = async () => { try { await api(`/auth/sessions/revoke/${button.dataset.id}`, {method: "POST", body: "{}"}); await securitySettingsView(); } catch (error) { toast(error.message, true); } });
  };

  async function addUserDialog(invite = false) {
    const orgs = await api("/organizations");
    modal(invite ? "Invite user" : "Add user", `<form id="admin-user-form" class="form-grid"><label>Full name<input name="full_name" maxlength="120" required></label><label>Username<input name="username" minlength="3" maxlength="40" required></label><label class="span2">Email<input type="email" name="email" maxlength="254" required></label>${invite ? "" : `<label class="span2">Temporary password<input type="password" name="password" minlength="6" required><small>Share through an approved secure channel.</small></label>`}<label>Role<select name="role"><option value="user">User</option><option value="auditor">Auditor</option><option value="admin">Admin</option></select></label><label>Organization<select name="organization_id">${orgs.organizations.map(o => `<option value="${o.id}">${h(o.name)}</option>`).join("")}</select></label><label><input type="checkbox" name="is_active" checked> Active</label><label><input type="checkbox" name="is_email_verified" ${invite ? "" : "checked"}> Email verified</label><label><input type="checkbox" name="require_mfa"> Require MFA</label><div class="modal-actions span2"><button type="button" class="button cancel">Cancel</button><button class="primary">${invite ? "Send invitation" : "Create user"}</button></div></form>`);
    $("#admin-user-form").onsubmit = async e => { e.preventDefault(); const form = e.currentTarget; const data = Object.fromEntries(new FormData(form)); for (const key of ["is_active", "is_email_verified", "require_mfa"]) data[key] = form.elements[key].checked; data.organization_id = Number(data.organization_id); try { await api(invite ? "/admin/users/invite" : "/admin/users", {method: "POST", body: JSON.stringify(data)}); closeModal(); toast(invite ? "Invitation sent" : "User created"); await adminUsersView(); } catch (error) { toast(error.message, true); } };
  }
  window.adminUsersView = async function (search = "", active = "") {
    const [result, security] = await Promise.all([api(`/admin/users?q=${encodeURIComponent(search)}&active=${encodeURIComponent(active)}`), api("/admin/security-events")]);
    $("#view").innerHTML = head("ADMINISTRATION", "User management", "Create accounts, control access, and review account security.", `<button id="invite-user" class="button">Invite</button><button id="add-admin-user" class="primary">＋ Add user</button>`) + `<section class="panel table-panel"><form id="user-search" class="filterbar"><input id="user-q" class="searchbox" placeholder="Search name, username, email" value="${h(search)}"><select id="user-active-filter"><option value="">All accounts</option><option value="1" ${active === "1" ? "selected" : ""}>Active</option><option value="0" ${active === "0" ? "selected" : ""}>Inactive</option></select><button class="button">Search</button></form><div class="table-scroll"><table><thead><tr><th>USER</th><th>ROLE</th><th>STATUS</th><th>EMAIL</th><th>MFA</th><th>CREATED</th><th>LAST SIGN-IN</th><th>ACTIONS</th></tr></thead><tbody>${result.users.map(u => `<tr><td><b>${h(u.full_name || u.email)}</b><div class="subtext">@${h(u.username)} · ${h(u.email)}</div></td><td><select class="admin-role" data-id="${u.id}">${["admin", "auditor", "user"].map(r => `<option value="${r}" ${u.role === r ? "selected" : ""}>${r}</option>`).join("")}</select></td><td><button class="text-btn user-active" data-id="${u.id}" data-active="${u.is_active}">${u.is_active ? "Active" : "Inactive"}</button></td><td>${u.email_verification_skipped ? "Not required" : u.is_email_verified ? "Verified" : "Pending"}</td><td>${u.mfa_enabled ? "Enabled" : u.require_mfa ? "Required" : "Off"}</td><td>${h(u.created_at)}</td><td>${h(u.last_login_at || "Never")}</td><td><button class="text-btn edit-user" data-id="${u.id}">Edit</button><button class="text-btn reset-mfa" data-id="${u.id}">Reset MFA</button><button class="text-btn reset-password" data-id="${u.id}">Reset password</button><button class="text-btn delete-user" data-id="${u.id}">Delete</button></td></tr>`).join("") || `<tr><td colspan="8">No users found</td></tr>`}</tbody></table></div></section><section class="panel table-panel"><div class="panel-head"><div><h2>Recent account security events</h2><p>Success/failure, timestamp, IP, and device metadata; no credentials or tokens.</p></div></div><div class="table-scroll"><table><thead><tr><th>ACCOUNT</th><th>EVENT</th><th>RESULT</th><th>IP</th><th>DEVICE</th><th>TIME</th></tr></thead><tbody>${security.events.map(e => `<tr><td>${h(e.email || "Deleted account")}</td><td>${h(e.event)}</td><td>${e.success ? "Success" : "Failed"}</td><td>${h(e.ip_address)}</td><td>${h(e.user_agent)}</td><td>${h(e.created_at)}</td></tr>`).join("")}</tbody></table></div></section>`;
    $("#add-admin-user").onclick = () => addUserDialog(false); $("#invite-user").onclick = () => addUserDialog(true);
    $("#user-search").onsubmit = e => { e.preventDefault(); adminUsersView($("#user-q").value.trim(), $("#user-active-filter").value); };
    $$(".admin-role").forEach(select => select.onchange = async () => { try { await api(`/admin/users/${select.dataset.id}`, {method: "PATCH", body: JSON.stringify({role: select.value})}); toast("Role updated"); } catch (error) { toast(error.message, true); await adminUsersView(search); } });
    $$(".user-active").forEach(button => button.onclick = async () => { try { await api(`/admin/users/${button.dataset.id}`, {method: "PATCH", body: JSON.stringify({is_active: button.dataset.active !== "1"})}); await adminUsersView(search); } catch (error) { toast(error.message, true); } });
    $$(".delete-user").forEach(button => button.onclick = async () => { if (!confirm("Deactivate and anonymize this account? Audit history is retained.")) return; try { await api(`/admin/users/${button.dataset.id}`, {method: "DELETE", body: "{}"}); await adminUsersView(search); } catch (error) { toast(error.message, true); } });
    $$(".reset-mfa").forEach(button => button.onclick = async () => { if (!confirm("Reset this user's MFA and revoke their sessions?")) return; try { await api(`/admin/users/${button.dataset.id}/reset-mfa`, {method: "POST", body: "{}"}); toast("MFA reset; sessions revoked"); await adminUsersView(search); } catch (error) { toast(error.message, true); } });
    $$(".reset-password").forEach(button => button.onclick = () => { const id = button.dataset.id; modal("Set temporary password", `<form id="admin-reset-password"><label>New temporary password<input type="password" name="password" minlength="6" required></label><div class="modal-actions"><button type="button" class="button cancel">Cancel</button><button class="primary">Set password</button></div></form>`); $("#admin-reset-password").onsubmit = async e => { e.preventDefault(); try { await api(`/admin/users/${id}/reset-password`, {method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(e.currentTarget)))}); closeModal(); toast("Password reset; active sessions revoked"); } catch (error) { toast(error.message, true); } }; });
    $$(".edit-user").forEach(button => button.onclick = () => { const u = result.users.find(x => String(x.id) === button.dataset.id); modal("Edit user", `<form id="edit-admin-user" class="form-grid"><input type="hidden" name="id" value="${u.id}"><label>Full name<input name="full_name" value="${h(u.full_name)}" required></label><label>Username<input name="username" value="${h(u.username)}" required></label><label class="span2">Email<input name="email" type="email" value="${h(u.email)}" required></label><label>Role<select name="role">${["admin", "auditor", "user"].map(r => `<option ${u.role === r ? "selected" : ""}>${r}</option>`).join("")}</select></label><label><input type="checkbox" name="is_active" ${u.is_active ? "checked" : ""}> Active</label><label><input type="checkbox" name="is_email_verified" ${u.is_email_verified ? "checked" : ""}> Email verified</label><label><input type="checkbox" name="require_mfa" ${u.require_mfa ? "checked" : ""}> Require MFA</label><div class="modal-actions span2"><button type="button" class="button cancel">Cancel</button><button class="primary">Save changes</button></div></form>`); $("#edit-admin-user").onsubmit = async e => { e.preventDefault(); const form = e.currentTarget; const data = Object.fromEntries(new FormData(form)); for (const key of ["is_active", "is_email_verified", "require_mfa"]) data[key] = form.elements[key].checked; delete data.id; try { await api(`/admin/users/${u.id}`, {method: "PATCH", body: JSON.stringify(data)}); closeModal(); await adminUsersView(search); } catch (error) { toast(error.message, true); } }; });
  };

  window.shell = function () {
    originalShell();
    if (state.user?.role === "admin" && !$("[data-view='Users']")) { const button = document.createElement("button"); button.className = "nav-item" + (state.view === "Users" ? " active" : ""); button.dataset.view = "Users"; button.innerHTML = "<span>♙</span>Users"; button.onclick = () => navigate("Users"); $("nav").appendChild(button); }
  };
  window.render = async function () {
    if (state.view === "Users") return adminUsersView();
    if (state.view === "Security") return securitySettingsView();
    await originalRender();
    if (state.view === "Settings" && !$("#open-security-settings")) {
      const panel = $(".settings-panel"); if (panel) { const row = document.createElement("div"); row.className = "setting-row"; row.innerHTML = `<div><b>Security settings</b><span>Email status, MFA, password, active sessions, and security events.</span></div><button id="open-security-settings" class="button">Open security settings</button>`; panel.appendChild(row); $("#open-security-settings").onclick = () => navigate("Security"); }
    }
  };
})();
