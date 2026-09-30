/* mailcow UI - a small dependency-free single page app on top of /api/v1.
 * Security: every state changing request carries the rotating CSRF token from the session,
 * the session itself lives in an HttpOnly cookie, and the API enforces roles and ACLs. */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const state = { session: null, csrf: null, route: "" };

  // ---------------------------------------------------------------- API ----
  async function api(method, path, body) {
    const headers = { "Accept": "application/json" };
    if (method !== "GET") {
      headers["Content-Type"] = "application/json";
      if (state.csrf) headers["X-CSRF-Token"] = state.csrf;
    }
    const resp = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin" });
    const newToken = resp.headers.get("X-CSRF-Token");
    if (newToken) state.csrf = newToken;
    let data = null;
    try { data = await resp.json(); } catch (e) { data = null; }
    if (data && data.csrf_token) state.csrf = data.csrf_token;
    if (resp.status === 401 && !path.endsWith("/login") && !path.includes("/login/")) {
      state.session = null;
      render();
    }
    return { status: resp.status, data };
  }
  const get = (p) => api("GET", p);
  const post = (p, b) => api("POST", p, b);

  function showMessages(msgs) {
    if (!Array.isArray(msgs)) return;
    for (const m of msgs) alert(m.type, fmtMsg(m.msg));
  }
  function fmtMsg(msg) {
    if (Array.isArray(msg)) return msg.map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))).join(" - ").replace(/_/g, " ");
    if (typeof msg === "object" && msg) return JSON.stringify(msg);
    return String(msg).replace(/_/g, " ");
  }
  function alert(type, text) {
    const box = document.createElement("div");
    box.className = "alert " + (type === "error" ? "danger" : type);
    box.textContent = text;
    $("#alerts").appendChild(box);
    setTimeout(() => box.remove(), type === "success" ? 4000 : 9000);
  }
  async function write(path, body) {
    const r = await post(path, body);
    if (r.data && Array.isArray(r.data)) showMessages(r.data);
    else if (r.data && r.data.msg) alert(r.data.type || "danger", fmtMsg(r.data.msg));
    return r;
  }

  // ------------------------------------------------------------- helpers ---
  function form(fields, values = {}) {
    return fields.map((f) => {
      const v = values[f.name] ?? f.value ?? "";
      if (f.type === "checkbox") return `<label class="check"><input type="checkbox" name="${f.name}" ${v == 1 || v === true ? "checked" : ""}> ${esc(f.label)}</label>`;
      if (f.type === "select") return `<label>${esc(f.label)}<select name="${f.name}">${f.options.map((o) => `<option value="${esc(o[0])}" ${String(o[0]) === String(v) ? "selected" : ""}>${esc(o[1])}</option>`).join("")}</select></label>`;
      if (f.type === "textarea") return `<label>${esc(f.label)}<textarea name="${f.name}" ${f.placeholder ? `placeholder="${esc(f.placeholder)}"` : ""}>${esc(v)}</textarea></label>`;
      return `<label>${esc(f.label)}<input type="${f.type || "text"}" name="${f.name}" value="${esc(v)}" ${f.placeholder ? `placeholder="${esc(f.placeholder)}"` : ""} ${f.required ? "required" : ""} ${f.attrs || ""}></label>`;
    }).join("");
  }
  function values(formEl) {
    const out = {};
    for (const el of formEl.querySelectorAll("input,select,textarea")) {
      if (!el.name) continue;
      if (el.type === "checkbox") out[el.name] = el.checked ? 1 : 0;
      else if (el.type === "number") out[el.name] = el.value === "" ? "" : Number(el.value);
      else out[el.name] = el.value;
    }
    return out;
  }
  function dialog(title, html, onSubmit) {
    const d = $("#dialog");
    d.innerHTML = `<form method="dialog"><h2>${esc(title)}</h2><div class="row">${html}</div><p class="row" style="justify-content:flex-end;margin-top:16px"><button value="cancel">Cancel</button><button class="primary" value="ok">Save</button></p></form>`;
    d.showModal();
    d.querySelector("form").addEventListener("submit", async (ev) => {
      if (ev.submitter && ev.submitter.value === "cancel") return;
      ev.preventDefault();
      const ok = await onSubmit(values(d.querySelector("form")));
      if (ok !== false) { d.close(); render(); }
    }, { once: false });
  }
  const badge = (v) => (v == 1 ? '<span class="badge on">active</span>' : v == 2 ? '<span class="badge">disabled (allow receiving)</span>' : '<span class="badge off">inactive</span>');
  const bytes = (n) => { n = Number(n || 0); const u = ["B", "KiB", "MiB", "GiB", "TiB"]; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${u[i]}`; };
  const mib = (b) => Math.round(Number(b || 0) / 1048576);
  const table = (cols, rows, actions) => `<table><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}${actions ? "<th></th>" : ""}</tr></thead><tbody>${rows.length ? rows.map((r) => `<tr>${r.cells.map((c) => `<td>${c}</td>`).join("")}${actions ? `<td class="actions">${actions(r.obj)}</td>` : ""}</tr>`).join("") : `<tr><td colspan="${cols.length + 1}" class="muted">Nothing here yet.</td></tr>`}</tbody></table>`;
  const has = (acl) => state.session && state.session.role === "admin" || (state.session && String(state.session.acl?.[acl]) === "1");

  // ----------------------------------------------------------------- pages --
  const pages = {};

  pages.login = async () => {
    $("#main").innerHTML = `<div class="card login"><h2>Sign in</h2><form id="loginform">${form([{ name: "username", label: "Username / e-mail", required: true, attrs: 'autocomplete="username" autofocus' }, { name: "password", label: "Password", type: "password", required: true, attrs: 'autocomplete="current-password"' }])}<p><button class="primary" style="width:100%">Login</button></p></form><p class="muted">Webmail: <a href="/SOGo/">SOGo</a></p></div>`;
    $("#loginform").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const r = await post("/api/v1/login", values(ev.target));
      showMessages(r.data?.messages);
      if (r.data?.result === "pending") { state.session = r.data; state.route = "tfa"; render(); }
      else if (r.data?.result) { await loadSession(); go(defaultRoute()); }
    });
  };

  pages.tfa = async () => {
    const methods = state.session.pending_tfa_methods || [];
    $("#main").innerHTML = `<div class="card login"><h2>Second factor</h2><form id="tfaform">${form([
      { name: "id", label: "Authenticator", type: "select", options: methods.map((m) => [m.id, `${m.key_id} (${m.authmech})`]) },
      { name: "token", label: "Code (TOTP / Yubico OTP)", attrs: 'autocomplete="one-time-code" autofocus' },
    ])}<p class="row"><button class="primary">Verify</button><button type="button" id="webauthn">Use security key</button></p></form></div>`;
    $("#tfaform").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const v = values(ev.target);
      const m = methods.find((x) => String(x.id) === String(v.id));
      const r = await post("/api/v1/login/tfa", { tfa_method: m ? m.authmech : "totp", id: v.id, token: v.token });
      showMessages(r.data?.messages);
      if (r.data?.result) { await loadSession(); go(defaultRoute()); }
    });
    $("#webauthn").addEventListener("click", async () => {
      const opts = (await get("/api/v1/get/webauthn-tfa-get-args")).data;
      if (!opts || !opts.challenge) return alert("danger", "No WebAuthn credentials registered");
      try {
        const cred = await navigator.credentials.get({ publicKey: decodeOptions(opts) });
        const m = methods.find((x) => x.authmech === "webauthn");
        const r = await post("/api/v1/login/tfa", { tfa_method: "webauthn", id: m?.id, token: encodeCredential(cred) });
        showMessages(r.data?.messages);
        if (r.data?.result) { await loadSession(); go(defaultRoute()); }
      } catch (e) { alert("danger", "WebAuthn: " + e.message); }
    });
  };

  pages.domains = async () => {
    const domains = (await get("/api/v1/get/domain/all")).data;
    const rows = (Array.isArray(domains) ? domains : []).map((d) => ({ obj: d, cells: [`<b>${esc(d.domain_h_name)}</b><br><span class="muted">${esc(d.description)}</span>`, `${d.mboxes_in_domain} / ${d.max_num_mboxes_for_domain}`, `${d.aliases_in_domain} / ${d.max_num_aliases_for_domain}`, `${bytes(d.bytes_total)} of ${mib(d.max_quota_for_domain)} MiB`, badge(d.active)] }));
    $("#main").innerHTML = `<div class="card"><h2>Domains</h2><p class="row">${state.session.role === "admin" ? '<button class="primary" id="add">Add domain</button>' : ""}</p>${table(["Domain", "Mailboxes", "Aliases", "Storage", "Status"], rows, (d) => `<button class="small" data-edit="${esc(d.domain_name)}">Edit</button> <button class="small" data-dkim="${esc(d.domain_name)}">DKIM</button> ${state.session.role === "admin" ? `<button class="small danger" data-del="${esc(d.domain_name)}">Delete</button>` : ""}`)}</div>
    <div class="card"><h2>Alias domains</h2><p class="row">${has("alias_domains") ? '<button class="primary" id="addad">Add alias domain</button>' : ""}</p><div id="aliasdomains"></div></div>`;
    const ads = (await get("/api/v1/get/alias-domain/all")).data;
    $("#aliasdomains").innerHTML = table(["Alias domain", "Target", "Status"], (Array.isArray(ads) ? ads : []).map((a) => ({ obj: a, cells: [esc(a.alias_domain), esc(a.target_domain), badge(a.active)] })), (a) => `<button class="small" data-editad="${esc(a.alias_domain)}">Edit</button> <button class="small danger" data-delad="${esc(a.alias_domain)}">Delete</button>`);
    const domainFields = (v = {}) => form([
      { name: "domain", label: "Domain", required: !v.domain_name, attrs: v.domain_name ? "readonly" : "" },
      { name: "description", label: "Description" },
      { name: "mailboxes", label: "Max. mailboxes", type: "number", value: 10 },
      { name: "aliases", label: "Max. aliases", type: "number", value: 400 },
      { name: "defquota", label: "Default mailbox quota (MiB)", type: "number", value: 3072 },
      { name: "maxquota", label: "Max. mailbox quota (MiB)", type: "number", value: 10240 },
      { name: "quota", label: "Domain quota (MiB)", type: "number", value: 10240 },
      { name: "rl_value", label: "Rate limit (messages)", type: "number" },
      { name: "rl_frame", label: "per", type: "select", options: [["s", "second"], ["m", "minute"], ["h", "hour"], ["d", "day"]], value: "h" },
      { name: "backupmx", label: "Relay this domain (backup MX)", type: "checkbox" },
      { name: "relay_all_recipients", label: "Relay all recipients", type: "checkbox" },
      { name: "relay_unknown_only", label: "Relay unknown recipients only", type: "checkbox" },
      { name: "gal", label: "Global address list", type: "checkbox", value: 1 },
      { name: "active", label: "Active", type: "checkbox", value: 1 },
    ], v.domain_name ? { domain: v.domain_name, description: v.description, mailboxes: v.max_num_mboxes_for_domain, aliases: v.max_num_aliases_for_domain, defquota: mib(v.def_quota_for_mbox), maxquota: mib(v.max_quota_for_mbox), quota: mib(v.max_quota_for_domain), rl_value: v.rl?.value || "", rl_frame: v.rl?.frame || "h", backupmx: v.backupmx, relay_all_recipients: v.relay_all_recipients, relay_unknown_only: v.relay_unknown_only, gal: v.gal, active: v.active } : {});
    $("#add")?.addEventListener("click", () => dialog("Add domain", domainFields(), async (v) => { const r = await write("/api/v1/add/domain", v); return r.status === 200; }));
    $("#addad")?.addEventListener("click", () => dialog("Add alias domain", form([{ name: "alias_domain", label: "Alias domain", required: true }, { name: "target_domain", label: "Target domain", type: "select", options: rows.map((r) => [r.obj.domain_name, r.obj.domain_name]) }, { name: "active", label: "Active", type: "checkbox", value: 1 }]), async (v) => (await write("/api/v1/add/alias-domain", v)).status === 200));
    $("#main").addEventListener("click", async (ev) => {
      const b = ev.target.closest("button"); if (!b) return;
      if (b.dataset.edit) { const d = rows.find((r) => r.obj.domain_name === b.dataset.edit).obj; dialog("Edit " + d.domain_name, domainFields(d), async (v) => { delete v.domain; const r = await write("/api/v1/edit/domain", { items: [d.domain_name], attr: v }); if (v.rl_value) await write("/api/v1/edit/rl-domain", { items: [d.domain_name], attr: { rl_value: v.rl_value, rl_frame: v.rl_frame } }); return r.status === 200; }); }
      if (b.dataset.del && confirm(`Delete domain ${b.dataset.del}? Mailboxes must be removed first.`)) { await write("/api/v1/delete/domain", [b.dataset.del]); render(); }
      if (b.dataset.dkim) { const dk = (await get("/api/v1/get/dkim/" + b.dataset.dkim)).data; dialog("DKIM " + b.dataset.dkim, dk && dk.pubkey ? `<div><p class="muted">Selector <code>${esc(dk.dkim_selector)}</code>, ${esc(dk.length)} bit. Publish this TXT record at <code>${esc(dk.dkim_selector)}._domainkey.${esc(b.dataset.dkim)}</code>:</p><pre>${esc(dk.dkim_txt)}</pre>${state.session.role === "admin" ? '<button type="button" class="danger" id="dkdel">Delete key</button>' : ""}</div>` : `<div><p class="muted">No key yet.</p>${form([{ name: "key_size", label: "Key size", type: "select", options: [[2048, "2048"], [3072, "3072"], [4096, "4096"]] }, { name: "dkim_selector", label: "Selector", value: "dkim" }])}</div>`, async (v) => { if (!dk || !dk.pubkey) return (await write("/api/v1/add/dkim", { ...v, domains: b.dataset.dkim })).status === 200; return true; }); $("#dkdel")?.addEventListener("click", async () => { await write("/api/v1/delete/dkim", [b.dataset.dkim]); $("#dialog").close(); }); }
      if (b.dataset.editad) { const a = (await get("/api/v1/get/alias-domain/" + b.dataset.editad)).data; dialog("Edit " + a.alias_domain, form([{ name: "target_domain", label: "Target domain", value: a.target_domain }, { name: "active", label: "Active", type: "checkbox", value: a.active }]), async (v) => (await write("/api/v1/edit/alias-domain", { items: [a.alias_domain], attr: v })).status === 200); }
      if (b.dataset.delad && confirm(`Delete alias domain ${b.dataset.delad}?`)) { await write("/api/v1/delete/alias-domain", [b.dataset.delad]); render(); }
    });
  };

  pages.mailboxes = async () => {
    const mailboxes = (await get("/api/v1/get/mailbox/all")).data;
    const domains = (await get("/api/v1/get/domain/all")).data;
    const list = Array.isArray(mailboxes) ? mailboxes : [];
    const rows = list.map((m) => ({ obj: m, cells: [`<b>${esc(m.username)}</b><br><span class="muted">${esc(m.name)}</span>`, m.quota ? `${bytes(m.quota_used)} / ${mib(m.quota)} MiB (${m.percent_in_use}%)` : `${bytes(m.quota_used)} (unlimited)`, `${m.messages}`, `${m.last_imap_login ? new Date(m.last_imap_login * 1000).toLocaleString() : "-"}`, badge(m.active)] }));
    $("#main").innerHTML = `<div class="card"><h2>Mailboxes</h2><p class="row"><button class="primary" id="add">Add mailbox</button></p>${table(["Mailbox", "Quota", "Messages", "Last IMAP login", "Status"], rows, (m) => `<button class="small" data-edit="${esc(m.username)}">Edit</button> ${has("login_as") ? `<button class="small" data-loginas="${esc(m.username)}">Login as</button>` : ""} <button class="small danger" data-del="${esc(m.username)}">Delete</button>`)}</div>`;
    const fields = (v = {}) => form([
      ...(v.username ? [] : [{ name: "local_part", label: "Local part", required: true }, { name: "domain", label: "Domain", type: "select", options: (Array.isArray(domains) ? domains : []).map((d) => [d.domain_name, d.domain_name]) }]),
      { name: "name", label: "Full name" },
      { name: "quota", label: "Quota (MiB, 0 = unlimited)", type: "number", value: 3072 },
      { name: "password", label: v.username ? "New password (leave empty to keep)" : "Password", type: "password", attrs: 'autocomplete="new-password"' },
      { name: "password2", label: "Confirm password", type: "password", attrs: 'autocomplete="new-password"' },
      { name: "force_pw_update", label: "Force password change at next login", type: "checkbox" },
      { name: "sogo_access", label: "SOGo access", type: "checkbox", value: 1 },
      { name: "imap_access", label: "IMAP", type: "checkbox", value: 1 }, { name: "pop3_access", label: "POP3", type: "checkbox", value: 1 }, { name: "smtp_access", label: "SMTP", type: "checkbox", value: 1 }, { name: "sieve_access", label: "Sieve", type: "checkbox", value: 1 },
      { name: "tls_enforce_in", label: "Enforce TLS incoming", type: "checkbox" }, { name: "tls_enforce_out", label: "Enforce TLS outgoing", type: "checkbox" },
      { name: "active", label: "Active", type: "checkbox", value: 1 },
    ], v.username ? { name: v.name, quota: mib(v.quota), force_pw_update: v.attributes.force_pw_update, sogo_access: v.attributes.sogo_access, imap_access: v.attributes.imap_access, pop3_access: v.attributes.pop3_access, smtp_access: v.attributes.smtp_access, sieve_access: v.attributes.sieve_access, tls_enforce_in: v.attributes.tls_enforce_in, tls_enforce_out: v.attributes.tls_enforce_out, active: v.active } : {});
    $("#add").addEventListener("click", () => dialog("Add mailbox", fields(), async (v) => (await write("/api/v1/add/mailbox", v)).status === 200));
    $("#main").addEventListener("click", async (ev) => {
      const b = ev.target.closest("button"); if (!b) return;
      if (b.dataset.edit) { const m = list.find((x) => x.username === b.dataset.edit); dialog("Edit " + m.username, fields(m), async (v) => { const tls = { tls_enforce_in: v.tls_enforce_in, tls_enforce_out: v.tls_enforce_out }; delete v.tls_enforce_in; delete v.tls_enforce_out; if (!v.password) { delete v.password; delete v.password2; } const r = await write("/api/v1/edit/mailbox", { items: [m.username], attr: v }); await write("/api/v1/edit/tls-policy", { items: [m.username], attr: tls }); return r.status === 200; }); }
      if (b.dataset.del && confirm(`Delete mailbox ${b.dataset.del} and all its mail?`)) { await write("/api/v1/delete/mailbox", [b.dataset.del]); render(); }
      if (b.dataset.loginas) { const r = await write("/api/v1/login-as", { username: b.dataset.loginas }); if (r.status === 200) { await loadSession(); go("user"); } }
    });
  };

  pages.aliases = async () => {
    const aliases = (await get("/api/v1/get/alias/all")).data;
    const list = Array.isArray(aliases) ? aliases : [];
    $("#main").innerHTML = `<div class="card"><h2>Aliases</h2><p class="row"><button class="primary" id="add">Add alias</button></p>${table(["Alias", "Goes to", "Comment", "Status"], list.map((a) => ({ obj: a, cells: [`<b>${esc(a.address)}</b>${a.is_catch_all ? ' <span class="badge">catch-all</span>' : ""}`, esc(a.goto).replace(/,/g, "<br>"), esc(a.public_comment || ""), badge(a.active)] })), (a) => `<button class="small" data-edit="${a.id}">Edit</button> <button class="small danger" data-del="${a.id}">Delete</button>`)}</div>`;
    const fields = (v = {}) => form([
      { name: "address", label: "Alias address(es) - one per line, @domain for catch-all", type: "textarea" },
      { name: "goto", label: "Target address(es)", type: "textarea" },
      { name: "public_comment", label: "Public comment" }, { name: "private_comment", label: "Private comment" },
      { name: "goto_null", label: "Silently discard", type: "checkbox" }, { name: "goto_spam", label: "Learn as spam", type: "checkbox" }, { name: "goto_ham", label: "Learn as ham", type: "checkbox" },
      { name: "sogo_visible", label: "Visible in SOGo", type: "checkbox", value: 1 }, { name: "active", label: "Active", type: "checkbox", value: 1 },
    ], v);
    $("#add").addEventListener("click", () => dialog("Add alias", fields(), async (v) => (await write("/api/v1/add/alias", v)).status === 200));
    $("#main").addEventListener("click", async (ev) => {
      const b = ev.target.closest("button"); if (!b) return;
      if (b.dataset.edit) { const a = list.find((x) => String(x.id) === b.dataset.edit); dialog("Edit " + a.address, fields(a), async (v) => (await write("/api/v1/edit/alias", { items: [a.id], attr: v })).status === 200); }
      if (b.dataset.del && confirm("Delete alias?")) { await write("/api/v1/delete/alias", [Number(b.dataset.del)]); render(); }
    });
  };

  pages.admins = async () => {
    const admins = (await get("/api/v1/get/admin/all")).data;
    const das = (await get("/api/v1/get/domain-admin/all")).data;
    const domains = (await get("/api/v1/get/domain/all")).data;
    const apiRw = (await get("/api/v1/get/api/rw")).data, apiRo = (await get("/api/v1/get/api/ro")).data;
    const pw = (await get("/api/v1/get/passwordpolicy")).data;
    $("#main").innerHTML = `
      <div class="grid2">
      <div class="card"><h2>Administrators</h2><p><button class="primary" id="addadmin">Add administrator</button></p>${table(["Username", "TFA", "Status"], (Array.isArray(admins) ? admins : []).map((a) => ({ obj: a, cells: [esc(a.username), a.tfa_active ? "on" : "off", badge(a.active)] })), (a) => `<button class="small" data-editadmin="${esc(a.username)}">Edit</button> <button class="small danger" data-deladmin="${esc(a.username)}">Delete</button>`)}</div>
      <div class="card"><h2>Domain administrators</h2><p><button class="primary" id="addda">Add domain admin</button></p>${table(["Username", "Domains", "Status"], (Array.isArray(das) ? das : []).map((a) => ({ obj: a, cells: [esc(a.username), esc((a.selected_domains || []).join(", ")), badge(a.active)] })), (a) => `<button class="small" data-editda="${esc(a.username)}">Edit</button> <button class="small danger" data-delda="${esc(a.username)}">Delete</button>`)}</div>
      </div>
      <div class="grid2">
      <div class="card"><h2>API access</h2>
        <h3>Read/write key</h3><form id="apirw">${form([{ name: "api_key", label: "Key", value: apiRw?.api_key || "(not created)", attrs: "readonly" }, { name: "allow_from", label: "Allowed networks (one per line)", type: "textarea", value: (apiRw?.allow_from || "") }, { name: "skip_ip_check", label: "Skip IP check", type: "checkbox", value: apiRw?.skip_ip_check }, { name: "active", label: "Active", type: "checkbox", value: apiRw?.active }])}<p class="row"><button class="primary">Save</button><button type="button" data-regen="rw">Regenerate key</button></p></form>
        <h3>Read-only key</h3><form id="apiro">${form([{ name: "api_key", label: "Key", value: apiRo?.api_key || "(not created)", attrs: "readonly" }, { name: "allow_from", label: "Allowed networks (one per line)", type: "textarea", value: (apiRo?.allow_from || "") }, { name: "skip_ip_check", label: "Skip IP check", type: "checkbox", value: apiRo?.skip_ip_check }, { name: "active", label: "Active", type: "checkbox", value: apiRo?.active }])}<p class="row"><button class="primary">Save</button><button type="button" data-regen="ro">Regenerate key</button></p></form>
      </div>
      <div class="card"><h2>Password policy</h2><form id="pwpolicy">${form([{ name: "length", label: "Minimum length", type: "number", value: pw?.length }, { name: "chars", label: "Require letters", type: "checkbox", value: pw?.chars }, { name: "numbers", label: "Require numbers", type: "checkbox", value: pw?.numbers }, { name: "special_chars", label: "Require special characters", type: "checkbox", value: pw?.special_chars }, { name: "lowerupper", label: "Require lower and upper case", type: "checkbox", value: pw?.lowerupper }])}<p><button class="primary">Save</button></p></form></div>
      </div>`;
    const domSel = (sel = []) => `<label>Domains<select name="domains" multiple size="6">${(Array.isArray(domains) ? domains : []).map((d) => `<option value="${esc(d.domain_name)}" ${sel.includes(d.domain_name) ? "selected" : ""}>${esc(d.domain_name)}</option>`).join("")}</select></label>`;
    const multi = (formEl, v) => { const s = formEl.querySelector('select[name="domains"]'); if (s) v.domains = [...s.selectedOptions].map((o) => o.value); return v; };
    $("#addadmin").addEventListener("click", () => dialog("Add administrator", form([{ name: "username", label: "Username", required: true }, { name: "password", label: "Password", type: "password" }, { name: "password2", label: "Confirm", type: "password" }, { name: "active", label: "Active", type: "checkbox", value: 1 }]), async (v) => (await write("/api/v1/add/admin", v)).status === 200));
    $("#addda").addEventListener("click", () => dialog("Add domain admin", form([{ name: "username", label: "Username", required: true }, { name: "password", label: "Password", type: "password" }, { name: "password2", label: "Confirm", type: "password" }, { name: "active", label: "Active", type: "checkbox", value: 1 }]) + domSel(), async (v) => (await write("/api/v1/add/domain-admin", multi($("#dialog form"), v))).status === 200));
    for (const [id, access] of [["apirw", "rw"], ["apiro", "ro"]]) $("#" + id).addEventListener("submit", async (ev) => { ev.preventDefault(); const v = values(ev.target); delete v.api_key; await write("/api/v1/edit/api", { attr: { ...v, access } }); render(); });
    $("#pwpolicy").addEventListener("submit", async (ev) => { ev.preventDefault(); await write("/api/v1/edit/passwordpolicy", { attr: values(ev.target) }); });
    $("#main").addEventListener("click", async (ev) => {
      const b = ev.target.closest("button"); if (!b) return;
      if (b.dataset.regen && confirm("Regenerate the API key? Clients using the old key will stop working.")) { await write("/api/v1/edit/api", { attr: { access: b.dataset.regen, regen_key: 1 } }); render(); }
      if (b.dataset.editadmin) dialog("Edit " + b.dataset.editadmin, form([{ name: "username_new", label: "Username", value: b.dataset.editadmin }, { name: "password", label: "New password", type: "password" }, { name: "password2", label: "Confirm", type: "password" }, { name: "active", label: "Active", type: "checkbox", value: admins.find((a) => a.username === b.dataset.editadmin)?.active }, { name: "disable_tfa", label: "Disable TFA for next login", type: "checkbox" }]), async (v) => { if (!v.password) { delete v.password; delete v.password2; } if (!v.disable_tfa) delete v.disable_tfa; return (await write("/api/v1/edit/admin", { items: [b.dataset.editadmin], attr: v })).status === 200; });
      if (b.dataset.deladmin && confirm("Delete administrator?")) { await write("/api/v1/delete/admin", [b.dataset.deladmin]); render(); }
      if (b.dataset.editda) { const a = das.find((x) => x.username === b.dataset.editda); const acl = (await get("/api/v1/get/da-acl/" + a.username)).data || {}; dialog("Edit " + a.username, form([{ name: "username_new", label: "Username", value: a.username }, { name: "password", label: "New password", type: "password" }, { name: "password2", label: "Confirm", type: "password" }, { name: "active", label: "Active", type: "checkbox", value: a.active }, { name: "disable_tfa", label: "Disable TFA for next login", type: "checkbox" }]) + domSel(a.selected_domains) + `<div style="flex-basis:100%"><h3>Permissions</h3>${Object.keys(acl).map((k) => `<label class="check"><input type="checkbox" name="acl_${k}" ${acl[k] == 1 ? "checked" : ""}> ${esc(k.replace(/_/g, " "))}</label>`).join(" ")}</div>`, async (v) => { const da_acl = Object.keys(v).filter((k) => k.startsWith("acl_") && v[k] == 1).map((k) => k.slice(4)); for (const k of Object.keys(v)) if (k.startsWith("acl_")) delete v[k]; if (!v.password) { delete v.password; delete v.password2; } if (!v.disable_tfa) delete v.disable_tfa; multi($("#dialog form"), v); const r = await write("/api/v1/edit/domain-admin", { items: [a.username], attr: v }); await write("/api/v1/edit/da-acl", { items: [v.username_new || a.username], attr: { da_acl } }); return r.status === 200; }); }
      if (b.dataset.delda && confirm("Delete domain administrator?")) { await write("/api/v1/delete/domain-admin", [b.dataset.delda]); render(); }
    });
  };

  pages.security = async () => {
    const f2b = (await get("/api/v1/get/fail2ban")).data || {};
    const q = (await get("/api/v1/get/quarantine_settings")).data || {};
    $("#main").innerHTML = `<div class="grid2">
      <div class="card"><h2>Fail2ban (netfilter)</h2><form id="f2b">${form([{ name: "ban_time", label: "Ban time (s)", type: "number", value: f2b.ban_time }, { name: "max_ban_time", label: "Max. ban time (s)", type: "number", value: f2b.max_ban_time }, { name: "ban_time_increment", label: "Increase ban time with each ban", type: "checkbox", value: f2b.ban_time_increment ? 1 : 0 }, { name: "max_attempts", label: "Max. attempts", type: "number", value: f2b.max_attempts }, { name: "retry_window", label: "Retry window (s)", type: "number", value: f2b.retry_window }, { name: "netban_ipv4", label: "IPv4 netmask", type: "number", value: f2b.netban_ipv4 }, { name: "netban_ipv6", label: "IPv6 netmask", type: "number", value: f2b.netban_ipv6 }, { name: "whitelist", label: "Whitelist (networks/hosts)", type: "textarea", value: f2b.whitelist }, { name: "blacklist", label: "Blacklist (networks)", type: "textarea", value: f2b.blacklist }])}<p><button class="primary">Save</button></p></form>
        <h3>Active bans</h3>${table(["Network", "Banned for", ""], (f2b.active_bans || []).map((b) => ({ obj: b, cells: [esc(b.network), esc(b.banned_until), b.queued_for_unban ? "unban queued" : ""] })), (b) => `<button class="small" data-unban="${esc(b.network)}">Unban</button>`)}
        <h3>Permanent bans</h3><p class="muted">${(f2b.perm_bans || []).map((b) => esc(b.network)).join(", ") || "none"}</p></div>
      <div class="card"><h2>Quarantine</h2><form id="q">${form([{ name: "retention_size", label: "Items per mailbox", type: "number", value: q.retention_size }, { name: "max_size", label: "Max. size (MiB)", type: "number", value: q.max_size }, { name: "max_age", label: "Max. age (days)", type: "number", value: q.max_age }, { name: "max_score", label: "Max. score to keep", type: "number", value: q.max_score, attrs: 'step="0.1"' }, { name: "release_format", label: "Release format", type: "select", options: [["raw", "raw message"], ["attachment", "as attachment"]], value: q.release_format }, { name: "sender", label: "Notification sender", value: q.sender }, { name: "subj", label: "Notification subject", value: q.subj }, { name: "bcc", label: "BCC", value: q.bcc }, { name: "redirect", label: "Redirect notifications to", value: q.redirect }, { name: "exclude_domains", label: "Exclude domains (one per line)", type: "textarea", value: (q.exclude_domains || []).join("\n") }])}<p><button class="primary">Save</button></p></form></div>
      </div>`;
    $("#f2b").addEventListener("submit", async (ev) => { ev.preventDefault(); await write("/api/v1/edit/fail2ban", { attr: values(ev.target) }); render(); });
    $("#q").addEventListener("submit", async (ev) => { ev.preventDefault(); const v = values(ev.target); v.exclude_domains = v.exclude_domains.split(/\s+/).filter(Boolean); await write("/api/v1/edit/quarantine_settings", { attr: v }); });
    $("#main").addEventListener("click", async (ev) => { const b = ev.target.closest("button[data-unban]"); if (b) { await write("/api/v1/edit/fail2ban", { attr: { action: "unban", network: b.dataset.unban } }); render(); } });
  };

  pages.quarantine = async () => {
    const items = (await get("/api/v1/get/quarantine/all")).data;
    const list = Array.isArray(items) ? items : [];
    $("#main").innerHTML = `<div class="card"><h2>Quarantine</h2>${table(["Received", "Recipient", "Sender", "Subject", "Score", "Action"], list.map((q) => ({ obj: q, cells: [esc(String(q.created).slice(0, 19)), esc(q.rcpt), esc(q.sender), q.subject, String(q.score), esc(q.action)] })), (q) => `<button class="small" data-show="${q.id}">Show</button> ${has("quarantine") ? `<button class="small" data-release="${q.id}">Release</button> <button class="small danger" data-del="${q.id}">Delete</button>` : ""}`)}</div>`;
    $("#main").addEventListener("click", async (ev) => {
      const b = ev.target.closest("button"); if (!b) return;
      if (b.dataset.show) { const q = (await get("/api/v1/get/quarantine/" + b.dataset.show)).data; dialog("Quarantined message " + q.qid, `<div style="flex-basis:100%"><p class="muted">From ${esc(q.sender)} to ${esc(q.rcpt)}, score ${q.score}, action ${esc(q.action)}</p><pre>${esc(q.msg || "").slice(0, 20000)}</pre><p class="muted">Symbols: ${esc(JSON.stringify(q.symbols))}</p></div>`, async () => true); }
      if (b.dataset.release && confirm("Release this message to the recipient?")) { await write("/api/v1/edit/qitem", { items: [Number(b.dataset.release)], attr: { action: "release" } }); render(); }
      if (b.dataset.del && confirm("Delete this message?")) { await write("/api/v1/delete/qitem", [Number(b.dataset.del)]); render(); }
    });
  };

  pages.routing = async () => {
    const rh = (await get("/api/v1/get/relayhost/all")).data, tr = (await get("/api/v1/get/transport/all")).data, tls = (await get("/api/v1/get/tls-policy-map/all")).data, bcc = (await get("/api/v1/get/bcc/all")).data, rm = (await get("/api/v1/get/recipient_map/all")).data, fh = (await get("/api/v1/get/fwdhost")).data;
    const L = (x) => (Array.isArray(x) ? x : []);
    $("#main").innerHTML = `<div class="grid2">
      <div class="card"><h2>Sender-dependent relay hosts</h2><p><button class="primary" id="addrh">Add</button></p>${table(["Host", "Username", "Status"], L(rh).map((r) => ({ obj: r, cells: [esc(r.hostname), esc(r.username), badge(r.active)] })), (r) => `<button class="small danger" data-del="relayhost:${r.id}">Delete</button>`)}</div>
      <div class="card"><h2>Transport maps</h2><p><button class="primary" id="addtr">Add</button></p>${table(["Destination", "Next hop", "MX based", "Status"], L(tr).map((r) => ({ obj: r, cells: [esc(r.destination), esc(r.nexthop), r.is_mx_based ? "yes" : "no", badge(r.active)] })), (r) => `<button class="small danger" data-del="transport:${r.id}">Delete</button>`)}</div>
      <div class="card"><h2>Outgoing TLS policy overrides</h2><p><button class="primary" id="addtls">Add</button></p>${table(["Destination", "Policy", "Parameters", "Status"], L(tls).map((r) => ({ obj: r, cells: [esc(r.dest), esc(r.policy), esc(r.parameters), badge(r.active)] })), (r) => `<button class="small danger" data-del="tls-policy-map:${r.id}">Delete</button>`)}</div>
      <div class="card"><h2>BCC maps</h2><p><button class="primary" id="addbcc">Add</button></p>${table(["Local", "BCC", "Type", "Status"], L(bcc).map((r) => ({ obj: r, cells: [esc(r.local_dest), esc(r.bcc_dest), esc(r.type), badge(r.active)] })), (r) => `<button class="small danger" data-del="bcc:${r.id}">Delete</button>`)}</div>
      <div class="card"><h2>Recipient maps</h2><p><button class="primary" id="addrm">Add</button></p>${table(["Original", "New", "Status"], L(rm).map((r) => ({ obj: r, cells: [esc(r.old_dest), esc(r.new_dest), badge(r.active)] })), (r) => `<button class="small danger" data-del="recipient_map:${r.id}">Delete</button>`)}</div>
      <div class="card"><h2>Forwarding hosts</h2><p><button class="primary" id="addfh">Add</button></p>${table(["Host", "Source", "Keep spam"], L(fh).map((r) => ({ obj: r, cells: [esc(r.host), esc(r.source), esc(r.keep_spam)] })), (r) => `<button class="small danger" data-del="fwdhost:${esc(r.host)}">Delete</button>`)}</div>
      </div>`;
    $("#addrh").addEventListener("click", () => dialog("Add relay host", form([{ name: "hostname", label: "Host[:port]", required: true }, { name: "username", label: "Username" }, { name: "password", label: "Password", type: "password" }, { name: "active", label: "Active", type: "checkbox", value: 1 }]), async (v) => (await write("/api/v1/add/relayhost", v)).status === 200));
    $("#addtr").addEventListener("click", () => dialog("Add transport", form([{ name: "destination", label: "Destination", required: true }, { name: "nexthop", label: "Next hop", required: true }, { name: "username", label: "Username" }, { name: "password", label: "Password", type: "password" }, { name: "is_mx_based", label: "MX based", type: "checkbox" }, { name: "active", label: "Active", type: "checkbox", value: 1 }]), async (v) => (await write("/api/v1/add/transport", v)).status === 200));
    $("#addtls").addEventListener("click", () => dialog("Add TLS policy", form([{ name: "dest", label: "Destination", required: true }, { name: "policy", label: "Policy", type: "select", options: ["none", "may", "encrypt", "dane", "dane-only", "fingerprint", "verify", "secure"].map((p) => [p, p]) }, { name: "parameters", label: "Parameters" }, { name: "active", label: "Active", type: "checkbox", value: 1 }]), async (v) => (await write("/api/v1/add/tls-policy-map", v)).status === 200));
    $("#addbcc").addEventListener("click", () => dialog("Add BCC map", form([{ name: "local_dest", label: "Local destination (address or domain)", required: true }, { name: "bcc_dest", label: "BCC destination", required: true }, { name: "type", label: "Type", type: "select", options: [["sender", "sender"], ["rcpt", "recipient"]] }, { name: "active", label: "Active", type: "checkbox", value: 1 }]), async (v) => (await write("/api/v1/add/bcc", v)).status === 200));
    $("#addrm").addEventListener("click", () => dialog("Add recipient map", form([{ name: "recipient_map_old", label: "Original recipient", required: true }, { name: "recipient_map_new", label: "New recipient", required: true }, { name: "active", label: "Active", type: "checkbox", value: 1 }]), async (v) => (await write("/api/v1/add/recipient_map", v)).status === 200));
    $("#addfh").addEventListener("click", () => dialog("Add forwarding host", form([{ name: "hostname", label: "Host or network", required: true }, { name: "filter_spam", label: "Filter spam", type: "checkbox", value: 1 }]), async (v) => (await write("/api/v1/add/fwdhost", v)).status === 200));
    $("#main").addEventListener("click", async (ev) => { const b = ev.target.closest("button[data-del]"); if (b && confirm("Delete?")) { const [cat, id] = b.dataset.del.split(":"); await write("/api/v1/delete/" + cat, [/^\d+$/.test(id) ? Number(id) : id]); render(); } });
  };

  pages.logs = async () => {
    const which = state.route.split("/")[1] || "ui";
    const logs = (await get(`/api/v1/get/logs/${which}/200`)).data;
    const kinds = ["ui", "sasl", "postfix", "dovecot", "sogo", "rspamd-history", "netfilter", "autodiscover", "acme", "watchdog", "ratelimited", "api"];
    const list = Array.isArray(logs) ? logs : [];
    const cols = list.length ? Object.keys(list[0]).slice(0, 8) : ["message"];
    $("#main").innerHTML = `<div class="card"><h2>Logs</h2><p class="row">${kinds.map((k) => `<a class="btn" href="#logs/${k}">${k}</a>`).join(" ")}</p>${table(cols, list.map((l) => ({ obj: l, cells: cols.map((c) => `<span class="muted" style="word-break:break-all">${esc(typeof l[c] === "object" ? JSON.stringify(l[c]) : c === "time" ? new Date(l[c] * 1000).toLocaleString() : l[c])}</span>`) })))}</div>`;
  };

  pages.status = async () => {
    const c = (await get("/api/v1/get/status/containers")).data || {};
    const v = (await get("/api/v1/get/status/version")).data || {};
    $("#main").innerHTML = `<div class="card"><h2>Containers</h2><p class="muted">mailcow ${esc(v.MAILCOW_GIT_VERSION || v.version)} (${esc(v.MAILCOW_BRANCH || "")})</p>${table(["Service", "State", "Started", "Image"], Object.values(c).map((x) => ({ obj: x, cells: [esc(x.container), `<span class="badge ${x.state === "running" ? "on" : "off"}">${esc(x.state)}</span>`, esc(String(x.started_at || "").slice(0, 19)), esc(x.image)] })), (x) => `<button class="small" data-restart="${esc(x.container)}">Restart</button>`)}</div>`;
    $("#main").addEventListener("click", async (ev) => { const b = ev.target.closest("button[data-restart]"); if (b && confirm(`Restart ${b.dataset.restart}?`)) { const r = await post(`/api/v1/status/container/${b.dataset.restart}/restart`, {}); alert(r.data?.type || "info", fmtMsg(r.data?.msg || "requested")); } });
  };

  pages.user = async () => {
    const me = state.session.username;
    const mb = (await get("/api/v1/get/mailbox/" + me)).data || {};
    const aliases = (await get("/api/v1/get/user_alias_details/" + me)).data || {};
    const apps = (await get("/api/v1/get/app-passwd/all")).data;
    const tfa = (await get("/api/v1/get/tfa")).data || {};
    const spam = (await get("/api/v1/get/spam-score")).data || {};
    const qn = (await get("/api/v1/get/quarantine_notification")).data || {};
    const qc = (await get("/api/v1/get/quarantine_category")).data || {};
    $("#main").innerHTML = `<div class="grid2">
      <div class="card"><h2>${esc(me)}</h2><p class="muted">${esc(mb.name || "")}</p><p>Storage: ${bytes(mb.quota_used)} of ${mb.quota ? mib(mb.quota) + " MiB" : "unlimited"} (${mb.messages} messages)</p>
        <p>Aliases: ${esc(Object.keys(aliases.direct_aliases || {}).concat(Object.keys(aliases.shared_aliases || {})).join(", ") || "-")}</p>
        <p>Last logins: IMAP ${mb.last_imap_login ? new Date(mb.last_imap_login * 1000).toLocaleString() : "-"}, SMTP ${mb.last_smtp_login ? new Date(mb.last_smtp_login * 1000).toLocaleString() : "-"}</p>
        ${state.session.skip_sogo ? "" : `<p><a class="btn" href="/sogo-auth?login=${encodeURIComponent(me)}">Open webmail (SOGo)</a></p>`}
        <h3>Change password</h3><form id="pw">${form([{ name: "user_old_pass", label: "Current password", type: "password", attrs: 'autocomplete="current-password"' }, { name: "user_new_pass", label: "New password", type: "password", attrs: 'autocomplete="new-password"' }, { name: "user_new_pass2", label: "Confirm", type: "password", attrs: 'autocomplete="new-password"' }])}<p><button class="primary">Change</button></p></form></div>
      <div class="card"><h2>Two-factor authentication</h2>${table(["Name", "Method"], (tfa.additional || []).map((t) => ({ obj: t, cells: [esc(t.key_id), esc(t.authmech)] })), (t) => `<button class="small danger" data-deltfa="${t.id}">Remove</button>`)}<p class="row"><button id="addtotp">Add TOTP app</button><button id="addwebauthn">Add security key</button><button id="addyubi">Add Yubico OTP</button></p></div>
      <div class="card"><h2>App passwords</h2><p class="muted">Use app passwords for mail clients instead of your main password. Each one is limited to the selected protocols.</p>${table(["Name", "Protocols", "Status"], [], null)}<div id="apps"></div>${has("app_passwds") ? '<p><button class="primary" id="addapp">Add app password</button></p>' : ""}</div>
      <div class="card"><h2>Spam filter</h2><form id="spam">${form([{ name: "spam_score", label: "Spam score (add header, reject) - 'default' to reset", value: spam.spam_score }, { name: "quarantine_notification", label: "Quarantine notifications", type: "select", options: [["never", "never"], ["hourly", "hourly"], ["daily", "daily"], ["weekly", "weekly"]], value: qn.quarantine_notification }, { name: "quarantine_category", label: "Notify about", type: "select", options: [["reject", "rejected mail"], ["add_header", "junk mail"], ["all", "both"]], value: qc.quarantine_category }])}<p><button class="primary">Save</button></p></form></div>
      </div>`;
    const appRows = await Promise.all((Array.isArray(apps) ? apps : []).map(async (a) => a && a.id ? a : null));
    $("#apps").innerHTML = table(["Name", "Protocols", "Status"], appRows.filter(Boolean).map((a) => ({ obj: a, cells: [esc(a.name), ["imap", "smtp", "pop3", "sieve", "dav", "eas"].filter((p) => a[p + "_access"] == 1).join(", "), badge(a.active)] })), (a) => `<button class="small danger" data-delapp="${a.id}">Delete</button>`);
    $("#pw").addEventListener("submit", async (ev) => { ev.preventDefault(); await write("/api/v1/edit/user", { attr: values(ev.target) }); ev.target.reset(); });
    $("#spam").addEventListener("submit", async (ev) => { ev.preventDefault(); const v = values(ev.target); await write("/api/v1/edit/spam-score", { items: [me], attr: { spam_score: v.spam_score } }); await write("/api/v1/edit/quarantine_notification", { items: [me], attr: { quarantine_notification: v.quarantine_notification } }); await write("/api/v1/edit/quarantine_category", { items: [me], attr: { quarantine_category: v.quarantine_category } }); });
    $("#addapp")?.addEventListener("click", () => dialog("Add app password", form([{ name: "app_name", label: "Name", required: true }, { name: "app_passwd", label: "Password", type: "password" }, { name: "app_passwd2", label: "Confirm", type: "password" }, ...["imap", "smtp", "pop3", "sieve", "dav", "eas"].map((p) => ({ name: "protocols_" + p, label: p.toUpperCase(), type: "checkbox", value: p === "imap" || p === "smtp" ? 1 : 0 })), { name: "active", label: "Active", type: "checkbox", value: 1 }]), async (v) => { v.protocols = ["imap", "smtp", "pop3", "sieve", "dav", "eas"].filter((p) => v["protocols_" + p] == 1).map((p) => p + "_access"); return (await write("/api/v1/add/app-passwd", v)).status === 200; }));
    $("#addtotp").addEventListener("click", async () => { const s = (await get("/api/v1/get/totp-secret")).data; dialog("Add TOTP authenticator", `<div style="flex-basis:100%"><p>Secret: <code>${esc(s.secret)}</code></p><p class="muted">Add it to your authenticator app (or scan a QR code generated from the URI below), then enter the current code.</p><pre>${esc(s.uri)}</pre></div>` + form([{ name: "key_id", label: "Name", value: "Authenticator" }, { name: "totp_confirm_token", label: "Current code", required: true }, { name: "confirm_password", label: "Your password", type: "password", required: true }]), async (v) => (await write("/api/v1/add/tfa", { tfa_method: "totp", totp_secret: s.secret, ...v })).status === 200); });
    $("#addyubi").addEventListener("click", () => dialog("Add Yubico OTP", form([{ name: "key_id", label: "Name", value: "YubiKey" }, { name: "yubico_id", label: "Yubico API client id", required: true }, { name: "yubico_key", label: "Yubico API secret key", required: true }, { name: "otp_token", label: "Touch the key (OTP)", required: true }, { name: "confirm_password", label: "Your password", type: "password", required: true }]), async (v) => (await write("/api/v1/add/tfa", { tfa_method: "yubi_otp", ...v })).status === 200));
    $("#addwebauthn").addEventListener("click", async () => {
      dialog("Add security key", form([{ name: "key_id", label: "Name", value: "Security key" }, { name: "confirm_password", label: "Your password", type: "password", required: true }]), async (v) => {
        const opts = (await get("/api/v1/get/webauthn-tfa-registration")).data;
        try {
          const cred = await navigator.credentials.create({ publicKey: decodeOptions(opts) });
          return (await write("/api/v1/add/tfa", { tfa_method: "webauthn", registration: encodeCredential(cred), ...v })).status === 200;
        } catch (e) { alert("danger", "WebAuthn: " + e.message); return false; }
      });
    });
    $("#main").addEventListener("click", async (ev) => {
      const b = ev.target.closest("button"); if (!b) return;
      if (b.dataset.delapp && confirm("Delete app password?")) { await write("/api/v1/delete/app-passwd", [Number(b.dataset.delapp)]); render(); }
      if (b.dataset.deltfa && confirm("Remove this authenticator?")) { await write("/api/v1/delete/tfa", [Number(b.dataset.deltfa)]); render(); }
    });
  };

  pages.qhandler = async () => {
    const [, action, hash] = state.route.split("/");
    const r = await get(`/qhandler/${action}/${hash}`);
    if (r.status !== 200) { $("#main").innerHTML = '<div class="card"><h2>Not found</h2><p class="muted">This quarantine link is invalid or the item was already handled.</p></div>'; return; }
    const it = r.data.item;
    $("#main").innerHTML = `<div class="card"><h2>Quarantined message</h2><p>From <b>${esc(it.sender)}</b> to <b>${esc(it.rcpt)}</b><br>Subject: ${it.subject}<br>Score: ${it.score}, action: ${esc(it.action)}, received ${esc(String(it.created).slice(0, 19))}</p>${action !== "show" ? `<p><button class="primary" id="do">${action === "release" ? "Release to my inbox" : "Delete permanently"}</button></p>` : ""}</div>`;
    $("#do")?.addEventListener("click", async () => { const rr = await post(`/qhandler/${action}/${hash}`, {}); showMessages(rr.data?.messages); if (rr.status === 200) $("#main").innerHTML = '<div class="card"><h2>Done</h2></div>'; });
  };

  // --------------------------------------------------------- WebAuthn utils --
  const b64u = { dec: (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=")), (c) => c.charCodeAt(0)), enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") };
  function decodeOptions(o) {
    const out = { ...o, challenge: b64u.dec(o.challenge) };
    if (o.user) out.user = { ...o.user, id: b64u.dec(o.user.id) };
    for (const k of ["excludeCredentials", "allowCredentials"]) if (o[k]) out[k] = o[k].map((c) => ({ ...c, id: b64u.dec(c.id) }));
    return out;
  }
  function encodeCredential(c) {
    const r = c.response;
    const resp = { clientDataJSON: b64u.enc(r.clientDataJSON) };
    if (r.attestationObject) resp.attestationObject = b64u.enc(r.attestationObject);
    if (r.authenticatorData) resp.authenticatorData = b64u.enc(r.authenticatorData);
    if (r.signature) resp.signature = b64u.enc(r.signature);
    if (r.userHandle) resp.userHandle = b64u.enc(r.userHandle);
    return { id: c.id, rawId: b64u.enc(c.rawId), type: c.type, response: resp, clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {} };
  }

  // -------------------------------------------------------------- routing ---
  const NAV = {
    admin: [["domains", "Domains"], ["mailboxes", "Mailboxes"], ["aliases", "Aliases"], ["admins", "Access"], ["security", "Security"], ["routing", "Routing"], ["quarantine", "Quarantine"], ["logs", "Logs"], ["status", "Status"]],
    domainadmin: [["domains", "Domains"], ["mailboxes", "Mailboxes"], ["aliases", "Aliases"], ["quarantine", "Quarantine"]],
    user: [["user", "My account"], ["quarantine", "Quarantine"]],
  };
  function defaultRoute() { return state.session?.role === "user" ? "user" : "domains"; }
  function go(route) { location.hash = "#" + route; }
  async function loadSession() {
    const r = await get("/api/v1/session");
    state.session = r.data;
    state.csrf = r.data?.csrf_token || state.csrf;
  }
  async function render() {
    state.route = location.hash.replace(/^#/, "") || "";
    const role = state.session?.role;
    const items = role ? NAV[role] || [] : [];
    $("#nav").innerHTML = items.map(([r, t]) => `<a href="#${r}" class="${state.route.split("/")[0] === r ? "active" : ""}">${t}</a>`).join("");
    $("#who").textContent = role ? `${state.session.username} (${role}${state.session.dual_login ? ", via " + state.session.dual_login.username : ""})` : "";
    $("#logout").hidden = !role;
    let page = state.route.split("/")[0];
    if (page === "qhandler") return pages.qhandler();
    if (!role) page = state.session?.pending_tfa ? "tfa" : "login";
    else if (!pages[page] || !items.some(([r]) => r === page)) page = defaultRoute();
    $("#main").innerHTML = '<p class="muted">Loading...</p>';
    try { await pages[page](); } catch (e) { $("#main").innerHTML = `<div class="card"><h2>Error</h2><pre>${esc(e.message)}</pre></div>`; }
  }
  $("#logout").addEventListener("click", async () => { const r = await post("/api/v1/logout", {}); if (r.data?.result === "dual-logout") { await loadSession(); go(defaultRoute()); } else { state.session = null; state.csrf = null; await loadSession(); go(""); render(); } });
  window.addEventListener("hashchange", render);
  loadSession().then(render);
})();
