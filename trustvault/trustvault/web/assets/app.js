/* TrustVault browser client.
 *
 * This UI is a convenience, not a security boundary: every button here calls the same
 * /api/v1 endpoints a script could call, and the server authorises each request.
 * All untrusted text is inserted with textContent (never innerHTML), so document
 * titles, file names and audit details cannot inject markup.
 */
(() => {
  "use strict";

  const state = { me: null, csrf: null, demo: false, checked: false };
  const app = document.getElementById("app");

  // ---------- tiny DOM helper -------------------------------------------------------------
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
      else if (k === "class") el.className = v;
      else if (k === "value") el.value = v;
      else if (v === true) el.setAttribute(k, "");
      else el.setAttribute(k, String(v));
    }
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
  const fmtDate = (s) => (s ? new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "");
  const fmtDay = (s) => (s ? new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" }) : "");
  const fmtSize = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
  const permTag = (p) => h("span", { class: `tag ${p}` }, p);

  function toast(message, kind = "ok") {
    const t = h("div", { class: `notice ${kind} toast`, role: "status" }, message);
    document.body.append(t);
    setTimeout(() => t.remove(), 4200);
  }

  // ---------- API -------------------------------------------------------------------------
  class ApiError extends Error {
    constructor(status, body) {
      super((body && body.error && body.error.message) || `Request failed (${status})`);
      this.status = status;
      this.code = body && body.error && body.error.code;
    }
  }

  async function api(method, path, body, isForm = false) {
    const opts = { method, credentials: "same-origin", headers: { Accept: "application/json" } };
    if (method !== "GET" && state.csrf) opts.headers["X-CSRF-Token"] = state.csrf;
    if (body !== undefined) {
      if (isForm) opts.body = body;
      else { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    }
    const res = await fetch(`/api/v1${path}`, opts);
    let data = null;
    try { data = await res.json(); } catch (_) { /* empty body */ }
    if (res.status === 401 && path !== "/auth/login") {
      state.me = null; state.csrf = null;
      if (location.hash !== "#/login") location.hash = "#/login";
      throw new ApiError(401, data);
    }
    if (res.status === 403 && data && data.error && data.error.code === "password_change_required") {
      location.hash = "#/account";
    }
    if (!res.ok) throw new ApiError(res.status, data);
    return data;
  }

  const qs = (obj) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(obj)) if (v !== "" && v !== null && v !== undefined) p.set(k, v);
    const s = p.toString();
    return s ? `?${s}` : "";
  };

  // ---------- shell -----------------------------------------------------------------------
  function navLink(href, label) {
    const active = location.hash === href || (href !== "#/admin" && location.hash.startsWith(href + "/"));
    return h("a", { href, class: active ? "active" : "" }, label);
  }

  function shell(content) {
    const me = state.me;
    const nav = [h("div", { class: "nav-label" }, "Vault"), navLink("#/documents", "Documents")];
    if (me.role === "owner") nav.push(navLink("#/upload", "Upload"), navLink("#/trash", "Trash"));
    if (me.role === "admin") {
      nav.push(h("div", { class: "nav-label" }, "Administration"),
        navLink("#/admin", "Activity & alerts"), navLink("#/admin/audit", "Audit trail"),
        navLink("#/admin/users", "People"), navLink("#/admin/documents", "All documents"));
    }
    nav.push(h("div", { class: "nav-label" }, "You"), navLink("#/account", "Account"));
    const logout = h("button", {
      class: "btn ghost sm",
      onclick: async () => { try { await api("POST", "/auth/logout"); } catch (_) {} state.me = null; location.hash = "#/login"; },
    }, "Sign out");
    return h("div", { class: "layout" },
      h("aside", { class: "sidebar" },
        h("div", { class: "brand" }, h("span", { class: "brand-mark" }, "TV"), "TrustVault"),
        h("nav", { class: "nav" }, nav),
        h("div", { class: "me" }, h("div", {}, h("strong", {}, me.display_name), `${me.username} · ${me.role}`), logout)),
      h("main", { class: "main" }, content));
  }

  function pageHead(title, subtitle, ...actions) {
    return h("div", { class: "page-head" },
      h("div", {}, h("h1", {}, title), subtitle ? h("p", {}, subtitle) : null),
      h("div", { class: "row" }, actions));
  }

  function errorBox(err) { return h("div", { class: "notice error" }, err.message || String(err)); }

  // ---------- login -----------------------------------------------------------------------
  function loginView() {
    const msg = h("div");
    const user = h("input", { id: "u", autocomplete: "username", required: true, maxlength: 64 });
    const pass = h("input", { id: "p", type: "password", autocomplete: "current-password", required: true, maxlength: 128 });
    const btn = h("button", { class: "btn primary", type: "submit" }, "Sign in");
    const form = h("form", {
      class: "form-stack",
      onsubmit: async (e) => {
        e.preventDefault(); btn.disabled = true; clear(msg);
        try {
          const me = await api("POST", "/auth/login", { username: user.value, password: pass.value });
          setMe(me);
          location.hash = me.user.must_change_password ? "#/account" : (me.user.role === "admin" ? "#/admin" : "#/documents");
        } catch (err) { msg.append(errorBox(err)); pass.value = ""; }
        finally { btn.disabled = false; }
      },
    }, h("div", { class: "field" }, h("label", { for: "u" }, "Username"), user),
       h("div", { class: "field" }, h("label", { for: "p" }, "Password"), pass), btn);
    return h("div", { class: "login-wrap" }, h("div", { class: "login-card" },
      h("div", { class: "brand" }, h("span", { class: "brand-mark" }, "TV"), "TrustVault"),
      h("p", {}, "Confidential documents, shared with named people only. Every access is recorded."),
      msg, form,
      h("div", { class: "foot-note" }, "Sessions end after 30 minutes of inactivity.")));
  }

  function setMe(payload) {
    state.me = payload.user; state.csrf = payload.csrf_token; state.demo = payload.demo_mode;
  }

  // ---------- documents list --------------------------------------------------------------
  async function documentsView(params) {
    const [list, cats] = await Promise.all([api("GET", `/documents${qs(params)}`), api("GET", "/categories")]);
    const f = {
      q: h("input", { id: "f-q", value: params.q || "", placeholder: "Title or file name", maxlength: 100 }),
      owner: h("input", { id: "f-owner", value: params.owner || "", placeholder: "Owner", maxlength: 64 }),
      category: h("select", { id: "f-cat" }, h("option", { value: "" }, "Any category"),
        cats.items.map((c) => h("option", { value: c, selected: c === params.category }, c))),
      from: h("input", { id: "f-from", type: "date", value: params.from || "" }),
      to: h("input", { id: "f-to", type: "date", value: params.to || "" }),
    };
    const go = (e) => {
      e.preventDefault();
      location.hash = `#/documents${qs({ q: f.q.value.trim(), owner: f.owner.value.trim(), category: f.category.value, from: f.from.value, to: f.to.value })}`;
    };
    const filters = h("form", { class: "card form-grid", onsubmit: go },
      h("div", { class: "field" }, h("label", { for: "f-q" }, "Name"), f.q),
      h("div", { class: "field" }, h("label", { for: "f-owner" }, "Owner"), f.owner),
      h("div", { class: "field" }, h("label", { for: "f-cat" }, "Category"), f.category),
      h("div", { class: "field" }, h("label", { for: "f-from" }, "Uploaded from"), f.from),
      h("div", { class: "field" }, h("label", { for: "f-to" }, "Uploaded to"), f.to),
      h("div", { class: "row" }, h("button", { class: "btn primary", type: "submit" }, "Search"),
        h("a", { class: "btn", href: "#/documents" }, "Reset")));

    const rows = list.items.map((d) => h("tr", {},
      h("td", { class: "wrap" }, h("a", { href: `#/documents/${d.id}` }, d.title),
        d.latest_version ? h("div", { class: "muted small" }, `${d.latest_version.filename} · ${fmtSize(d.latest_version.size_bytes)} · v${d.latest_version.version}`) : null),
      h("td", {}, d.category),
      h("td", {}, d.owner.display_name, h("div", { class: "muted small" }, d.owner.username)),
      h("td", {}, permTag(d.my_permission)),
      h("td", { class: "small" }, fmtDay(d.created_at))));
    const table = list.items.length
      ? h("div", { class: "table-wrap" }, h("table", {},
          h("thead", {}, h("tr", {}, ["Document", "Category", "Owner", "Your access", "Uploaded"].map((t) => h("th", {}, t)))),
          h("tbody", {}, rows)))
      : h("div", { class: "empty" }, Object.keys(params).length ? "No documents match these filters." : "Nothing has been shared with you yet.");
    const subtitle = state.me.role === "admin"
      ? "Administrators see only documents an owner has explicitly shared with them."
      : `${list.total} document(s) you own or were granted.`;
    return [pageHead("Documents", subtitle, state.me.role === "owner" ? h("a", { class: "btn primary", href: "#/upload" }, "Upload document") : null),
      filters, h("div", { class: "card" }, table)];
  }

  // ---------- upload ----------------------------------------------------------------------
  async function uploadView() {
    const cats = await api("GET", "/categories");
    const msg = h("div");
    const title = h("input", { id: "t", required: true, maxlength: 160 });
    const category = h("input", { id: "c", required: true, maxlength: 60, list: "cat-list" });
    const file = h("input", { id: "file", type: "file", required: true, accept: ".pdf,.png,.jpg,.jpeg,.docx,.xlsx,.pptx,.txt,.csv" });
    const btn = h("button", { class: "btn primary", type: "submit" }, "Encrypt and upload");
    const form = h("form", {
      class: "form-stack",
      onsubmit: async (e) => {
        e.preventDefault(); clear(msg); btn.disabled = true;
        const fd = new FormData();
        fd.append("title", title.value); fd.append("category", category.value); fd.append("file", file.files[0]);
        try {
          const doc = await api("POST", "/documents", fd, true);
          toast("Uploaded. Only you can see it until you grant access.");
          location.hash = `#/documents/${doc.id}`;
        } catch (err) { msg.append(errorBox(err)); } finally { btn.disabled = false; }
      },
    },
    h("div", { class: "field" }, h("label", { for: "t" }, "Title"), title),
    h("div", { class: "field" }, h("label", { for: "c" }, "Category"), category,
      h("datalist", { id: "cat-list" }, cats.items.map((c) => h("option", { value: c })))),
    h("div", { class: "field" }, h("label", { for: "file" }, "File"), file,
      h("span", { class: "muted small" }, "PDF, Word, Excel, PowerPoint, PNG, JPEG, TXT or CSV. Up to 10 MB. Checked by content, not by name. Macro-enabled files and PDFs with scripts are refused.")),
    btn);
    return [pageHead("Upload a document", "New documents are private to you until you grant access to named people."),
      h("div", { class: "card" }, msg, form)];
  }

  // ---------- document detail -------------------------------------------------------------
  async function documentView(id) {
    const doc = await api("GET", `/documents/${encodeURIComponent(id)}`);
    const perm = doc.my_permission;
    const canEdit = perm === "edit" || perm === "owner";
    const isOwner = perm === "owner";
    const dl = (v) => `/api/v1/documents/${encodeURIComponent(doc.id)}/download${v ? `?version=${v}` : ""}`;

    const head = pageHead(doc.title, `${doc.category} · owned by ${doc.owner.display_name}`,
      permTag(perm),
      doc.latest_version ? h("a", { class: "btn primary", href: dl(), download: "" }, "Download latest") : null);

    const details = h("div", { class: "card" }, h("h2", {}, "Details"),
      h("dl", { class: "kv" },
        h("dt", {}, "Owner"), h("dd", {}, `${doc.owner.display_name} (${doc.owner.username})`),
        h("dt", {}, "Category"), h("dd", {}, doc.category),
        h("dt", {}, "Created"), h("dd", {}, fmtDate(doc.created_at)),
        h("dt", {}, "Last change"), h("dd", {}, fmtDate(doc.updated_at)),
        h("dt", {}, "Your access"), h("dd", {}, permTag(perm)),
        h("dt", {}, "SHA-256 (latest)"), h("dd", { class: "mono" }, doc.latest_version ? doc.latest_version.sha256 : "")));

    const versions = h("div", { class: "card" }, h("h2", {}, "Versions"),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["#", "File", "Size", "Uploaded by", "When", ""].map((t) => h("th", {}, t)))),
        h("tbody", {}, doc.versions.map((v) => h("tr", {},
          h("td", {}, `v${v.version}`), h("td", { class: "wrap" }, v.filename), h("td", {}, fmtSize(v.size_bytes)),
          h("td", {}, v.uploaded_by.username), h("td", { class: "small" }, fmtDate(v.created_at)),
          h("td", {}, h("a", { class: "btn sm", href: dl(v.version), download: "" }, "Download"))))))));

    const left = [details, versions];
    const right = [];

    if (canEdit) {
      const emsg = h("div");
      const t = h("input", { id: "et", value: doc.title, maxlength: 160, required: true });
      const c = h("input", { id: "ec", value: doc.category, maxlength: 60, required: true });
      right.push(h("div", { class: "card" }, h("h2", {}, "Edit details"), emsg,
        h("form", {
          class: "form-stack",
          onsubmit: async (e) => {
            e.preventDefault(); clear(emsg);
            try { await api("PATCH", `/documents/${doc.id}`, { title: t.value, category: c.value }); toast("Saved."); render(); }
            catch (err) { emsg.append(errorBox(err)); }
          },
        }, h("div", { class: "field" }, h("label", { for: "et" }, "Title"), t),
           h("div", { class: "field" }, h("label", { for: "ec" }, "Category"), c),
           h("div", {}, h("button", { class: "btn", type: "submit" }, "Save")))));

      const vmsg = h("div");
      const vf = h("input", { id: "vf", type: "file", required: true });
      right.push(h("div", { class: "card" }, h("h2", {}, "Upload a new version"), vmsg,
        h("form", {
          class: "form-stack",
          onsubmit: async (e) => {
            e.preventDefault(); clear(vmsg);
            const fd = new FormData(); fd.append("file", vf.files[0]);
            try { await api("POST", `/documents/${doc.id}/versions`, fd, true); toast("New version stored."); render(); }
            catch (err) { vmsg.append(errorBox(err)); }
          },
        }, vf, h("div", {}, h("button", { class: "btn", type: "submit" }, "Upload version")))));
    }

    if (isOwner) {
      right.unshift(await accessCard(doc));
      left.push(await activityCard(doc));
      left.push(h("div", { class: "card" }, h("h2", {}, "Delete"),
        h("p", { class: "muted" }, "Moves the document to your trash. Everyone you shared it with loses access immediately. You can restore it from the trash."),
        h("button", {
          class: "btn danger",
          onclick: async () => {
            if (!confirm("Move this document to the trash? All grantees lose access now.")) return;
            try { await api("DELETE", `/documents/${doc.id}`); toast("Moved to trash."); location.hash = "#/trash"; }
            catch (err) { toast(err.message, "error"); }
          },
        }, "Move to trash")));
    }
    return [head, h("div", { class: "grid-2" }, h("div", {}, left), h("div", {}, right))];
  }

  async function accessCard(doc) {
    const [grants, directory] = await Promise.all([
      api("GET", `/documents/${doc.id}/grants`), api("GET", "/users/directory")]);
    const msg = h("div");
    const granted = new Set(grants.items.map((g) => g.user.id));
    const setGrant = async (userId, permission, source = "manual") => {
      try { await api("PUT", `/documents/${doc.id}/grants/${userId}`, { permission, source }); toast("Access updated."); render(); }
      catch (err) { clear(msg).append(errorBox(err)); }
    };
    const list = grants.items.length ? grants.items.map((g) => {
      const sel = h("select", { "aria-label": `Permission for ${g.user.username}`, onchange: () => setGrant(g.user.id, sel.value) },
        h("option", { value: "read", selected: g.permission === "read" }, "Read"),
        h("option", { value: "edit", selected: g.permission === "edit" }, "Edit"));
      return h("div", { class: "list-item" },
        h("div", { class: "who" }, g.user.display_name,
          h("small", {}, `${g.user.username} · granted ${fmtDay(g.created_at)} by ${g.granted_by.username}${g.source === "suggestion" ? " · from suggestion" : ""}`)),
        sel,
        h("button", {
          class: "btn sm danger",
          onclick: async () => {
            try { await api("DELETE", `/documents/${doc.id}/grants/${g.user.id}`); toast(`Access revoked for ${g.user.username}. Effective immediately.`); render(); }
            catch (err) { clear(msg).append(errorBox(err)); }
          },
        }, "Revoke"));
    }) : h("p", { class: "muted" }, "Only you can access this document.");

    const candidates = directory.items.filter((u) => u.id !== doc.owner.id && !granted.has(u.id));
    const who = h("select", { id: "g-user", required: true }, h("option", { value: "" }, "Choose a person…"),
      candidates.map((u) => h("option", { value: u.id }, `${u.display_name} (${u.username}, ${u.role})`)));
    const perm = h("select", { id: "g-perm" }, h("option", { value: "read" }, "Read: view and download"),
      h("option", { value: "edit" }, "Edit: also rename and add versions"));
    const form = h("form", {
      class: "form-stack",
      onsubmit: (e) => { e.preventDefault(); if (who.value) setGrant(who.value, perm.value); },
    }, h("div", { class: "field" }, h("label", { for: "g-user" }, "Person"), who),
       h("div", { class: "field" }, h("label", { for: "g-perm" }, "Permission"), perm),
       h("div", {}, h("button", { class: "btn primary", type: "submit" }, "Grant access")));

    const sugBox = h("div");
    const sugBtn = h("button", {
      class: "btn sm",
      onclick: async () => {
        clear(sugBox);
        try {
          const res = await api("GET", `/documents/${doc.id}/suggestions`);
          if (!res.items.length) { sugBox.append(h("p", { class: "muted small" }, "No suggestions: nobody you share similar documents with is missing access.")); return; }
          sugBox.append(h("p", { class: "muted small" }, res.note), res.items.map((s) => h("div", { class: "list-item" },
            h("div", { class: "who" }, s.user.display_name, h("small", {}, s.reasons.join("; "))),
            h("button", { class: "btn sm primary", onclick: () => setGrant(s.user.id, "read", "suggestion") }, "Grant read"),
            h("button", {
              class: "btn sm",
              onclick: async () => {
                try { await api("POST", `/documents/${doc.id}/suggestions/${s.user.id}/dismiss`); toast("Dismissed (recorded)."); sugBtn.click(); }
                catch (err) { toast(err.message, "error"); }
              },
            }, "Dismiss"))));
        } catch (err) { sugBox.append(errorBox(err)); }
      },
    }, "Suggest people");

    return h("div", { class: "card" }, h("h2", {}, "Who has access"), msg, list,
      h("div", { class: "section" }, form),
      h("div", { class: "row section" }, h("h3", {}, "Suggestions"), h("span", { class: "spacer" }), sugBtn),
      h("p", { class: "muted small" }, "Suggestions are advisory and never grant access on their own. Your decision and the suggestion are both recorded."),
      sugBox);
  }

  function eventsTable(items, { showDoc = false } = {}) {
    if (!items.length) return h("div", { class: "empty" }, "No events.");
    return h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["#", "When", "Who", "Action", "Result", showDoc ? "Document" : null, "Details"].filter(Boolean).map((t) => h("th", {}, t)))),
      h("tbody", {}, items.map((e) => h("tr", {},
        h("td", { class: "mono" }, e.seq),
        h("td", { class: "small" }, fmtDate(e.at)),
        h("td", {}, e.actor.username, e.actor.role ? h("div", { class: "muted small" }, e.actor.role) : null, e.ip ? h("div", { class: "muted small mono" }, e.ip) : null),
        h("td", { class: "mono" }, e.action),
        h("td", {}, h("span", { class: `tag ${e.outcome}` }, e.outcome)),
        showDoc ? h("td", { class: "mono small wrap" }, e.document_id || "") : null,
        h("td", {}, detailsView(e.details)))))));
  }

  function detailsView(d) {
    const fmt = (v) => {
      if (v === null || v === undefined) return "none";
      if (typeof v === "object") return JSON.stringify(v);
      const s = String(v);
      return s.length > 40 ? `${s.slice(0, 16)}…${s.slice(-8)}` : s;
    };
    return h("div", { class: "details" }, Object.entries(d || {}).map(([k, v]) =>
      h("div", {}, h("span", { class: "muted" }, `${k}: `), fmt(v))));
  }

  async function activityCard(doc) {
    const res = await api("GET", `/documents/${doc.id}/activity`);
    return h("div", { class: "card" }, h("h2", {}, "Who reached this document"),
      h("p", { class: "muted small" }, "Every view, download, change and refused attempt on this document, newest first."),
      eventsTable(res.items));
  }

  // ---------- trash -----------------------------------------------------------------------
  async function trashView() {
    const res = await api("GET", "/documents/trash");
    const body = res.items.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Document", "Deleted", "Purged automatically", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, res.items.map((d) => h("tr", {},
        h("td", { class: "wrap" }, d.title, h("div", { class: "muted small" }, d.category)),
        h("td", { class: "small" }, fmtDate(d.deleted_at)),
        h("td", { class: "small" }, fmtDay(d.purge_after)),
        h("td", {}, h("div", { class: "row" },
          h("button", { class: "btn sm", onclick: async () => {
            try { await api("POST", `/documents/${d.id}/restore`); toast("Restored. Previous grants are active again."); render(); } catch (err) { toast(err.message, "error"); }
          } }, "Restore"),
          h("button", { class: "btn sm danger", onclick: async () => {
            if (prompt(`Permanently destroy "${d.title}"? Its encryption keys are deleted and it cannot be recovered. Type PURGE to confirm.`) !== "PURGE") return;
            try { await api("DELETE", `/documents/${d.id}/purge`, { confirm: "PURGE" }); toast("Purged."); render(); } catch (err) { toast(err.message, "error"); }
          } }, "Purge now")))))))) : h("div", { class: "empty" }, "Trash is empty.");
    return [pageHead("Trash", "Deleted documents are invisible to everyone else. Restore them, or purge to destroy the keys."), h("div", { class: "card" }, body)];
  }

  // ---------- account ---------------------------------------------------------------------
  function accountView() {
    const msg = h("div");
    const cur = h("input", { id: "cp", type: "password", autocomplete: "current-password", required: true });
    const nw = h("input", { id: "np", type: "password", autocomplete: "new-password", required: true, minlength: 12, maxlength: 128 });
    const form = h("form", {
      class: "form-stack",
      onsubmit: async (e) => {
        e.preventDefault(); clear(msg);
        try {
          await api("POST", "/auth/change-password", { current_password: cur.value, new_password: nw.value });
          state.me.must_change_password = false;
          msg.append(h("div", { class: "notice ok" }, "Password changed. Your other sessions were signed out."));
          cur.value = ""; nw.value = "";
        } catch (err) { msg.append(errorBox(err)); }
      },
    }, h("div", { class: "field" }, h("label", { for: "cp" }, "Current password"), cur),
       h("div", { class: "field" }, h("label", { for: "np" }, "New password"), nw,
         h("span", { class: "muted small" }, "At least 12 characters, mixing three of: lower case, upper case, digits, symbols.")),
       h("div", {}, h("button", { class: "btn primary", type: "submit" }, "Change password")));
    return [pageHead("Account", `${state.me.display_name} · ${state.me.username} · ${state.me.role}`),
      state.me.must_change_password ? h("div", { class: "notice warn" }, "An administrator set a temporary password. Choose your own to continue.") : null,
      h("div", { class: "card" }, h("h2", {}, "Change password"), msg, form)];
  }

  // ---------- admin -----------------------------------------------------------------------
  async function adminOverview() {
    const o = await api("GET", "/admin/overview");
    const stat = (label, value) => h("div", { class: "stat" }, h("div", { class: "label" }, label), h("div", { class: "value" }, value));
    const verifyBox = h("div");
    const verify = h("button", {
      class: "btn primary",
      onclick: async () => {
        clear(verifyBox).append(h("p", { class: "muted" }, "Verifying…"));
        try {
          const r = await api("POST", "/admin/audit/verify");
          clear(verifyBox).append(h("div", { class: `notice ${r.valid ? "ok" : "error"}` },
            r.valid ? `Audit chain intact: ${r.events} events, ${r.checkpoints_checked} checkpoint(s) matched. Head #${r.head_seq} ${r.head_hash.slice(0, 16)}…`
                    : `TAMPERING DETECTED: ${r.problems.join(" | ")}`));
        } catch (err) { clear(verifyBox).append(errorBox(err)); }
      },
    }, "Verify audit chain now");
    const alerts = o.alerts.length ? o.alerts.map((a) => h("div", { class: `alert ${a.severity}` },
      h("div", { class: "row" }, h("span", { class: `tag ${a.severity}` }, a.severity), h("strong", {}, a.message)),
      h("div", { class: "muted small" }, `${a.kind} · last ${fmtDate(a.last_seen)} · events #${a.seqs.join(", #")}`)))
      : h("p", { class: "muted" }, "Nothing unusual in the last 24 hours.");
    return [pageHead("Activity & alerts", "What happened, and what looks worth a second look.", verify),
      verifyBox,
      h("div", { class: "grid-stats" },
        stat("Active people", `${o.totals.active_users}/${o.totals.users}`), stat("Documents", o.totals.documents),
        stat("In trash", o.totals.in_trash), stat("Active grants", o.totals.grants), stat("Audit events", o.totals.audit_events)),
      h("div", { class: "grid-stats" },
        stat("Downloads (24h)", o.last_24h.downloads), stat("Views (24h)", o.last_24h.views), stat("Uploads (24h)", o.last_24h.uploads),
        stat("Refused (24h)", o.last_24h.denied), stat("Permission changes (24h)", o.last_24h.permission_changes),
        stat("Failed sign-ins (24h)", o.last_24h.failed_logins)),
      h("div", { class: "card" }, h("h2", {}, "Alerts"), alerts),
      h("div", { class: "card" }, h("h2", {}, "Recent permission changes (7 days)"), eventsTable(o.recent_permission_changes, { showDoc: true }))];
  }

  async function adminAudit(params) {
    const res = await api("GET", `/admin/audit${qs(params)}`);
    const f = {
      action: h("input", { id: "a-action", value: params.action || "", placeholder: "e.g. document.download" }),
      outcome: h("select", { id: "a-out" }, ["", "success", "denied", "error"].map((o) => h("option", { value: o, selected: o === (params.outcome || "") }, o || "Any result"))),
      actor: h("input", { id: "a-actor", value: params.actor || "", placeholder: "username" }),
      document_id: h("input", { id: "a-doc", value: params.document_id || "", placeholder: "document id" }),
      from: h("input", { id: "a-from", type: "date", value: params.from || "" }),
      to: h("input", { id: "a-to", type: "date", value: params.to || "" }),
    };
    const form = h("form", {
      class: "card form-grid",
      onsubmit: (e) => {
        e.preventDefault();
        location.hash = `#/admin/audit${qs({ action: f.action.value.trim(), outcome: f.outcome.value, actor: f.actor.value.trim(), document_id: f.document_id.value.trim(), from: f.from.value, to: f.to.value })}`;
      },
    }, h("div", { class: "field" }, h("label", { for: "a-action" }, "Action starts with"), f.action),
       h("div", { class: "field" }, h("label", { for: "a-out" }, "Result"), f.outcome),
       h("div", { class: "field" }, h("label", { for: "a-actor" }, "Actor"), f.actor),
       h("div", { class: "field" }, h("label", { for: "a-doc" }, "Document"), f.document_id),
       h("div", { class: "field" }, h("label", { for: "a-from" }, "From"), f.from),
       h("div", { class: "field" }, h("label", { for: "a-to" }, "To"), f.to),
       h("div", { class: "row" }, h("button", { class: "btn primary", type: "submit" }, "Filter"), h("a", { class: "btn", href: "#/admin/audit" }, "Reset")));
    const more = res.next_before_seq
      ? h("a", { class: "btn", href: `#/admin/audit${qs({ ...params, before_seq: res.next_before_seq })}` }, "Older events →") : null;
    return [pageHead("Audit trail", "Append-only and hash-chained. Refused attempts are recorded alongside successful ones."),
      form, h("div", { class: "card" }, eventsTable(res.items, { showDoc: true }), more ? h("div", { class: "row" }, more) : null)];
  }

  async function adminUsers() {
    const res = await api("GET", "/admin/users");
    const msg = h("div");
    const act = async (fn, ok) => { try { await fn(); toast(ok); render(); } catch (err) { clear(msg).append(errorBox(err)); window.scrollTo(0, 0); } };
    const rows = res.items.map((u) => {
      const role = h("select", { "aria-label": `Role for ${u.username}`, disabled: u.id === state.me.id,
        onchange: () => act(() => api("PATCH", `/admin/users/${u.id}`, { role: role.value }), "Role changed; their sessions were ended.") },
        ["admin", "owner", "viewer"].map((r) => h("option", { value: r, selected: r === u.role }, r)));
      return h("tr", {},
        h("td", {}, u.display_name, h("div", { class: "muted small" }, u.username, u.is_demo_account ? " · demo" : "")),
        h("td", {}, role),
        h("td", {}, h("span", { class: `tag ${u.is_active ? "success" : "inactive"}` }, u.is_active ? "active" : "deactivated"),
          u.must_change_password ? h("div", { class: "muted small" }, "temp password") : null),
        h("td", {}, u.owned_documents), h("td", {}, u.active_sessions),
        h("td", {}, h("div", { class: "row" },
          u.id === state.me.id ? null : h("button", { class: `btn sm ${u.is_active ? "danger" : ""}`,
            onclick: () => {
              if (u.is_active && !confirm(`Deactivate ${u.username}? They are signed out everywhere immediately.`)) return;
              act(() => api("PATCH", `/admin/users/${u.id}`, { is_active: !u.is_active }), u.is_active ? "Deactivated and signed out." : "Reactivated.");
            } }, u.is_active ? "Deactivate" : "Reactivate"),
          h("button", { class: "btn sm", onclick: () => {
            const p = prompt(`Temporary password for ${u.username} (12+ chars). They must change it at next sign-in.`);
            if (p) act(() => api("POST", `/admin/users/${u.id}/reset-password`, { password: p }), "Password reset; sessions ended.");
          } }, "Reset password"),
          h("button", { class: "btn sm", onclick: () => act(() => api("POST", `/admin/users/${u.id}/revoke-sessions`), "Sessions ended.") }, "Sign out everywhere"))));
    });
    const nf = {
      username: h("input", { id: "n-u", required: true, maxlength: 32, placeholder: "e.g. priya.n" }),
      display: h("input", { id: "n-d", maxlength: 80, placeholder: "Full name" }),
      role: h("select", { id: "n-r" }, ["viewer", "owner", "admin"].map((r) => h("option", { value: r }, r))),
      password: h("input", { id: "n-p", type: "password", required: true, minlength: 12, autocomplete: "new-password" }),
    };
    const create = h("form", {
      class: "form-grid",
      onsubmit: (e) => {
        e.preventDefault();
        act(() => api("POST", "/admin/users", { username: nf.username.value.trim(), display_name: nf.display.value.trim() || nf.username.value.trim(), role: nf.role.value, password: nf.password.value }),
          "Account created. They must change the password at first sign-in.");
      },
    }, h("div", { class: "field" }, h("label", { for: "n-u" }, "Username"), nf.username),
       h("div", { class: "field" }, h("label", { for: "n-d" }, "Display name"), nf.display),
       h("div", { class: "field" }, h("label", { for: "n-r" }, "Role"), nf.role),
       h("div", { class: "field" }, h("label", { for: "n-p" }, "Temporary password"), nf.password),
       h("div", {}, h("button", { class: "btn primary", type: "submit" }, "Create account")));
    return [pageHead("People", "Deactivating someone or changing their role signs them out everywhere, immediately."),
      msg, h("div", { class: "card" }, h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Person", "Role", "Status", "Owns", "Sessions", ""].map((t) => h("th", {}, t)))),
        h("tbody", {}, rows)))),
      h("div", { class: "card" }, h("h2", {}, "New account"), create)];
  }

  async function adminDocuments() {
    const [res, users] = await Promise.all([api("GET", "/admin/documents"), api("GET", "/admin/users")]);
    const owners = users.items.filter((u) => u.role === "owner" && u.is_active);
    const msg = h("div");
    const rows = res.items.map((d) => {
      const sel = h("select", { "aria-label": "New owner" }, h("option", { value: "" }, "Transfer to…"),
        owners.filter((o) => o.id !== d.owner.id).map((o) => h("option", { value: o.id }, o.username)));
      return h("tr", {},
        h("td", { class: "wrap" }, d.title, h("div", { class: "muted small mono" }, d.id)),
        h("td", {}, d.category),
        h("td", {}, d.owner.username, d.owner.is_active ? null : h("div", {}, h("span", { class: "tag inactive" }, "owner deactivated"))),
        h("td", {}, d.grant_count),
        h("td", {}, d.deleted_at ? h("span", { class: "tag inactive" }, "in trash") : h("span", { class: "tag success" }, "active")),
        h("td", {}, h("div", { class: "row" }, sel, h("button", { class: "btn sm", onclick: async () => {
          if (!sel.value) return;
          const reason = prompt("Reason for the transfer (recorded in the audit trail):");
          if (!reason) return;
          try { await api("POST", `/admin/documents/${d.id}/transfer`, { new_owner_id: sel.value, reason }); toast("Ownership transferred."); render(); }
          catch (err) { clear(msg).append(errorBox(err)); }
        } }, "Transfer"))));
    });
    return [pageHead("All documents", "Metadata only. Administrators cannot open or download documents they were not granted."),
      msg, h("div", { class: "card" }, h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Document", "Category", "Owner", "Grants", "State", "Ownership"].map((t) => h("th", {}, t)))),
        h("tbody", {}, rows))))];
  }

  // ---------- router ----------------------------------------------------------------------
  function parseHash() {
    const raw = location.hash.replace(/^#/, "") || "/documents";
    const [path, query] = raw.split("?");
    return { path, params: Object.fromEntries(new URLSearchParams(query || "")) };
  }

  let renderToken = 0;
  async function render() {
    const token = ++renderToken;
    const { path, params } = parseHash();
    if (!state.me && !state.checked) {
      state.checked = true;  // ask the server once per page load; afterwards the login flow sets it
      try { setMe(await api("GET", "/auth/me")); } catch (_) { /* not signed in */ }
    }
    if (!state.me) {
      if (path !== "/login") { location.hash = "#/login"; return; }
      clear(app).append(loginView());
      app.className = "";
      return;
    }
    if (path === "/login") { location.hash = state.me.role === "admin" ? "#/admin" : "#/documents"; return; }
    if (state.me.must_change_password && path !== "/account") { location.hash = "#/account"; return; }
    let content;
    try {
      const m = path.match(/^\/documents\/([^/]+)$/);
      if (path === "/documents") content = await documentsView(params);
      else if (m) content = await documentView(decodeURIComponent(m[1]));
      else if (path === "/upload") content = await uploadView();
      else if (path === "/trash") content = await trashView();
      else if (path === "/account") content = accountView();
      else if (path === "/admin") content = await adminOverview();
      else if (path === "/admin/audit") content = await adminAudit(params);
      else if (path === "/admin/users") content = await adminUsers();
      else if (path === "/admin/documents") content = await adminDocuments();
      else content = [pageHead("Not found", "")];
    } catch (err) {
      if (err.status === 401) return;
      content = [pageHead(err.status === 404 ? "Not available" : "Something went wrong", ""),
        h("div", { class: "card" }, err.status === 404
          ? h("div", { class: "notice" }, "This document does not exist, or you do not have access to it. Ask its owner to share it with you.")
          : errorBox(err), h("a", { href: "#/documents" }, "Back to documents"))];
    }
    if (token !== renderToken) return;
    clear(app).append(shell(content));
    app.className = "";
  }

  window.addEventListener("hashchange", render);
  render();
})();
