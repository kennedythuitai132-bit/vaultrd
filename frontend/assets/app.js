const API = {
  async call(method, path, body, isForm) {
    const headers = {};
    if (!isForm) headers["Content-Type"] = "application/json";
    const csrf = localStorage.getItem("vaultrd_csrf");
    if (csrf) headers["X-CSRF-Token"] = csrf;
    const opts = { method, headers, credentials: "include" };
    if (body) opts.body = isForm ? body : JSON.stringify(body);
    const res = await fetch("/api" + path, opts);
    const ct = res.headers.get("content-type") || "";
    const data = ct.includes("json") ? await res.json() : { raw: await res.text() };
    if (!res.ok && data.error) throw new Error(data.error);
    return data;
  },
  get(p) { return this.call("GET", p); },
  post(p, b) { return this.call("POST", p, b); },
  patch(p, b) { return this.call("PATCH", p, b); },
  del(p) { return this.call("DELETE", p); },
  postForm(p, fd) { return this.call("POST", p, fd, true); },
};

const UI = {
  el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") e.className = v;
      else if (k === "html") e.innerHTML = v;
      else if (k.startsWith("on")) e[k] = v;
      else e.setAttribute(k, v);
    }
    for (const c of children) { if (c == null) continue; e.appendChild(typeof c === "string" ? document.createTextNode(c) : c); }
    return e;
  },
  fmtDate(s) { return s ? new Date(s).toLocaleString() : "—"; },
  fmtBytes(n) { if (n < 1024) return n + " B"; if (n < 1048576) return (n/1024).toFixed(1) + " KB"; return (n/1048576).toFixed(2) + " MB"; },
  badge(s, kind) {
    const cls = kind || (s === "success" || s === "resolved" || s === "approved" ? "success" : s === "failure" || s === "open" || s === "high" ? "danger" : s === "pending" || s === "medium" ? "warn" : "muted");
    return this.el("span", { class: "badge badge-" + cls }, String(s));
  },
  roleTag(r) { return this.el("span", { class: "role-" + r }, r); },
  showError(host, msg) { if (host) host.innerHTML = '<div class="alert-box error">' + (msg || "Error") + '</div>'; },
  showSuccess(host, msg) { if (host) host.innerHTML = '<div class="alert-box success">' + (msg || "Done") + '</div>'; },
};

async function requireAuth() {
  try { const me = await API.get("/auth/me"); return me.user; }
  catch { window.location.href = "/pages/login.html"; return null; }
}
async function requireAdmin() {
  const user = await requireAuth();
  if (!user) return null;
  if (user.role !== "admin") { alert("Admin access required"); window.location.href = "/pages/dashboard.html"; return null; }
  return user;
}

function buildSidebar(user) {
  const path = window.location.pathname;
  const items = [
    { href: "/pages/dashboard.html",     label: "Dashboard",     icon: "layout-dashboard" },
    { href: "/pages/files.html",         label: "Research Files",icon: "folder-lock" },
    { href: "/pages/catalogue.html",     label: "Catalogue",     icon: "library" },
    { href: "/pages/grants.html",        label: "Grants",        icon: "hand-coins" },
    { href: "/pages/departments.html",   label: "Departments",   icon: "building-2" },
    { href: "/pages/collaborators.html", label: "Collaborators", icon: "users" },
  ];
  if (user.role === "admin") {
    items.push({ href: "/pages/users.html",   label: "User Management", icon: "user-cog" });
    items.push({ href: "/pages/audit.html",   label: "Audit Logs",      icon: "scroll-text" });
    items.push({ href: "/pages/alerts.html",  label: "Alerts",          icon: "bell" });
    items.push({ href: "/pages/reports.html", label: "Reports",         icon: "bar-chart-3" });
    items.push({ href: "/pages/settings.html", label: "Settings",       icon: "settings" });
  }
  const navEl = UI.el("nav", { class: "sb-nav" });
  for (const it of items) {
    const active = path.includes(it.href.split("/").pop()) ? "active" : "";
    navEl.appendChild(UI.el("a", { href: it.href, class: "sb-item " + active },
      UI.el("i", { "data-lucide": it.icon }),
      UI.el("span", null, it.label)
    ));
  }
  return UI.el("aside", { class: "sidebar" },
    UI.el("div", { class: "sb-brand" },
      UI.el("div", { class: "sb-brand-icon" }, UI.el("i", { "data-lucide": "shield-check" })),
      UI.el("span", { class: "sb-brand-name" }, "VaultRD")
    ),
    navEl,
  );
}

function buildTopbar(user) {
  const initial = (user.username || "?").charAt(0).toUpperCase();
  return UI.el("div", { class: "topbar" },
    UI.el("button", { class: "home-btn", onclick: () => window.location.href = "/pages/dashboard.html" }, UI.el("i", { "data-lucide": "home" })),
    UI.el("div", { class: "search-bar" },
      UI.el("i", { "data-lucide": "search" }),
      UI.el("input", { placeholder: "Search projects, files, or people...", type: "text" })
    ),
    UI.el("div", { class: "top-actions" },
      UI.el("button", { class: "icon-btn" }, UI.el("i", { "data-lucide": "bell" })),
      UI.el("button", { class: "icon-btn" }, UI.el("i", { "data-lucide": "moon" })),
      UI.el("div", { class: "user-chip", id: "userDropdownBtn", style: "position:relative" },
        UI.el("div", { class: "avatar-lg" }, initial),
        UI.el("div", { class: "u-meta" },
          UI.el("div", { class: "u-name" }, user.username),
          UI.el("div", { class: "u-role" }, user.role)
        ),
        UI.el("i", { "data-lucide": "chevron-down", style: "width:14px;height:14px;color:#94a3b8" })
      )
    )
  );
}

function mountShell(user) {
  const sidebar = buildSidebar(user);
  const topbar = buildTopbar(user);
  const mainArea = UI.el("div", { class: "main-area" }, topbar);
  const shell = UI.el("div", { class: "app-shell" }, sidebar, mainArea);
  document.body.insertBefore(shell, document.body.firstChild);
  document.body.classList.add("v2");
  setTimeout(() => { if (window.lucide) window.lucide.createIcons(); }, 0);

  // Inject User Dropdown
  const chip = document.getElementById("userDropdownBtn");
  if (chip) {
    chip.style.position = "relative";
    const menu = UI.el("div", { id: "userDropdownMenu", style: "display:none;position:absolute;top:110%;right:0;width:200px;background:#fff;border:1px solid #e2e8f0;border-radius:10px;box-shadow:0 10px 25px rgba(0,0,0,.1);z-index:100;padding:8px 0" });
    
    menu.innerHTML = `
      <div style="padding:8px 16px 12px;border-bottom:1px solid #e2e8f0;margin-bottom:8px">
        <div style="font-weight:600;font-size:.9rem;color:#0f172a">${user.username}</div>
        <div style="font-size:.75rem;color:#3b82f6;font-weight:600;text-transform:uppercase;margin-top:2px">${user.role}</div>
      </div>
      <a href="/pages/settings.html" style="display:flex;align-items:center;gap:10px;padding:10px 16px;color:#334155;text-decoration:none;font-size:.85rem;font-weight:500" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='transparent'">
        <i data-lucide="settings" style="width:16px;height:16px"></i> Settings
      </a>
      <a href="/pages/notifications.html" style="display:flex;align-items:center;gap:10px;padding:10px 16px;color:#334155;text-decoration:none;font-size:.85rem;font-weight:500" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='transparent'">
        <i data-lucide="bell" style="width:16px;height:16px"></i> Notifications
      </a>
      <div style="height:1px;background:#e2e8f0;margin:8px 0"></div>
      <button id="realLogoutBtn" style="display:flex;align-items:center;gap:10px;padding:10px 16px;color:#dc2626;background:none;border:none;width:100%;text-align:left;cursor:pointer;font-size:.85rem;font-weight:500" onmouseover="this.style.background='#fef2f2'" onmouseout="this.style.background='transparent'">
        <i data-lucide="log-out" style="width:16px;height:16px"></i> Sign out
      </button>
    `;
    chip.appendChild(menu);
    
    chip.addEventListener("click", (e) => {
      if (e.target.closest("#userDropdownMenu")) return; // ignore clicks inside menu
      menu.style.display = menu.style.display === "none" ? "block" : "none";
      if (window.lucide) window.lucide.createIcons();
    });

    document.addEventListener("click", (e) => {
      if (!chip.contains(e.target)) menu.style.display = "none";
    });

    document.getElementById("realLogoutBtn").onclick = async () => {
      try { await API.post("/auth/logout"); } catch(e) {}
      window.location.href = "/pages/login.html";
    };
  }

  return mainArea;
}

// Backward-compat shim: old pages call mountHeader(user) — map it to mountShell
function mountHeader(user) { return mountShell(user); }
