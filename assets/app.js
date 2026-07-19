// Cryptarch — progressive enhancement only. The portal is fully functional
// with JS disabled; this file adds conveniences. Served from /static/app.js
// under a strict CSP (no inline scripts anywhere). htmx (hx-boost, hx-confirm)
// is loaded separately from /static/htmx.min.js.

// Copy-to-clipboard for credentials and connection strings.
// navigator.clipboard only exists in secure contexts — a plain-HTTP LAN
// deploy (the homelab norm) doesn't have it, so fall back to the legacy
// execCommand path, and if that fails too, tell the user instead of
// silently doing nothing. These are show-once passwords; silence is not ok.
function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise((resolve, reject) => {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (_) { /* fall through */ }
    ta.remove();
    ok ? resolve() : reject(new Error("execCommand copy failed"));
  });
}

function flashCopyButton(btn, label, cls) {
  // Stash the true resting label once — re-reading textContent on a second
  // click inside the flash window would capture the flash text forever.
  if (btn.dataset.restLabel === undefined) btn.dataset.restLabel = btn.textContent;
  clearTimeout(btn._flashTimer);
  btn.textContent = label;
  btn.classList.remove("copied", "failed");
  btn.classList.add(cls);
  btn._flashTimer = setTimeout(() => {
    btn.textContent = btn.dataset.restLabel;
    btn.classList.remove(cls);
  }, 1600);
}

document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  copyText(btn.dataset.copy).then(
    () => flashCopyButton(btn, "copied", "copied"),
    () => flashCopyButton(btn, "select & Ctrl-C", "failed"),
  );
});

// Provision form: "Allowed from" follows the selected server's default CIDR.
// Options carry data-cidr; the input is only rewritten while the user hasn't
// typed their own value (i.e. it still equals the previous server's default).
function wireCidrFollow(root) {
  const select = root.querySelector("select[name=server_id]");
  const input = root.querySelector("input[name=allowed_from]");
  if (!select || !input || select.dataset.cidrWired) return;
  select.dataset.cidrWired = "1";
  const cidrOf = () => select.selectedOptions[0]?.dataset.cidr ?? "";
  // Named-source groups (CRYPTARCH-39): show only the selected server's
  // checkboxes and untick the hidden ones so they can't post. Without JS,
  // every group stays visible (captioned by server name) and the backend's
  // server-scoped resolution ignores foreign ticks — degraded but safe.
  const groups = [...root.querySelectorAll(".src-group[data-server]")];
  const showGroups = () => {
    groups.forEach((g) => {
      const active = g.dataset.server === select.value;
      g.hidden = !active;
      if (!active) g.querySelectorAll("input[type=checkbox]").forEach((c) => (c.checked = false));
      else g.querySelectorAll("input[type=checkbox]").forEach((c) => (c.checked = c.defaultChecked));
    });
    const caption = groups.length > 0;
    if (caption) root.querySelectorAll(".src-server").forEach((el) => (el.hidden = true));
  };
  if (groups.length) showGroups();
  let lastDefault = cidrOf();
  select.addEventListener("change", () => {
    if (groups.length) showGroups();
    if (input.value.trim() === lastDefault.trim()) input.value = cidrOf();
    lastDefault = cidrOf();
  });
}
// ---- toasts -----------------------------------------------------------------

function toastHost() {
  let host = document.getElementById("toast-host");
  if (!host) {
    host = document.createElement("div");
    host.id = "toast-host";
    document.body.appendChild(host);
  }
  return host;
}

// Styled confirmation replacing the browser-native dialog: htmx fires
// htmx:confirm for any element carrying hx-confirm; we take over, render a
// centered modal dialog, and resume the request via issueRequest(true) on
// approval. Centered + backdrop on purpose: a destructive confirmation is a
// blocking decision and must interrupt where the eyes are — corner toasts
// are for ignorable outcomes, not questions. Without JS, htmx isn't running
// either and forms submit natively — same behavior as before this layer.
document.addEventListener("htmx:confirm", (e) => {
  if (!e.detail.question) return;
  e.preventDefault();
  showConfirmDialog(e.detail.question, () => e.detail.issueRequest(true));
});

function showConfirmDialog(message, onConfirm) {
  document.querySelectorAll(".confirm-backdrop").forEach((b) => b.remove());
  const backdrop = document.createElement("div");
  backdrop.className = "confirm-backdrop";
  const dialog = document.createElement("div");
  dialog.className = "confirm-dialog";
  dialog.setAttribute("role", "alertdialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-label", "Confirm action");
  const text = document.createElement("p");
  text.textContent = message;
  const actions = document.createElement("div");
  actions.className = "toast-actions";
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "small";
  cancel.textContent = "Cancel";
  const confirm = document.createElement("button");
  confirm.type = "button";
  confirm.className = "danger small";
  confirm.textContent = "Confirm";
  actions.append(cancel, confirm);
  dialog.append(text, actions);
  backdrop.append(dialog);
  const opener = document.activeElement;
  const close = () => {
    backdrop.remove();
    document.removeEventListener("keydown", onKey);
    if (opener && opener.focus) opener.focus();
  };
  const onKey = (ev) => {
    if (ev.key === "Escape") {
      close();
    } else if (ev.key === "Tab") {
      // Two-stop focus trap: the dialog owns Tab while it's open.
      ev.preventDefault();
      (document.activeElement === cancel ? confirm : cancel).focus();
    }
  };
  document.addEventListener("keydown", onKey);
  backdrop.addEventListener("click", (ev) => {
    if (ev.target === backdrop) close();
  });
  cancel.addEventListener("click", close);
  confirm.addEventListener("click", () => {
    close();
    onConfirm();
  });
  document.body.appendChild(backdrop);
  // Safe default: focus lands on Cancel, Enter does nothing destructive.
  cancel.focus();
}

// Success flashes: the server renders inline .notice banners (visible as-is
// without JS); with JS we lift them into auto-dismissing toasts so feedback
// reads in one consistent place. Errors stay inline — they must persist.
function liftFlashes() {
  document.querySelectorAll("main .notice[role=status]").forEach((n) => {
    const toast = document.createElement("div");
    toast.className = "toast note";
    toast.setAttribute("role", "status");
    toast.textContent = n.textContent;
    n.remove();
    toastHost().append(toast);
    setTimeout(() => {
      toast.classList.add("bye");
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  });
}

// Topbar: mark the primary-nav link matching the current location. Runs on
// load and after every boosted swap; without JS the nav simply has no
// highlight, which loses nothing functional.
function markActiveNav() {
  const path = location.pathname;
  document.querySelectorAll("nav.primary a").forEach((a) => {
    const href = a.getAttribute("href");
    const active =
      href === "/dashboard"
        ? path === "/dashboard" || path.startsWith("/db/") || path === "/provision"
        : path.startsWith(href);
    a.classList.toggle("active", active);
    if (active) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
}

document.addEventListener("DOMContentLoaded", () => {
  wireCidrFollow(document);
  markActiveNav();
  liftFlashes();
});
// Re-wire after boosted navigation swaps in a new page body.
document.addEventListener("htmx:load", (e) => {
  wireCidrFollow(e.target);
  markActiveNav();
  liftFlashes();
});
