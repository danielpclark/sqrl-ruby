/*
 * sqrl.js - browser side of SQRL login for the sqrl-rack / sqrl-rails gems.
 *
 * Attaches to every element with [data-sqrl-login]. Attributes:
 *   data-sqrl-url      the sqrl:// login URL
 *   data-sqrl-status   URL of the cookie-bound status poll endpoint
 *   data-sqrl-refresh  URL of the JSON endpoint that hands out a fresh login URL (optional)
 *   data-sqrl-poll     poll interval in milliseconds (default 2000)
 *   data-sqrl-text-*   message texts (message, cps, done, expired)
 * Children (optional): a[data-sqrl-link], [data-sqrl-qr], [data-sqrl-message],
 * button[data-sqrl-refresh-button].
 *
 * 1. Same-device Client Provided Session (CPS) probe: native SQRL clients and the browser
 *    extension listen on http://localhost:25519/. When the probe image loads, the login link
 *    is pointed at http://localhost:25519/<base64url sqrl url>.
 * 2. Polling for logins from another device: the status endpoint is bound to this
 *    browser's session cookie and answers {"authenticated": true, "next": url} once done,
 *    or {"expired": true} when the login code is no longer valid. Errors back the poll
 *    off (up to 10 s) and a success resets it.
 * 3. Refresh: SQRL.refresh(root) asks the refresh endpoint for a new login URL and swaps
 *    the link and QR code in place; the "Get a new code" button appears on expiry.
 *
 * Events dispatched on the root element: sqrl:cps-detected, sqrl:authenticated (detail:
 * {next}), sqrl:expired, sqrl:refreshed (detail: {sqrlUrl}), sqrl:error (detail: {error}).
 */
(function () {
  "use strict";

  var CPS_ORIGIN = "http://localhost:25519/";
  var MAX_BACKOFF = 10000;

  function base64url(str) {
    var bytes = new TextEncoder().encode(str);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function text(root, key, fallback) {
    return root.getAttribute("data-sqrl-text-" + key) || fallback;
  }

  function setMessage(root, msg) {
    var el = root.querySelector("[data-sqrl-message]");
    if (el) el.textContent = msg;
  }

  function emit(root, name, detail) {
    root.dispatchEvent(new CustomEvent(name, { bubbles: true, detail: detail || {} }));
  }

  function applyLink(root) {
    var link = root.querySelector("a[data-sqrl-link]");
    var url = root.getAttribute("data-sqrl-url");
    if (!link || !url) return;
    link.href = root.getAttribute("data-sqrl-cps") === "true" ? CPS_ORIGIN + base64url(url) : url;
  }

  function probeCps(root) {
    var img = new Image();
    img.onload = function () {
      root.setAttribute("data-sqrl-cps", "true");
      var link = root.querySelector("a[data-sqrl-link]");
      if (link) link.setAttribute("data-sqrl-cps", "true");
      applyLink(root);
      setMessage(root, text(root, "cps", "Local SQRL client detected."));
      emit(root, "sqrl:cps-detected");
    };
    img.onerror = function () {
      root.setAttribute("data-sqrl-cps", "false");
      var link = root.querySelector("a[data-sqrl-link]");
      if (link) link.setAttribute("data-sqrl-cps", "false");
    };
    img.src = CPS_ORIGIN + Math.random().toString(36).slice(2) + ".gif";
  }

  function startPolling(root) {
    if (root.sqrlStopPolling) root.sqrlStopPolling();
    var statusUrl = root.getAttribute("data-sqrl-status");
    if (!statusUrl) return;
    var base = parseInt(root.getAttribute("data-sqrl-poll") || "2000", 10) || 2000;
    var delay = base;
    var stopped = false;
    function schedule() { if (!stopped) window.setTimeout(tick, delay); }
    function tick() {
      if (stopped) return;
      fetch(statusUrl, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } })
        .then(function (r) { if (!r.ok) throw new Error("status " + r.status); return r.json(); })
        .then(function (j) {
          delay = base;
          if (j.authenticated && j.next) {
            stopped = true;
            setMessage(root, text(root, "done", "Logged in, redirecting…"));
            emit(root, "sqrl:authenticated", { next: j.next });
            window.location.href = j.next;
          } else if (j.expired) {
            stopped = true;
            expire(root);
          } else {
            schedule();
          }
        })
        .catch(function (e) {
          delay = Math.min(delay * 2, MAX_BACKOFF);
          emit(root, "sqrl:error", { error: e });
          schedule();
        });
    }
    schedule();
    root.sqrlStopPolling = function () { stopped = true; };
  }

  function expire(root) {
    root.setAttribute("data-sqrl-expired", "true");
    setMessage(root, text(root, "expired", "This login code expired. Reload the page to get a new one."));
    var button = root.querySelector("[data-sqrl-refresh-button]");
    if (button && root.getAttribute("data-sqrl-refresh")) button.hidden = false;
    emit(root, "sqrl:expired");
  }

  function refresh(root) {
    var url = root.getAttribute("data-sqrl-refresh");
    if (!url) return Promise.reject(new Error("no data-sqrl-refresh"));
    return fetch(url, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("refresh " + r.status); return r.json(); })
      .then(function (j) {
        root.setAttribute("data-sqrl-url", j.sqrl_url);
        if (j.status_url) root.setAttribute("data-sqrl-status", j.status_url);
        root.removeAttribute("data-sqrl-expired");
        applyLink(root);
        var qr = root.querySelector("[data-sqrl-qr]");
        if (qr && j.qr_svg) qr.innerHTML = j.qr_svg;
        var button = root.querySelector("[data-sqrl-refresh-button]");
        if (button) button.hidden = true;
        setMessage(root, text(root, "message", ""));
        startPolling(root);
        emit(root, "sqrl:refreshed", { sqrlUrl: j.sqrl_url });
        return j;
      });
  }

  function init(root) {
    if (root.getAttribute("data-sqrl-initialized")) return;
    root.setAttribute("data-sqrl-initialized", "true");
    if (root.getAttribute("data-sqrl-url")) probeCps(root);
    var button = root.querySelector("[data-sqrl-refresh-button]");
    if (button) button.addEventListener("click", function () { refresh(root).catch(function () { expire(root); }); });
    startPolling(root);
  }

  function initAll() {
    var roots = document.querySelectorAll("[data-sqrl-login]");
    for (var i = 0; i < roots.length; i++) init(roots[i]);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAll);
  } else {
    initAll();
  }
  document.addEventListener("turbo:load", initAll);
  window.SQRL = window.SQRL || {};
  window.SQRL.init = initAll;
  window.SQRL.refresh = refresh;
})();
