/*
 * sqrl.js - browser side of SQRL login for the sqrl-rack / sqrl-rails gems.
 *
 * Attaches to every element with [data-sqrl-login]. Expected attributes:
 *   data-sqrl-url     the sqrl:// (or qrl://) login URL
 *   data-sqrl-status  URL of the cookie-bound status poll endpoint
 *   data-sqrl-poll    poll interval in milliseconds (default 2000)
 * Inside the element, optional children:
 *   a[data-sqrl-link]            the login link (its href is rewritten for CPS)
 *   [data-sqrl-message]          status text (aria-live)
 *
 * 1. Same-device Client Provided Session (CPS) probe. Native SQRL clients and the
 *    browser extension listen on http://localhost:25519/. When a probe image loads, the
 *    login link is pointed at http://localhost:25519/<base64url sqrl url> so the client can
 *    redirect this tab straight into the logged-in session.
 * 2. Polling for non-CPS logins (for example a phone scanning the QR code): the status
 *    endpoint is bound to this browser's session cookie and answers
 *    {"authenticated": true, "next": "<url>"} once the login completed.
 */
(function () {
  "use strict";

  var CPS_ORIGIN = "http://localhost:25519/";

  function base64url(str) {
    var bytes = new TextEncoder().encode(str);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function setMessage(root, text) {
    var el = root.querySelector("[data-sqrl-message]");
    if (el) el.textContent = text;
  }

  function probeCps(root, sqrlUrl) {
    var link = root.querySelector("a[data-sqrl-link]");
    if (!link) return;
    var img = new Image();
    img.onload = function () {
      link.href = CPS_ORIGIN + base64url(sqrlUrl);
      link.setAttribute("data-sqrl-cps", "true");
      setMessage(root, root.getAttribute("data-sqrl-text-cps") || "Local SQRL client detected.");
    };
    img.onerror = function () {
      link.setAttribute("data-sqrl-cps", "false");
    };
    img.src = CPS_ORIGIN + Math.random().toString(36).slice(2) + ".gif";
  }

  function poll(root, statusUrl, interval) {
    var stopped = false;
    function tick() {
      if (stopped) return;
      fetch(statusUrl, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (j) {
          if (j && j.authenticated && j.next) {
            stopped = true;
            setMessage(root, root.getAttribute("data-sqrl-text-done") || "Logged in, redirecting…");
            window.location.href = j.next;
          } else if (j && j.expired) {
            stopped = true;
            setMessage(root, root.getAttribute("data-sqrl-text-expired") || "This login code expired. Reload the page to get a new one.");
          } else {
            window.setTimeout(tick, interval);
          }
        })
        .catch(function () { window.setTimeout(tick, interval * 2); });
    }
    window.setTimeout(tick, interval);
    return function () { stopped = true; };
  }

  function init(root) {
    if (root.getAttribute("data-sqrl-initialized")) return;
    root.setAttribute("data-sqrl-initialized", "true");
    var sqrlUrl = root.getAttribute("data-sqrl-url");
    var statusUrl = root.getAttribute("data-sqrl-status");
    var interval = parseInt(root.getAttribute("data-sqrl-poll") || "2000", 10);
    if (sqrlUrl) probeCps(root, sqrlUrl);
    if (statusUrl) root.sqrlStopPolling = poll(root, statusUrl, interval);
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
  // Turbo / pjax style navigations
  document.addEventListener("turbo:load", initAll);
  window.SQRL = window.SQRL || {};
  window.SQRL.init = initAll;
})();
