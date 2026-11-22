// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Magnus Kolsjö
//
// Progressive enhancement for the admin UI. Every page works without this
// file; it adds what plain HTML cannot do:
//
//   * focus on the status or error message after a redirect, since the
//     autofocus attribute on a non-control is not applied reliably;
//   * a keep-alive ping while the owner types or clicks, so the idle
//     timeout only stops a server nobody is using;
//   * a warning dialog before the idle timeout (WCAG 2.2.1), with focus on
//     a Continue button that extends the time;
//   * a confirmation before a header link or "Close settings" throws away
//     what was typed in a form.
//
// The page's Content-Security-Policy allows only same-origin scripts, so
// all text comes from the server-rendered dialogs in base.html.

(function () {
  "use strict";

  var body = document.body;
  var csrf = body.getAttribute("data-csrf") || "";
  var idleSeconds = parseInt(body.getAttribute("data-idle-seconds") || "0", 10);

  // Pinging on every keystroke would be wasteful; once a minute is far
  // inside any useful timeout.
  var PING_INTERVAL_MS = 60 * 1000;
  // The watcher thread on the server checks every 15 seconds at most, so
  // the server may stop up to that long after the deadline.
  var SHUTDOWN_GRACE_MS = 20 * 1000;

  // ---------------------------------------------------------------------
  // Focus after redirects
  // ---------------------------------------------------------------------

  function focusMessage() {
    var target = document.querySelector("[data-focus-on-load]");
    if (target && document.activeElement !== target) {
      target.focus();
    }
  }

  // ---------------------------------------------------------------------
  // Dialog helpers
  // ---------------------------------------------------------------------

  var supportsDialog = typeof HTMLDialogElement === "function";

  function openDialog(dialog, initialFocus) {
    if (!dialog || !supportsDialog || dialog.open) {
      return false;
    }
    var returnTo = document.activeElement;
    dialog.addEventListener("close", function restore() {
      dialog.removeEventListener("close", restore);
      if (returnTo && typeof returnTo.focus === "function" && document.contains(returnTo)) {
        returnTo.focus();
      }
    });
    dialog.showModal();
    if (initialFocus) {
      initialFocus.focus();
    }
    return true;
  }

  // ---------------------------------------------------------------------
  // Idle timeout: keep-alive and warning
  // ---------------------------------------------------------------------

  var idleDialog = document.getElementById("idle-dialog");
  var deadline = Date.now() + idleSeconds * 1000;
  var lastPing = Date.now();  // loading the page was a request too
  var warnTimer = null;
  var closedTimer = null;
  var serverClosed = false;

  // Warn two minutes ahead; with a very short timeout (for testing) warn
  // halfway, so the warning never comes before the page has settled.
  function warnBeforeMs() {
    var total = idleSeconds * 1000;
    return Math.min(120 * 1000, Math.max(total - 30 * 1000, total / 2));
  }

  function idleState(name) {
    if (!idleDialog) {
      return null;
    }
    var shown = null;
    Array.prototype.forEach.call(idleDialog.querySelectorAll("[data-state]"), function (part) {
      var match = part.getAttribute("data-state") === name;
      part.hidden = !match;
      if (match) {
        shown = part;
      }
    });
    return shown;
  }

  function applyStatus(data) {
    if (data && typeof data.seconds_left === "number") {
      deadline = Date.now() + data.seconds_left * 1000;
      schedule();
    }
  }

  function markClosed() {
    serverClosed = true;
    window.clearTimeout(warnTimer);
    window.clearTimeout(closedTimer);
    var part = idleState("closed");
    if (!idleDialog || !part) {
      return;
    }
    var button = part.querySelector("[data-idle-dismiss]");
    if (idleDialog.open) {
      button.focus();
    } else {
      openDialog(idleDialog, button);
    }
  }

  function request(method, url, payload) {
    var options = { method: method, credentials: "same-origin", cache: "no-store" };
    if (payload) {
      options.body = payload;
    }
    return fetch(url, options).then(function (response) {
      if (!response.ok) {
        // A 403 means the session is gone, which only happens when the
        // settings were closed; treat it like a stopped server.
        throw new Error("status " + response.status);
      }
      return response.json();
    });
  }

  function ping() {
    lastPing = Date.now();
    var form = new FormData();
    form.append("csrf_token", csrf);
    return request("POST", "/keepalive", form).then(applyStatus, markClosed);
  }

  function onActivity() {
    // While the warning is open only its button continues, so that the
    // time it shows stays true until the owner answers it.
    if (idleDialog.open) {
      return;
    }
    if (!serverClosed && Date.now() - lastPing >= PING_INTERVAL_MS) {
      ping();
    }
  }

  function showWarning() {
    // Another tab may have kept the server alive; ask before warning.
    request("GET", "/status").then(function (data) {
      if (data.seconds_left * 1000 > warnBeforeMs() + 5000) {
        applyStatus(data);
        return;
      }
      deadline = Date.now() + data.seconds_left * 1000;
      var part = idleState("warning");
      var time = idleDialog.querySelector("[data-idle-time]");
      if (time) {
        time.textContent = new Date(deadline).toLocaleTimeString(
          document.documentElement.lang || undefined, { hour: "2-digit", minute: "2-digit" });
      }
      openDialog(idleDialog, part.querySelector("[data-idle-continue]"));
      window.clearTimeout(closedTimer);
      closedTimer = window.setTimeout(checkClosed, Math.max(deadline - Date.now(), 0) + SHUTDOWN_GRACE_MS);
    }, markClosed);
  }

  function checkClosed() {
    request("GET", "/status").then(function (data) {
      if (data.seconds_left > 0) {
        closedTimer = window.setTimeout(checkClosed, data.seconds_left * 1000 + SHUTDOWN_GRACE_MS);
      } else {
        closedTimer = window.setTimeout(checkClosed, 5000);
      }
    }, markClosed);
  }

  function schedule() {
    window.clearTimeout(warnTimer);
    if (serverClosed) {
      return;
    }
    var wait = Math.max(deadline - Date.now() - warnBeforeMs(), 0);
    warnTimer = window.setTimeout(showWarning, wait);
  }

  function continueWorking() {
    window.clearTimeout(closedTimer);
    if (idleDialog.open) {
      idleDialog.close();
    }
    ping();
  }

  function setUpIdle() {
    if (!idleDialog || !csrf || idleSeconds <= 0 || typeof fetch !== "function") {
      return;
    }
    ["keydown", "input", "pointerdown"].forEach(function (name) {
      document.addEventListener(name, onActivity, true);
    });
    idleDialog.querySelector("[data-idle-continue]").addEventListener("click", continueWorking);
    idleDialog.querySelector("[data-idle-dismiss]").addEventListener("click", function () {
      idleDialog.close();
    });
    // Escape closes a modal dialog; in the warning state it means the
    // owner is here, so it continues just like the button does.
    idleDialog.addEventListener("cancel", function (event) {
      if (!serverClosed) {
        event.preventDefault();
        continueWorking();
      }
    });
    schedule();
  }

  // ---------------------------------------------------------------------
  // Unsaved changes
  // ---------------------------------------------------------------------

  var leaveDialog = document.getElementById("leave-dialog");
  var pendingLeave = null;

  function dirtyForm() {
    var form = document.querySelector("form[data-dirty-check]");
    return form && form.getAttribute("data-dirty") === "true" ? form : null;
  }

  function guard(event, proceed) {
    if (!dirtyForm() || !leaveDialog || !supportsDialog) {
      return;
    }
    event.preventDefault();
    pendingLeave = proceed;
    openDialog(leaveDialog, leaveDialog.querySelector("[data-leave-stay]"));
  }

  function setUpLeaveGuard() {
    var form = document.querySelector("form[data-dirty-check]");
    if (!form || !leaveDialog) {
      return;
    }
    function markDirty() {
      form.setAttribute("data-dirty", "true");
    }
    form.addEventListener("input", markDirty);
    form.addEventListener("change", markDirty);
    form.addEventListener("submit", function () {
      form.removeAttribute("data-dirty");
    });

    // Header links (navigation and language) leave the page; in-page
    // anchors such as the skip link do not.
    Array.prototype.forEach.call(document.querySelectorAll(".site-header a[href]"), function (link) {
      if (link.getAttribute("href").charAt(0) === "#") {
        return;
      }
      link.addEventListener("click", function (event) {
        guard(event, function () {
          window.location.href = link.href;
        });
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll("form[data-leave-guard]"), function (closeForm) {
      closeForm.addEventListener("submit", function (event) {
        guard(event, function () {
          // form.submit() skips the submit event, so this does not loop.
          closeForm.submit();
        });
      });
    });

    leaveDialog.querySelector("[data-leave-stay]").addEventListener("click", function () {
      pendingLeave = null;
      leaveDialog.close();
    });
    leaveDialog.querySelector("[data-leave-go]").addEventListener("click", function () {
      var proceed = pendingLeave;
      pendingLeave = null;
      form.removeAttribute("data-dirty");
      leaveDialog.close();
      if (proceed) {
        proceed();
      }
    });
    leaveDialog.addEventListener("cancel", function () {
      pendingLeave = null;
    });
  }

  focusMessage();
  setUpIdle();
  setUpLeaveGuard();
})();
