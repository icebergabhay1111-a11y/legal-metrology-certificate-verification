/* Offline checker: verifies a certificate QR's Ed25519 signature on the phone.
   Format after '#': v1|code|serial|owner|type|verified|expires|officer|key id|signature
   The server signed the text "code|serial|owner|type|verified|expires|officer". */
(function () {
  "use strict";
  var keys = {};          // key id -> CryptoKey
  var ready = document.getElementById("offline-ready");
  var result = document.getElementById("offline-result");

  // Base64 text -> bytes.
  function b64ToBytes(text) {
    var bin = atob(text);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
    return out;
  }

  // Load public keys: network first, then the copy saved on this phone.
  async function loadKeys() {
    var list = null;
    try {
      var res = await fetch("/keys.json", { cache: "no-store" });
      list = (await res.json()).keys;
      try { localStorage.setItem("sd-keys", JSON.stringify(list)); } catch (e) { /* storage off */ }
    } catch (e) {
      try { list = JSON.parse(localStorage.getItem("sd-keys") || "null"); } catch (e2) { list = null; }
    }
    if (!list) { throw new Error("no keys"); }
    for (var i = 0; i < list.length; i++) {
      keys[list[i].key_id] = await crypto.subtle.importKey(
        "raw", b64ToBytes(list[i].public_key), { name: "Ed25519" }, false, ["verify"]);
    }
  }

  // Split the QR text into named fields, or return null if it is not ours.
  function parse(text) {
    var hash = text.indexOf("#");
    if (hash < 0) { return null; }
    var parts = text.slice(hash + 1).trim().split("|").map(function (p) {
      try { return decodeURIComponent(p); } catch (e) { return p; }
    });
    if (parts.length !== 10 || parts[0] !== "v1") { return null; }
    return { code: parts[1], serial: parts[2], owner: parts[3], type: parts[4], verified: parts[5],
             expires: parts[6], officer: parts[7], keyId: parts[8], signature: parts[9],
             signed: parts.slice(1, 8).join("|") };
  }

  // Whole days from today (this phone's date) to an ISO date; negative = past.
  function daysUntil(iso) {
    var p = iso.split("-");
    var target = new Date(+p[0], +p[1] - 1, +p[2]);
    var now = new Date();
    var today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    return Math.round((target - today) / 86400000);
  }

  // Draw the result panel. Text only - nothing from the QR is treated as HTML.
  function show(tone, heading, lines, cert) {
    result.textContent = "";
    var box = document.createElement("div");
    box.className = "status " + tone;
    box.setAttribute("data-status", heading);
    var body = document.createElement("div");
    var strong = document.createElement("strong");
    strong.textContent = heading;
    body.appendChild(strong);
    lines.forEach(function (line) {
      var p = document.createElement("p");
      p.textContent = line;
      body.appendChild(p);
    });
    box.appendChild(body);
    result.appendChild(box);
    if (cert) {
      var wrap = document.createElement("section");
      wrap.className = "panel claimed";
      var title = document.createElement("h2");
      title.className = "body";
      // Under a failed check, the details are only what the QR claims.
      title.textContent = tone === "bad" && heading === "NOT AUTHENTIC"
        ? "Details this QR claims (not trustworthy)" : "Details in this QR";
      wrap.appendChild(title);
      var dl = document.createElement("dl");
      dl.className = "facts body";
      [["Certificate ID", cert.code], ["Serial number", cert.serial], ["Owner", cert.owner],
       ["Instrument type", cert.type], ["Verified on", cert.verified], ["Expires on", cert.expires]]
        .forEach(function (row) {
          var dt = document.createElement("dt"); dt.textContent = row[0];
          var dd = document.createElement("dd"); dd.textContent = row[1];
          dl.appendChild(dt); dl.appendChild(dd);
        });
      wrap.appendChild(dl);
      result.appendChild(wrap);
    }
    result.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // Check one QR text and show the answer.
  async function check(text) {
    var cert = parse(text || "");
    if (!cert) {
      show("bad", "NOT A SAHI DAAM QR", ["This text is not a Sahi Daam certificate code, or it is incomplete."]);
      return;
    }
    var key = keys[cert.keyId];
    var ok = false;
    if (key) {
      try {
        ok = await crypto.subtle.verify({ name: "Ed25519" }, key, b64ToBytes(cert.signature),
                                        new TextEncoder().encode(cert.signed));
      } catch (e) { ok = false; }
    }
    if (!ok) {
      show("bad", "NOT AUTHENTIC", ["The signature does not match. The QR was not issued by this system, or a detail in it was changed.",
                                    "Do not rely on this certificate. Report it when you are online."], cert);
      return;
    }
    var days = daysUntil(cert.expires);
    var limit = "Revocation is not checked offline: confirm online when you have signal.";
    if (days < 0) {
      show("bad", "AUTHENTIC · EXPIRED", ["Genuine certificate, but it expired " + (-days) + " days ago by this phone's date.",
                                          "The instrument must not be used in trade until re-verified.", limit], cert);
    } else {
      show("ok", "AUTHENTIC · IN DATE", ["Genuine certificate, valid for " + days + " more days by this phone's date.", limit], cert);
    }
  }

  // Camera scanning, where the browser has a built-in QR reader.
  function setUpCamera() {
    if (!("BarcodeDetector" in window) || !navigator.mediaDevices) { return; }
    var start = document.getElementById("scan-start");
    var stop = document.getElementById("scan-stop");
    var video = document.getElementById("scan-video");
    var stream = null;
    var detector = new window.BarcodeDetector({ formats: ["qr_code"] });
    document.getElementById("scan-actions").hidden = false;

    function end() {
      if (stream) { stream.getTracks().forEach(function (t) { t.stop(); }); }
      stream = null; video.hidden = true; stop.hidden = true; start.hidden = false;
    }
    async function tick() {
      if (!stream) { return; }
      try {
        var codes = await detector.detect(video);
        if (codes.length) {
          document.getElementById("qr-text").value = codes[0].rawValue;
          end();
          check(codes[0].rawValue);
          return;
        }
      } catch (e) { /* frame not ready yet */ }
      requestAnimationFrame(tick);
    }
    start.addEventListener("click", async function () {
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      } catch (e) {
        ready.textContent = "The camera could not be opened. Paste the QR text instead.";
        return;
      }
      video.srcObject = stream; video.hidden = false; stop.hidden = false; start.hidden = true;
      await video.play();
      tick();
    });
    stop.addEventListener("click", end);
  }

  document.getElementById("qr-check").addEventListener("click", function () {
    check(document.getElementById("qr-text").value);
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(function () { /* still works online */ });
  }

  loadKeys().then(function () {
    ready.textContent = "Ready. This page now works without a network.";
    setUpCamera();
  }).catch(function () {
    ready.textContent = "This browser cannot check signatures offline (it needs Ed25519 support), or the keys could not be loaded. Use the online check instead.";
    document.getElementById("qr-check").disabled = true;
  });
})();
