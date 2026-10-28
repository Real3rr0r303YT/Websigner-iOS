/*
 * WebSigner - in-browser front end for signing an IPA with GitHub Actions.
 *
 * Flow:
 *   1. The IPA, .p12 and .mobileprovision are checked locally in the browser.
 *   2. The .p12, its password and the profile are encrypted with the repo's
 *      public key (libsodium sealed box) and stored as Actions secrets.
 *   3. The IPA is encrypted with a random AES-256-CTR key (also a secret) and
 *      committed to a temporary branch.
 *   4. .github/workflows/sign.yml signs it with zsign, uploads it to the
 *      "websigner" release and commits signed/<id>.plist to the Pages branch.
 *   5. Once GitHub Pages serves the manifest, the itms-services:// install
 *      button and a QR code are shown.
 * Temporary secrets and the upload branch are deleted afterwards.
 *
 * Requires: vendor/jszip.min.js, vendor/forge.min.js, vendor/nacl-fast.min.js,
 *           vendor/sealedbox.js, vendor/qrcode.js, js/plist.js
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
(function () {
  "use strict";

  var API = "https://api.github.com";
  var WORKFLOW = "sign.yml";
  var RELEASE_TAG = "websigner";
  var SECRET_NAMES = ["WEBSIGNER_P12_BASE64", "WEBSIGNER_P12_PASSWORD", "WEBSIGNER_PROFILE_BASE64", "WEBSIGNER_UPLOAD_KEY"];
  var MAX_UPLOAD_BYTES = 95 * 1024 * 1024; // Git blob API limit is 100 MB
  var JOB_ID_RE = /^[a-z0-9]{8,32}$/;
  var TOKEN_KEY = "websigner.token";
  var REPO_KEY = "websigner.repo";

  var state = { ipa: null, p12: null, profile: null, busy: false };

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function fmtBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(1) + " MB";
  }

  function fmtDate(d) { return d.toISOString().slice(0, 10); }

  function daysUntil(d) { return Math.floor((d.getTime() - Date.now()) / 86400000); }

  function readFile(file) {
    return new Promise(function (resolve, reject) {
      var r = new FileReader();
      r.onload = function () { resolve(new Uint8Array(r.result)); };
      r.onerror = function () { reject(r.error); };
      r.readAsArrayBuffer(file);
    });
  }

  function bytesToBinary(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i += 8192) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
    }
    return s;
  }

  function bytesToBase64(bytes) { return btoa(bytesToBinary(bytes)); }

  function base64ToBytes(b64) {
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function hex(bytes) {
    return Array.prototype.map.call(bytes, function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }

  // Large files: let the browser do base64 natively instead of building strings.
  function blobToBase64(blob) {
    return new Promise(function (resolve, reject) {
      var r = new FileReader();
      r.onload = function () { resolve(r.result.slice(r.result.indexOf(",") + 1)); };
      r.onerror = function () { reject(r.error); };
      r.readAsDataURL(blob);
    });
  }

  function randomJobId() {
    var b = crypto.getRandomValues(new Uint8Array(8));
    return hex(b);
  }

  // ---------------------------------------------------------------------------
  // Local analysis
  // ---------------------------------------------------------------------------

  function provisioningType(p) {
    if (p.ProvisionsAllDevices) return "Enterprise";
    var devices = p.ProvisionedDevices || [];
    if (devices.length && p.Entitlements && p.Entitlements["get-task-allow"]) return "Development";
    if (devices.length) return "Ad Hoc";
    return "App Store";
  }

  function wildcardMatch(pattern, value) {
    var re = new RegExp("^" + pattern.split("*").map(function (s) {
      return s.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    }).join(".*") + "$");
    return re.test(value);
  }

  // Returns true if the arm64 slice is FairPlay-encrypted (App Store download).
  function machoEncrypted(bytes) {
    var dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    function thin(off) {
      if (dv.getUint32(off, true) !== 0xFEEDFACF) return null;
      var ncmds = dv.getUint32(off + 16, true);
      var p = off + 32;
      for (var i = 0; i < ncmds && p + 8 <= bytes.length; i++) {
        var cmd = dv.getUint32(p, true);
        var size = dv.getUint32(p + 4, true);
        if (cmd === 0x2C) return dv.getUint32(p + 16, true) !== 0; // LC_ENCRYPTION_INFO_64.cryptid
        if (size < 8) break;
        p += size;
      }
      return false;
    }
    var magic = dv.getUint32(0, false);
    if (magic === 0xCAFEBABE || magic === 0xCAFEBABF) {
      var n = dv.getUint32(4, false);
      var stride = magic === 0xCAFEBABE ? 20 : 32;
      for (var i = 0; i < n; i++) {
        var base = 8 + i * stride;
        if (dv.getInt32(base, false) !== 0x0100000C) continue; // arm64
        var off = magic === 0xCAFEBABE ? dv.getUint32(base + 8, false) : Number(dv.getBigUint64(base + 8, false));
        return thin(off);
      }
      return null;
    }
    return thin(0);
  }

  async function analyzeIPA(file) {
    var res = { file: file, errors: [], warnings: [], info: [] };
    if (file.size > MAX_UPLOAD_BYTES) {
      res.errors.push("The IPA is " + fmtBytes(file.size) + ". GitHub accepts at most " + fmtBytes(MAX_UPLOAD_BYTES) + " per upload.");
    }
    var zip;
    try {
      zip = await JSZip.loadAsync(file);
    } catch (e) {
      res.errors.push("Not a valid IPA/zip file (" + e.message + ").");
      return res;
    }
    var appDirs = {};
    zip.forEach(function (path) {
      var m = /^Payload\/([^/]+\.app)\//.exec(path);
      if (m) appDirs[m[1]] = true;
    });
    var apps = Object.keys(appDirs);
    if (apps.length !== 1) {
      res.errors.push(apps.length ? "More than one .app inside Payload/." : "No Payload/<Name>.app/ folder. This isn't a valid IPA.");
      return res;
    }
    var app = "Payload/" + apps[0] + "/";
    var infoEntry = zip.file(app + "Info.plist");
    if (!infoEntry) {
      res.errors.push("Info.plist is missing from " + app + ".");
      return res;
    }
    var info = WSPlist.parse(await infoEntry.async("uint8array"));
    res.bundleId = info.CFBundleIdentifier;
    res.version = info.CFBundleShortVersionString || info.CFBundleVersion || "?";
    res.build = info.CFBundleVersion || "?";
    res.name = info.CFBundleDisplayName || info.CFBundleName || apps[0].replace(/\.app$/, "");
    res.minOS = info.MinimumOSVersion;
    res.info.push(res.name + " " + res.version + " (" + res.build + ")");
    res.info.push("Bundle ID: " + res.bundleId);
    if (res.minOS) res.info.push("Requires iOS " + res.minOS + " or later");

    var platforms = info.CFBundleSupportedPlatforms || [];
    if (info.DTPlatformName === "iphonesimulator" || platforms.indexOf("iPhoneSimulator") !== -1) {
      res.errors.push("This is a Simulator build. It can't run on a real device.");
    }
    var exe = info.CFBundleExecutable && zip.file(app + info.CFBundleExecutable);
    if (!exe) {
      res.errors.push("The app executable (" + info.CFBundleExecutable + ") is missing.");
    } else {
      try {
        var enc = machoEncrypted(await exe.async("uint8array"));
        if (enc === null) res.warnings.push("Couldn't find an arm64 slice in the executable.");
        else if (enc) res.warnings.push("The app is FairPlay-encrypted (downloaded from the App Store). It will install, but crash on launch. Use a decrypted IPA.");
      } catch (e) {
        res.warnings.push("Couldn't inspect the executable (" + e.message + ").");
      }
    }
    return res;
  }

  async function analyzeProfile(file) {
    var res = { file: file, errors: [], warnings: [], info: [] };
    var bytes = await readFile(file);
    var p;
    try {
      p = WSPlist.extractFromCMS(bytes);
    } catch (e) {
      res.errors.push("Not a valid .mobileprovision file.");
      return res;
    }
    res.bytes = bytes;
    res.plist = p;
    res.type = provisioningType(p);
    res.devices = p.ProvisionedDevices || [];
    var ents = p.Entitlements || {};
    var appId = ents["application-identifier"] || "";
    var team = (p.TeamIdentifier && p.TeamIdentifier[0]) || appId.split(".")[0];
    res.appIdPattern = appId.indexOf(team + ".") === 0 ? appId.slice(team.length + 1) : appId;
    res.certs = (p.DeveloperCertificates || []).map(function (der) {
      try {
        return forge.pki.certificateFromAsn1(forge.asn1.fromDer(bytesToBinary(der)));
      } catch (e) {
        return null;
      }
    }).filter(Boolean);

    res.info.push((p.Name || "Profile") + " (" + res.type + ")");
    res.info.push("Team: " + (p.TeamName || "?") + " (" + team + ")");
    res.info.push("App ID: " + res.appIdPattern);
    if (res.type === "Enterprise") res.info.push("Any device can install");
    else res.info.push(res.devices.length + " registered device(s)");

    if (res.type === "App Store") {
      res.errors.push("This is an App Store distribution profile. It can't be used for direct installs. Use an Ad Hoc, Development or Enterprise profile.");
    }
    if (p.ExpirationDate instanceof Date) {
      var days = daysUntil(p.ExpirationDate);
      if (days < 0) res.errors.push("The profile expired on " + fmtDate(p.ExpirationDate) + ".");
      else if (days < 14) res.warnings.push("The profile expires in " + days + " day(s) (" + fmtDate(p.ExpirationDate) + ").");
      else res.info.push("Valid until " + fmtDate(p.ExpirationDate));
    }
    return res;
  }

  async function analyzeP12(file, password) {
    var res = { file: file, errors: [], warnings: [], info: [] };
    res.bytes = await readFile(file);
    try {
      var p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(bytesToBinary(res.bytes)), password);
      var certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
      var keyBags = (p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || [])
        .concat(p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] || []);
      if (!keyBags.length) res.errors.push("The .p12 contains no private key. Export the certificate together with its key from Keychain Access.");
      var certs = certBags.map(function (b) { return b.cert; }).filter(Boolean);
      var leaf = certs.filter(function (c) {
        return !(c.getExtension("basicConstraints") || {}).cA;
      })[0] || certs[0];
      if (!leaf) {
        res.errors.push("The .p12 contains no signing certificate.");
        return res;
      }
      res.cert = leaf;
      var cn = leaf.subject.getField("CN");
      res.info.push(cn ? cn.value : "Certificate");
      var days = daysUntil(leaf.validity.notAfter);
      if (days < 0) res.errors.push("The certificate expired on " + fmtDate(leaf.validity.notAfter) + ".");
      else if (days < 14) res.warnings.push("The certificate expires in " + days + " day(s).");
      else res.info.push("Valid until " + fmtDate(leaf.validity.notAfter));
    } catch (e) {
      if (/password|MAC could not be verified/i.test(e.message)) {
        res.errors.push("Wrong .p12 password.");
      } else {
        res.warnings.push("The .p12 couldn't be fully checked in the browser (" + e.message + "). zsign will check it during signing.");
      }
    }
    return res;
  }

  // Combines the three analyses into one verdict.
  function crossCheck() {
    var out = { errors: [], warnings: [], info: [], bundleId: null };
    var ipa = state.ipa, prof = state.profile, p12 = state.p12;
    if (p12 && p12.cert && prof && prof.certs) {
      var match = prof.certs.some(function (c) {
        return c.serialNumber === p12.cert.serialNumber;
      });
      if (!match) out.errors.push("The certificate in the .p12 isn't included in the provisioning profile. Use the profile created for this certificate.");
    }
    if (ipa && ipa.bundleId && prof && prof.appIdPattern) {
      if (wildcardMatch(prof.appIdPattern, ipa.bundleId)) {
        out.bundleId = ipa.bundleId;
      } else if (prof.appIdPattern.indexOf("*") === -1) {
        out.bundleId = prof.appIdPattern;
        out.info.push("The bundle ID will be changed to " + prof.appIdPattern + " to match the profile.");
      } else {
        out.errors.push("The profile's App ID (" + prof.appIdPattern + ") doesn't match the bundle ID " + ipa.bundleId + ". Set a matching bundle ID under Advanced.");
      }
    }
    var udid = $("ws-udid").value.trim();
    if (udid && prof && prof.type !== "Enterprise") {
      var has = prof.devices.some(function (d) { return d.toLowerCase() === udid.toLowerCase(); });
      if (has) out.info.push("Your device (" + udid + ") is in the profile.");
      else out.errors.push("Your device (" + udid + ") isn't in the profile. Register it, regenerate the profile and try again.");
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Rendering
  // ---------------------------------------------------------------------------

  function renderResult(container, res) {
    container.textContent = "";
    if (!res) return;
    function add(list, cls, icon) {
      list.forEach(function (msg) {
        var li = el("li", cls);
        li.appendChild(el("span", "ws-icon", icon));
        li.appendChild(el("span", null, msg));
        container.appendChild(li);
      });
    }
    add(res.errors, "ws-err", "✕");
    add(res.warnings, "ws-warn", "!");
    add(res.info, "ws-ok", "✓");
  }

  function effectiveBundleId(cc) {
    var override = $("ws-bundle-id").value.trim();
    return override || cc.bundleId || (state.ipa && state.ipa.bundleId) || "";
  }

  function refresh() {
    renderResult($("ws-ipa-result"), state.ipa);
    renderResult($("ws-p12-result"), state.p12);
    renderResult($("ws-profile-result"), state.profile);
    var cc = crossCheck();
    var override = $("ws-bundle-id").value.trim();
    if (override) {
      cc.errors = cc.errors.filter(function (e) { return e.indexOf("App ID") === -1; });
      cc.info = cc.info.filter(function (i) { return i.indexOf("bundle ID will be changed") === -1; });
      if (state.profile && state.profile.appIdPattern && !wildcardMatch(state.profile.appIdPattern, override)) {
        cc.errors.push("The bundle ID " + override + " doesn't match the profile's App ID (" + state.profile.appIdPattern + ").");
      }
    }
    renderResult($("ws-cross-result"), cc);

    var ready = state.ipa && state.p12 && state.profile &&
      !state.ipa.errors.length && !state.p12.errors.length && !state.profile.errors.length && !cc.errors.length;
    var hasRepo = /^[\w.-]+\/[\w.-]+$/.test($("ws-repo").value.trim());
    var hasToken = $("ws-token").value.trim().length > 10;
    $("ws-start").disabled = state.busy || !(ready && hasRepo && hasToken);
    var hint = !ready ? "Add a valid IPA, .p12 and provisioning profile." :
      !hasRepo ? "Enter your repository as owner/name." :
      !hasToken ? "Enter a GitHub access token." : "";
    $("ws-start-hint").textContent = state.busy ? "" : hint;
  }

  // ---------------------------------------------------------------------------
  // File inputs and drag & drop
  // ---------------------------------------------------------------------------

  function kindOf(file) {
    var n = file.name.toLowerCase();
    if (/\.ipa$/.test(n)) return "ipa";
    if (/\.(p12|pfx)$/.test(n)) return "p12";
    if (/\.mobileprovision$/.test(n)) return "profile";
    return null;
  }

  async function handleFiles(files, preferred) {
    for (var i = 0; i < files.length; i++) {
      var f = files[i];
      var kind = kindOf(f) || preferred;
      if (!kind) continue;
      var label = $("ws-" + kind + "-name");
      label.textContent = f.name + " · " + fmtBytes(f.size) + " · checking…";
      try {
        if (kind === "ipa") state.ipa = await analyzeIPA(f);
        else if (kind === "profile") state.profile = await analyzeProfile(f);
        else state.p12 = await analyzeP12(f, $("ws-p12-password").value);
      } catch (e) {
        state[kind] = { file: f, errors: ["Couldn't read the file: " + e.message], warnings: [], info: [] };
      }
      label.textContent = f.name + " · " + fmtBytes(f.size);
      $("ws-drop-" + kind).classList.add("has-file");
    }
    if (state.ipa) $("ws-display-name").placeholder = state.ipa.name || "";
    refresh();
  }

  function setupDropzone(kind) {
    var zone = $("ws-drop-" + kind);
    var input = $("ws-" + kind + "-input");
    input.addEventListener("change", function () {
      if (input.files.length) handleFiles(Array.from(input.files), kind);
      input.value = "";
    });
    ["dragenter", "dragover"].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add("drag"); });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.remove("drag"); });
    });
    zone.addEventListener("drop", function (e) {
      if (e.dataTransfer && e.dataTransfer.files.length) handleFiles(Array.from(e.dataTransfer.files), kind);
    });
  }

  // ---------------------------------------------------------------------------
  // GitHub API
  // ---------------------------------------------------------------------------

  function token() { return $("ws-token").value.trim(); }

  async function gh(method, path, body) {
    var res = await fetch(API + path, {
      method: method,
      headers: {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token(),
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json"
      },
      body: body === undefined ? undefined : (typeof body === "string" ? body : JSON.stringify(body)),
      cache: "no-store"
    });
    if (res.status === 204) return null;
    var text = await res.text();
    var data = text ? JSON.parse(text) : null;
    if (!res.ok) {
      var err = new Error((data && data.message) || ("HTTP " + res.status));
      err.status = res.status;
      throw err;
    }
    return data;
  }

  // Upload with progress (fetch can't report upload progress).
  function ghUpload(path, body, onProgress) {
    return new Promise(function (resolve, reject) {
      var xhr = new XMLHttpRequest();
      xhr.open("POST", API + path);
      xhr.setRequestHeader("Accept", "application/vnd.github+json");
      xhr.setRequestHeader("Authorization", "Bearer " + token());
      xhr.setRequestHeader("X-GitHub-Api-Version", "2022-11-28");
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.upload.onprogress = function (e) { if (e.lengthComputable) onProgress(e.loaded / e.total); };
      xhr.onload = function () {
        var data = null;
        try { data = JSON.parse(xhr.responseText); } catch (e) { /* ignore */ }
        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
        else reject(new Error((data && data.message) || ("HTTP " + xhr.status)));
      };
      xhr.onerror = function () { reject(new Error("Network error during upload")); };
      xhr.send(body);
    });
  }

  function pagesBaseFor(owner, repo) {
    if (repo.toLowerCase() === owner.toLowerCase() + ".github.io") return "https://" + repo.toLowerCase() + "/";
    return "https://" + owner.toLowerCase() + ".github.io/" + repo + "/";
  }

  // ---------------------------------------------------------------------------
  // Progress UI
  // ---------------------------------------------------------------------------

  var STEPS = [
    ["check", "Check repository access"],
    ["secrets", "Encrypt and store certificate"],
    ["upload", "Encrypt and upload IPA"],
    ["dispatch", "Start signing workflow"],
    ["sign", "Sign with zsign"],
    ["pages", "Publish install manifest"]
  ];

  function resetSteps() {
    var list = $("ws-steps");
    list.textContent = "";
    STEPS.forEach(function (s) {
      var li = el("li", "pending");
      li.id = "ws-step-" + s[0];
      li.appendChild(el("span", "ws-step-dot"));
      li.appendChild(el("span", "ws-step-label", s[1]));
      li.appendChild(el("span", "ws-step-detail"));
      list.appendChild(li);
    });
    list.hidden = false;
  }

  function step(id, status, detail) {
    var li = $("ws-step-" + id);
    if (!li) return;
    li.className = status;
    if (detail !== undefined) li.querySelector(".ws-step-detail").textContent = detail;
  }

  function showError(msg, link) {
    var box = $("ws-error");
    box.textContent = msg;
    if (link) {
      box.appendChild(document.createTextNode(" "));
      var a = el("a", null, "Open the workflow run");
      a.href = link;
      a.target = "_blank";
      a.rel = "noopener";
      box.appendChild(a);
    }
    box.hidden = false;
  }

  // ---------------------------------------------------------------------------
  // Main flow
  // ---------------------------------------------------------------------------

  async function start() {
    if (state.busy) return;
    var cc = crossCheck();
    var repoInput = $("ws-repo").value.trim();
    var parts = repoInput.split("/");
    var jobId = randomJobId();
    var uploadBranch = "websigner-upload/" + jobId;
    var current = "check";
    var repo, secretsStored = false, branchCreated = false, runUrl = null;

    state.busy = true;
    $("ws-error").hidden = true;
    $("ws-result").hidden = true;
    resetSteps();
    refresh();
    rememberSettings();

    try {
      // 1. Repository access
      step("check", "active");
      repo = await gh("GET", "/repos/" + parts[0] + "/" + parts[1]);
      if (repo.permissions && !repo.permissions.push) throw new Error("This token can't write to " + repo.full_name + ".");
      var base = "/repos/" + repo.full_name;
      try {
        await gh("GET", base + "/actions/workflows/" + WORKFLOW);
      } catch (e) {
        if (e.status === 404) throw new Error(".github/workflows/" + WORKFLOW + " isn't in " + repo.full_name + " on " + repo.default_branch + ".");
        throw e;
      }
      var active = await gh("GET", base + "/actions/workflows/" + WORKFLOW + "/runs?per_page=5&status=in_progress");
      var queued = await gh("GET", base + "/actions/workflows/" + WORKFLOW + "/runs?per_page=5&status=queued");
      if (active.total_count + queued.total_count > 0) throw new Error("Another signing job is still running. Wait for it to finish, then try again.");
      step("check", "done", repo.full_name);

      // 2. Secrets
      current = "secrets";
      step("secrets", "active");
      var key = await gh("GET", base + "/actions/secrets/public-key");
      var pub = base64ToBytes(key.key);
      var aesKey = crypto.getRandomValues(new Uint8Array(32));
      var iv = new Uint8Array(16);
      iv.set(crypto.getRandomValues(new Uint8Array(8)), 0); // low 64 bits stay 0: no counter wrap
      var secretValues = {
        WEBSIGNER_P12_BASE64: bytesToBase64(state.p12.bytes),
        WEBSIGNER_P12_PASSWORD: $("ws-p12-password").value,
        WEBSIGNER_PROFILE_BASE64: bytesToBase64(state.profile.bytes),
        WEBSIGNER_UPLOAD_KEY: hex(aesKey) + ":" + hex(iv)
      };
      secretsStored = true;
      for (var i = 0; i < SECRET_NAMES.length; i++) {
        var name = SECRET_NAMES[i];
        var sealed = sealedBox.seal(new TextEncoder().encode(secretValues[name]), pub);
        await gh("PUT", base + "/actions/secrets/" + name, { encrypted_value: bytesToBase64(sealed), key_id: key.key_id });
        step("secrets", "active", (i + 1) + "/" + SECRET_NAMES.length);
      }
      step("secrets", "done", "encrypted in your browser");

      // 3. Encrypted IPA upload to a temporary branch
      current = "upload";
      step("upload", "active", "encrypting…");
      var plain = await readFile(state.ipa.file);
      var digest = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", plain)));
      var cryptoKey = await crypto.subtle.importKey("raw", aesKey, "AES-CTR", false, ["encrypt"]);
      var cipher = await crypto.subtle.encrypt({ name: "AES-CTR", counter: iv, length: 64 }, cryptoKey, plain);
      plain = null;
      var b64 = await blobToBase64(new Blob([cipher]));
      cipher = null;
      var blob = await ghUpload(base + "/git/blobs", "{\"encoding\":\"base64\",\"content\":\"" + b64 + "\"}", function (f) {
        step("upload", "active", Math.round(f * 100) + "%");
      });
      b64 = null;
      var tree = await gh("POST", base + "/git/trees", { tree: [{ path: "upload.ipa.enc", mode: "100644", type: "blob", sha: blob.sha }] });
      var commit = await gh("POST", base + "/git/commits", { message: "WebSigner upload " + jobId, tree: tree.sha, parents: [] });
      await gh("POST", base + "/git/refs", { ref: "refs/heads/" + uploadBranch, sha: commit.sha });
      branchCreated = true;
      step("upload", "done", fmtBytes(state.ipa.file.size));

      // 4. Dispatch the workflow and find its run
      current = "dispatch";
      step("dispatch", "active");
      var bundleId = effectiveBundleId(cc);
      await gh("POST", base + "/actions/workflows/" + WORKFLOW + "/dispatches", {
        ref: repo.default_branch,
        inputs: {
          job_id: jobId,
          upload_branch: uploadBranch,
          sha256: digest,
          bundle_id: bundleId && bundleId !== state.ipa.bundleId ? bundleId : "",
          display_name: $("ws-display-name").value.trim()
        }
      });
      var run = null;
      for (var t = 0; t < 30 && !run; t++) {
        await sleep(3000);
        var runs = await gh("GET", base + "/actions/workflows/" + WORKFLOW + "/runs?event=workflow_dispatch&per_page=20");
        run = runs.workflow_runs.filter(function (r) { return r.display_title === "Sign " + jobId; })[0] || null;
      }
      if (!run) throw new Error("The workflow didn't start. Check that Actions are enabled for the repository.");
      runUrl = run.html_url;
      step("dispatch", "done");

      // 5. Wait for signing
      current = "sign";
      step("sign", "active", "queued");
      while (run.status !== "completed") {
        await sleep(5000);
        run = await gh("GET", base + "/actions/runs/" + run.id);
        try {
          var jobs = await gh("GET", base + "/actions/runs/" + run.id + "/jobs");
          var steps = (jobs.jobs[0] && jobs.jobs[0].steps) || [];
          var running = steps.filter(function (s) { return s.status === "in_progress"; })[0];
          step("sign", "active", running ? running.name : run.status.replace("_", " "));
        } catch (e) { /* progress detail is optional */ }
      }
      if (run.conclusion !== "success") throw new Error("Signing failed (" + run.conclusion + ").");
      step("sign", "done", "");

      // 6. Wait until GitHub Pages serves the manifest
      current = "pages";
      var pagesBase = pagesBaseFor(repo.owner.login, repo.name);
      try {
        var pages = await gh("GET", base + "/pages");
        if (pages && pages.html_url) pagesBase = pages.html_url.replace(/\/?$/, "/");
      } catch (e) { /* token may lack Pages access; use the default URL */ }
      var manifestUrl = pagesBase + "signed/" + jobId + ".plist";
      var started = Date.now(), rebuildRequested = false;
      for (;;) {
        var waited = Math.round((Date.now() - started) / 1000);
        step("pages", "active", "waiting for GitHub Pages (" + waited + "s)");
        try {
          var head = await fetch(manifestUrl + "?t=" + Date.now(), { method: "GET", cache: "no-store" });
          if (head.ok) break;
        } catch (e) { /* not there yet */ }
        if (!rebuildRequested && waited > 90) {
          rebuildRequested = true;
          gh("POST", base + "/pages/builds").catch(function () {});
        }
        if (waited > 600) throw new Error("GitHub Pages didn't publish " + manifestUrl + " within 10 minutes. Check Settings → Pages.");
        await sleep(6000);
      }
      step("pages", "done", "published");
      showInstall(jobId, manifestUrl, pagesBase, run.html_url);
    } catch (e) {
      step(current, "failed", e.message);
      showError(e.message, runUrl);
    } finally {
      // Clean up: secrets and the upload branch are only needed by the run.
      if (repo) {
        var cleanupBase = "/repos/" + repo.full_name;
        if (secretsStored) {
          for (var s = 0; s < SECRET_NAMES.length; s++) {
            await gh("DELETE", cleanupBase + "/actions/secrets/" + SECRET_NAMES[s]).catch(function () {});
          }
        }
        if (branchCreated) {
          await gh("DELETE", cleanupBase + "/git/refs/heads/" + uploadBranch).catch(function () {});
        }
      }
      state.busy = false;
      refresh();
    }
  }

  // ---------------------------------------------------------------------------
  // Install panel (also used for ?install=<id> links)
  // ---------------------------------------------------------------------------

  function itmsLink(manifestUrl) {
    return "itms-services://?action=download-manifest&url=" + encodeURIComponent(manifestUrl);
  }

  function showInstall(jobId, manifestUrl, pagesBase, runUrl) {
    var shareUrl = pagesBase + "?install=" + jobId;
    $("ws-install-btn").href = itmsLink(manifestUrl);
    $("ws-share-link").href = shareUrl;
    $("ws-share-link").textContent = shareUrl;
    $("ws-manifest-link").href = manifestUrl;
    if (runUrl) {
      $("ws-run-link").href = runUrl;
      $("ws-run-link").hidden = false;
    }
    var qr = qrcode(0, "M");
    qr.addData(shareUrl);
    qr.make();
    $("ws-qr").innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
    $("ws-result").hidden = false;
    $("ws-result").scrollIntoView({ behavior: "smooth", block: "center" });
  }

  async function handleInstallParam() {
    var id = new URLSearchParams(location.search).get("install");
    if (!id || !JOB_ID_RE.test(id)) return;
    var manifestUrl = new URL("signed/" + id + ".plist", location.href).href;
    var panel = $("ws-install-panel");
    $("ws-install-direct").href = itmsLink(manifestUrl);
    panel.hidden = false;
    try {
      var r = await fetch(manifestUrl, { cache: "no-store" });
      if (!r.ok) throw new Error();
      var m = WSPlist.parse(new Uint8Array(await r.arrayBuffer())).items[0].metadata;
      $("ws-install-title").textContent = "Install " + m.title + " " + m["bundle-version"];
    } catch (e) {
      $("ws-install-title").textContent = "This install link isn't available (yet).";
      $("ws-install-direct").classList.add("disabled");
    }
  }

  // ---------------------------------------------------------------------------
  // Settings
  // ---------------------------------------------------------------------------

  function storage(remember) {
    try { return remember ? localStorage : sessionStorage; } catch (e) { return null; }
  }

  function rememberSettings() {
    var remember = $("ws-remember").checked;
    try {
      localStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(TOKEN_KEY);
      localStorage.setItem(REPO_KEY, $("ws-repo").value.trim());
    } catch (e) { /* storage unavailable */ }
    var s = storage(remember);
    if (s) try { s.setItem(TOKEN_KEY, token()); } catch (e) { /* ignore */ }
  }

  function loadSettings() {
    var repo = null, tok = null, remembered = false;
    try {
      repo = localStorage.getItem(REPO_KEY);
      tok = localStorage.getItem(TOKEN_KEY);
      remembered = !!tok;
      tok = tok || sessionStorage.getItem(TOKEN_KEY);
    } catch (e) { /* storage unavailable */ }
    if (!repo && /\.github\.io$/i.test(location.hostname)) {
      var owner = location.hostname.split(".")[0];
      var first = location.pathname.split("/").filter(Boolean)[0];
      repo = owner + "/" + (first && !/\.html?$/.test(first) ? first : owner + ".github.io");
    }
    if (repo) $("ws-repo").value = repo;
    if (tok) $("ws-token").value = tok;
    $("ws-remember").checked = remembered;
  }

  function init() {
    if (!$("ws-start")) return;
    ["ipa", "p12", "profile"].forEach(setupDropzone);
    $("ws-p12-password").addEventListener("change", function () {
      if (state.p12) handleFiles([state.p12.file], "p12");
    });
    ["ws-repo", "ws-token", "ws-bundle-id", "ws-udid"].forEach(function (id) {
      $(id).addEventListener("input", refresh);
    });
    $("ws-remember").addEventListener("change", function () {
      if (!$("ws-remember").checked) {
        try { localStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ }
      }
    });
    $("ws-start").addEventListener("click", start);
    window.addEventListener("beforeunload", function (e) {
      if (state.busy) { e.preventDefault(); e.returnValue = ""; }
    });
    loadSettings();
    refresh();
    handleInstallParam();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
