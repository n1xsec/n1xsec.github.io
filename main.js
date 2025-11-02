/* ========================================================================
   istria.dev - AntiMonkey v1.3 (debuggable, multi-realm, 40+ heuristics)
   - Adds 10 new checks (bind/indirect eval/new Function/Request/Response/Headers/
     MessageChannel/PerformanceObserver/History/attachShadow/Permissions/Clipboard)
   - Adds a site-level watchdog (heartbeat + expectation markers) and 'watchdogMissing'
   - Fresh-iframe + Worker realm anti-masking; rich debug groups/tables; rescans
   ======================================================================== */

(() => {
  "use strict";

  // ----------------- tiny utils -----------------
  const now = () => (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  const rand = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const isFn = (x) => typeof x === "function";
  const NATIVE_RX = /\[native code\]/i;

  const looksNative = (fn) => {
    try {
      if (!isFn(fn)) return false;
      const s = Function.prototype.toString.call(fn);
      return NATIVE_RX.test(s);
    } catch { return false; }
  };

  const safeDesc = (obj, k) => { try { return Object.getOwnPropertyDescriptor(obj, k) || null; } catch { return null; } };
  const appendHidden = (el) => {
    try {
      el.style.cssText = "position:absolute;left:-99999px;top:-99999px;width:1px;height:1px;opacity:0;pointer-events:none;";
      (document.body || document.documentElement).appendChild(el);
      return true;
    } catch { return false; }
  };

  const LS = {
    set(k, v){ try { localStorage.setItem(k, JSON.stringify(v)); } catch{} },
    get(k, d){ try { const x = localStorage.getItem(k); return x == null ? d : JSON.parse(x); } catch { return d; } }
  };

  // Known extension IDs (precision lists; Firefox handled via moz-extension marker)
  const KNOWN_IDS = {
    chrome: {
      tampermonkey: ["dhdgffkkebhmkfjojejmpbldmpobfkfo"],
      violentmonkey: ["jinjaccalgkegednnccohejagnlnfdag"]
    },
    edge: {
      tampermonkey: ["iikmkjmpaadaobahmlepeloendndfphd"],
      violentmonkey: ["eeagobfjdenkkddmbclomhiblgggliao"]
    },
    opera: {
      tampermonkey: ["iikmkjmpaadaobahmlepeloendndfphd","dhdgffkkebhmkfjojejmpbldmpobfkfo"],
      violentmonkey: ["jinjaccalgkegednnccohejagnlnfdag"]
    },
    firefox: { tampermonkey:["moz-extension"], violentmonkey:["moz-extension"], greasemonkey:["moz-extension"] }
  };

  const EXT_RESOURCES = [
    "/images/icon128.png","/icons/icon128.png","/assets/icon128.png",
    "/images/icon48.png","/assets/logo.png","/manifest.json"
  ];

  // Precision targeting for Edge Tampermonkey
  const EDGE_TM_ID = "iikmkjmpaadaobahmlepeloendndfphd";
  const EDGE_TM_PATHS = [
    "/userscript.html",
    "/userscript.html?name=",
    "/options.html",
    "/assets/icon128.png",
    "/images/icon128.png",
    "/icons/icon128.png",
    "/manifest.json"
  ];

  // Weights (existing + new + watchdog)
  const DEFAULT_WEIGHTS = {
    probeExtensionImage: 12,
    probeExtensionStylesheet: 10,
    scanResourceTimings: 6,
    scanDOMForExtensionScripts: 10,
    scanStylesForExtensionHrefs: 8,
    detectXHRHook: 6,
    detectFetchHook: 6,
    detectWebSocketHook: 4,
    detectConsoleHook: 8,
    detectToStringTamper: 6,
    mutationScriptTrap: 5,
    baitAdRemovalTrap: 5,
    timingAnomaly: 3,
    checkWindowProps: 6,
    stackMozExtensionLeak: 10,
    detectExtensionIframes: 8,

    // anti-masking from v1.1
    freshToStringMismatch: 18,
    crossRealmConsoleProbe: 16,
    descriptorWeirdness: 8,

    // v1.2 (kept)
    detectEvalHook: 8,
    detectSetTimeoutHook: 6,
    detectRAFHook: 5,
    detectAddEventListenerHook: 8,
    detectNodeAppendHook: 8,
    detectCreateElementHook: 6,
    detectMutationObserverHook: 8,
    detectCSSInsertRuleHook: 6,
    freshBoundConsoleProbe: 12,
    workerRealmToStringDrift: 12,
    multiAdBaitPlus: 4,
    probeEdgeTampermonkeyUserscript: 20,

    // v1.3 NEW (10)
    detectIndirectEvalHook: 8,
    detectNewFunctionHook: 8,
    detectBindHook: 6,
    detectRequestResponseHeadersHook: 10,
    detectMessageChannelHook: 5,
    detectPerformanceObserverHook: 6,
    detectHistoryHook: 5,
    detectAttachShadowHook: 6,
    detectPermissionsHook: 6,
    detectClipboardHook: 4,

    // Watchdog
    watchdogMissing: 16
  };

  class AntiMonkey {
    static start(opts = {}) { const inst = new AntiMonkey(opts); inst.init(); return inst; }

    constructor(opts = {}) {
      this.opts = {
        weights: { ...DEFAULT_WEIGHTS, ...(opts.weights || {}) },
        continuous: opts.continuous !== false,
        intervalMinMs: opts.intervalMinMs || 4500,
        intervalMaxMs: opts.intervalMaxMs || 9000,
        runOnReadyState: opts.runOnReadyState || "interactive",
        onDetect: isFn(opts.onDetect) ? opts.onDetect : null,
        onScore: isFn(opts.onScore) ? opts.onScore : null,
        maxLog: opts.maxLog || 800,
        debug: !!opts.debug,
        threshold: typeof opts.threshold === "number" ? opts.threshold : 35,
        watchdog: {
          enable: opts.watchdog?.enable !== false,
          // if the page includes <meta name="istria-am-expected" content="1"> or any <script data-istria-am>
          // and heartbeat is missing/stale, raise watchdogMissing
          staleMs: opts.watchdog?.staleMs || 15000
        }
      };
      this.log = [];
      this.findings = [];
      this.listeners = new Set();
      this.timer = null; this.destroyed = false;

      // traps/baits
      this._mo = null; this._bait = null; this._adBait = null; this._adBait2 = null;
      this._lastPayload = null;

      // watchdog state
      this._hbTimer = null;
      this._hbKey = "istria.am.hb";
      this._verKey = "istria.am.version";
      this._ver = "v1.3";
    }

    // ---------------- lifecycle ----------------
    init() {
      const go = async () => {
        this._dinfo("init: DOM ready");
        this._watchdogStart();     // start heartbeat early
        await this.runAll();
        if (this.opts.continuous) this._loop();
      };
      const s = document.readyState;
      (s === "complete" || s === "interactive") ? go() :
        document.addEventListener("readystatechange", () => {
          if (document.readyState === this.opts.runOnReadyState) go();
        }, { once: true });
    }

    destroy() { this.destroyed = true; if (this.timer) clearTimeout(this.timer); try { this._mo?.disconnect(); } catch{} if (this._hbTimer) clearInterval(this._hbTimer); }

    on(fn) { if (isFn(fn)) this.listeners.add(fn); return () => this.listeners.delete(fn); }
    _emit(p) { this._lastPayload = p; for (const l of this.listeners) try { l(p); } catch{} if (this.opts.onScore) try { this.opts.onScore(p);}catch{} if (p.suspected && this.opts.onDetect) try { this.opts.onDetect(p);}catch{} }
    lastReport(){ return this._lastPayload; }

    _loop() {
      if (this.destroyed) return;
      const ms = rand(this.opts.intervalMinMs, this.opts.intervalMaxMs);
      this._dinfo(`next scan in ${ms}ms`);
      this.timer = setTimeout(async () => { await this.runAll(); this._loop(); }, ms);
    }

    _l(level, msg, extra) {
      const e = { t: Date.now(), level, msg, extra: extra ?? null };
      this.log.push(e); if (this.log.length > this.opts.maxLog) this.log.shift();
      if (this.opts.debug) {
        const tag = `%c[AntiMonkey:${level}]`;
        const style = level === "error" ? "color:#ff5252" : level === "warn" ? "color:#ffb54c" : level === "debug" ? "color:#8ab4f8" : "color:#9be29b";
        try { console.log(tag, style, msg, extra ?? ""); } catch {}
      }
    }
    _dinfo(m,x){ this._l("info",m,x); }
    _dwarn(m,x){ this._l("warn",m,x); }
    _derr(m,x){ this._l("error",m,x); }
    _d(m,x){ this._l("debug",m,x); }

    _addFinding(id, passed, evidence, weightKey) {
      const weight = this.opts.weights[weightKey] || 0;
      const f = { id, weightKey, weight, passed: !!passed, score: passed ? weight : 0, ts: Date.now(), evidence };
      this.findings.push(f);
      if (this.opts.debug) this._debugPrintFinding(f);
      return f;
    }

    _aggregate() {
      const latest = new Map();
      for (let i = this.findings.length - 1; i >= 0; i--) if (!latest.has(this.findings[i].id)) latest.set(this.findings[i].id, this.findings[i]);
      const items = Array.from(latest.values());
      const total = items.reduce((a,b)=>a+b.weight,0)||1;
      const gained = items.reduce((a,b)=>a+(b.passed?b.weight:0),0);
      const score = clamp(Math.round(100*(gained/total)),0,100);
      const suspected = score >= this.opts.threshold;
      return { items, score, suspected, gained, total };
    }

    async runAll() {
      const t0 = now();
      this._prepareMutationBait(); this._prepareAdBait(); this._prepareAdBaitPlus();

      const tasks = [
        // ----- legacy + core
        this._probeExtensionImage(),
        this._probeExtensionStylesheet(),
        this._scanResourceTimings(),
        this._scanDOMForExtensionScripts(),
        this._scanStylesForExtensionHrefs(),
        this._detectXHRHook(),
        this._detectFetchHook(),
        this._detectWebSocketHook(),
        this._detectConsoleHook(),
        this._detectToStringTamper(),
        this._mutationScriptTrapCheck(),
        this._baitAdRemovalTrapCheck(),
        this._timingAnomalyCheck(),
        this._checkWindowProps(),
        this._stackMozExtensionLeak(),
        this._detectExtensionIframes(),

        // anti-masking (v1.1)
        this._freshToStringMismatch(),
        this._crossRealmConsoleProbe(),
        this._descriptorWeirdness(),

        // v1.2 set
        this._detectEvalHook(),
        this._detectSetTimeoutHook(),
        this._detectRAFHook(),
        this._detectAddEventListenerHook(),
        this._detectNodeAppendHook(),
        this._detectCreateElementHook(),
        this._detectMutationObserverHook(),
        this._detectCSSInsertRuleHook(),
        this._freshBoundConsoleProbe(),
        this._workerRealmToStringDrift(),
        this._multiAdBaitPlusCheck(),

        // precision: Edge TM userscript page/resources
        this._probeEdgeTampermonkeyUserscript(),

        // v1.3 NEW (10)
        this._detectIndirectEvalHook(),
        this._detectNewFunctionHook(),
        this._detectBindHook(),
        this._detectRequestResponseHeadersHook(),
        this._detectMessageChannelHook(),
        this._detectPerformanceObserverHook(),
        this._detectHistoryHook(),
        this._detectAttachShadowHook(),
        this._detectPermissionsHook(),
        this._detectClipboardHook(),

        // Watchdog presence (runs every cycle)
        this._watchdogPresenceCheck()
      ];

      const settled = await Promise.allSettled(tasks);
      const res = [];
      for (const s of settled) if (s.status === "fulfilled" && s.value) res.push(...(Array.isArray(s.value)?s.value:[s.value]));

      const agg = this._aggregate();
      const dt = Math.max(1, Math.round(now() - t0));
      const payload = { score: agg.score, suspected: agg.suspected, findings: agg.items, gained: agg.gained, total: agg.total, durationMs: dt, timestamp: Date.now() };

      this._debugReport(payload);
      this._emit(payload);
      return payload;
    }

    // ---------------- debug pretty printing ----------------
    _debugPrintFinding(f) {
      try {
        const icon = f.passed ? "🟥" : "⬜";
        const hdr = `${icon} ${f.id}  (+${f.passed ? f.weight : 0}/${f.weight})`;
        console.groupCollapsed(`%c${hdr}`, f.passed ? "color:#ff7675" : "color:#8ab4f8");
        console.log("weightKey:", f.weightKey, "passed:", f.passed, "weight:", f.weight, "score:", f.score, "ts:", new Date(f.ts).toISOString());
        if (f.evidence && typeof f.evidence === "object") {
          try { console.table(f.evidence); } catch { console.log(f.evidence); }
        } else {
          console.log(f.evidence);
        }
        console.groupEnd();
      } catch {}
    }

    _debugReport(payload) {
      if (!this.opts.debug) return;
      try {
        const color = payload.suspected ? "background:#2b090b;color:#ffb3b3;padding:2px 6px;border-radius:6px" : "background:#0c2a12;color:#a3f2b6;padding:2px 6px;border-radius:6px";
        console.group(`%cAntiMonkey scan: score=${payload.score} suspected=${payload.suspected} (${payload.gained}/${payload.total}) in ${payload.durationMs}ms`, color);
        const tableData = payload.findings.map(f => ({ id: f.id, passed: f.passed, weight: f.weight, score: f.score }));
        console.table(tableData);
        console.groupEnd();
      } catch {}
    }

    // ---------------- core heuristics (unchanged) ----------------
    async _probeExtensionImage() {
      const evid = [], hits = [];
      const allIds = [
        ...KNOWN_IDS.chrome.tampermonkey, ...KNOWN_IDS.chrome.violentmonkey,
        ...KNOWN_IDS.edge.tampermonkey, ...KNOWN_IDS.edge.violentmonkey,
        ...KNOWN_IDS.opera.tampermonkey, ...KNOWN_IDS.opera.violentmonkey
      ];
      const tryId = (id) => new Promise(resolve => {
        try {
          const img = new Image();
          let done = false; const path = EXT_RESOURCES[rand(0, EXT_RESOURCES.length-1)];
          img.onload = () => { if (!done) { done = true; resolve({ id, ok:true, path }); } };
          img.onerror = () => { if (!done) { done = true; resolve({ id, ok:false, path }); } };
          img.src = `chrome-extension://${id}${path}?r=${Math.random()}`;
          setTimeout(() => { if (!done) { done = true; resolve({ id, ok:false, path, timeout:true }); } }, 1200);
        } catch { resolve({ id, ok:false, error:true }); }
      });
      const res = await Promise.all(allIds.map(tryId));
      for (const r of res) if (r.ok) { evid.push(`image:${r.id}${r.path}`); hits.push(r.id); }
      return this._addFinding("probeExtensionImage", hits.length>0, { hits, evid }, "probeExtensionImage");
    }

    async _probeExtensionStylesheet() {
      const evid = [], hits = [];
      const allIds = [
        ...KNOWN_IDS.chrome.tampermonkey, ...KNOWN_IDS.chrome.violentmonkey,
        ...KNOWN_IDS.edge.tampermonkey, ...KNOWN_IDS.edge.violentmonkey,
        ...KNOWN_IDS.opera.tampermonkey, ...KNOWN_IDS.opera.violentmonkey
      ];
      const tryId = (id) => new Promise(resolve => {
        let link;
        try {
          link = document.createElement("link"); link.rel = "stylesheet";
          let done = false; const path = EXT_RESOURCES[rand(0, EXT_RESOURCES.length-1)];
          link.onload = () => { if (!done) { done = true; cleanup(); resolve({ id, ok:true, path }); } };
          link.onerror = () => { if (!done) { done = true; cleanup(); resolve({ id, ok:false, path }); } };
          link.href = `chrome-extension://${id}${path}?r=${Math.random()}`;
          document.documentElement.appendChild(link);
          function cleanup(){ try{link.remove();}catch{} }
          setTimeout(() => { if (!done) { done = true; cleanup(); resolve({ id, ok:false, path, timeout:true }); } }, 1200);
        } catch { resolve({ id, ok:false, error:true }); }
      });
      const res = await Promise.all(allIds.map(tryId));
      for (const r of res) if (r.ok) { evid.push(`css:${r.id}${r.path}`); hits.push(r.id); }
      return this._addFinding("probeExtensionStylesheet", hits.length>0, { hits, evid }, "probeExtensionStylesheet");
    }

    async _scanResourceTimings() {
      try {
        const entries = performance.getEntriesByType("resource") || [];
        const ext = entries.filter(e => typeof e.name === "string" && (e.name.startsWith("chrome-extension://") || e.name.startsWith("moz-extension://"))).map(e => e.name);
        return this._addFinding("scanResourceTimings", ext.length>0, { ext }, "scanResourceTimings");
      } catch { return this._addFinding("scanResourceTimings", false, { error:true }, "scanResourceTimings"); }
    }

    async _scanDOMForExtensionScripts() {
      try {
        const hits = Array.from(document.scripts).map(s => s.src||"").filter(src => src.startsWith("chrome-extension://") || src.startsWith("moz-extension://"));
        return this._addFinding("scanDOMForExtensionScripts", hits.length>0, { hits }, "scanDOMForExtensionScripts");
      } catch { return this._addFinding("scanDOMForExtensionScripts", false, { error:true }, "scanDOMForExtensionScripts"); }
    }

    async _scanStylesForExtensionHrefs() {
      try {
        const hits = [];
        for (const sh of Array.from(document.styleSheets||[])) {
          const href = sh && sh.href || "";
          if (href && (href.startsWith("chrome-extension://") || href.startsWith("moz-extension://"))) hits.push(href);
        }
        return this._addFinding("scanStylesForExtensionHrefs", hits.length>0, { hits }, "scanStylesForExtensionHrefs");
      } catch { return this._addFinding("scanStylesForExtensionHrefs", false, { error:true }, "scanStylesForExtensionHrefs"); }
    }

    async _detectXHRHook() {
      try {
        const o = XMLHttpRequest && XMLHttpRequest.prototype;
        const openLooks = o && looksNative(o.open);
        const sendLooks = o && looksNative(o.send);
        return this._addFinding("detectXHRHook", !(openLooks && sendLooks), { openLooks, sendLooks }, "detectXHRHook");
      } catch { return this._addFinding("detectXHRHook", false, { error:true }, "detectXHRHook");}
    }

    async _detectFetchHook() {
      try {
        const fetchNative = looksNative(window.fetch);
        return this._addFinding("detectFetchHook", !fetchNative, { fetchNative }, "detectFetchHook");
      } catch { return this._addFinding("detectFetchHook", false, { error:true }, "detectFetchHook"); }
    }

    async _detectWebSocketHook() {
      try {
        const ctorNative = looksNative(window.WebSocket);
        const sendNative = window.WebSocket && window.WebSocket.prototype && looksNative(window.WebSocket.prototype.send);
        return this._addFinding("detectWebSocketHook", !(ctorNative && sendNative), { ctorNative, sendNative }, "detectWebSocketHook");
      } catch { return this._addFinding("detectWebSocketHook", false, { error:true }, "detectWebSocketHook"); }
    }

    async _detectConsoleHook() {
      try {
        const c = console||{};
        const hooks = ["log","warn","error","debug","info","table","trace","group","groupCollapsed","groupEnd"].map(k => ({k, native: looksNative(c[k])}));
        const anyNon = hooks.some(h => !h.native);
        return this._addFinding("detectConsoleHook", anyNon, { hooks }, "detectConsoleHook");
      } catch { return this._addFinding("detectConsoleHook", false, { error:true }, "detectConsoleHook"); }
    }

    async _detectToStringTamper() {
      try {
        const ts = Function.prototype.toString;
        const tsNative = looksNative(ts);
        const baseNative = NATIVE_RX.test(Function.prototype.toString.call(Object.prototype.toString));
        return this._addFinding("detectToStringTamper", !(tsNative && baseNative), { tsNative, baseNative }, "detectToStringTamper");
      } catch { return this._addFinding("detectToStringTamper", false, { error:true }, "detectToStringTamper"); }
    }

    _prepareMutationBait() {
      if (this._mo) return;
      try {
        const bait = document.createElement("div");
        bait.id=`tm-bait-${Math.random().toString(36).slice(2)}`; bait.setAttribute("data-bait","script-injection");
        bait.innerHTML="<span style='display:none'>bait</span>";
        appendHidden(bait); this._bait = bait;

        const mo = new MutationObserver((muts) => {
          for (const m of muts) {
            if (m.type === "childList") {
              for (const n of Array.from(m.addedNodes||[])) try{
                const tag = n.tagName?.toLowerCase()||"";
                if (tag==="script") {
                  const src = n.src||"";
                  if (src.startsWith("chrome-extension://") || src.startsWith("moz-extension://"))
                    this._addFinding("mutationScriptTrap", true, { src }, "mutationScriptTrap");
                }
              }catch{}
            }
          }
        });
        mo.observe(document.documentElement || document.body, { childList:true, subtree:true, attributes:true, attributeFilter:["src","href","class","data-*"] });
        this._mo = mo;
      } catch(e) { this._dwarn("mutation observer unavailable", e); }
    }

    async _mutationScriptTrapCheck() {
      try {
        const hit = Array.from(document.scripts).find(s => (s.src||"").startsWith("chrome-extension://") || (s.src||"").startsWith("moz-extension://"));
        return this._addFinding("mutationScriptTrap", !!hit, { preScanHit: !!hit, src: hit?.src ?? null }, "mutationScriptTrap");
      } catch { return this._addFinding("mutationScriptTrap", false, { error:true }, "mutationScriptTrap"); }
    }

    _prepareAdBait() {
      if (this._adBait) return;
      try {
        const b = document.createElement("div");
        b.id=`ad-banner-${Math.random().toString(36).slice(2)}`;
        b.className="ad ad-banner adsbox"; b.textContent="advertisement";
        appendHidden(b); this._adBait = b;
      } catch {}
    }

    async _baitAdRemovalTrapCheck() {
      try {
        if (!this._adBait) return this._addFinding("baitAdRemovalTrap", false, { prepared:false }, "baitAdRemovalTrap");
        const cs = getComputedStyle(this._adBait);
        const hidden = cs && (cs.display==="none"||cs.visibility==="hidden"||cs.opacity==="0");
        const r = this._adBait.getBoundingClientRect();
        const collapsed = r.width===0 || r.height===0;
        const removed = !document.documentElement.contains(this._adBait);
        return this._addFinding("baitAdRemovalTrap", (hidden||collapsed||removed), { hidden, collapsed, removed }, "baitAdRemovalTrap");
      } catch { return this._addFinding("baitAdRemovalTrap", false, { error:true }, "baitAdRemovalTrap"); }
    }

    async _timingAnomalyCheck() {
      try {
        const samples=8, deltas=[]; let last=now();
        for (let i=0;i<samples;i++) { await new Promise(r=>setTimeout(r,0)); const t=now(); deltas.push(t-last); last=t; }
        const avg = deltas.reduce((a,b)=>a+b,0)/Math.max(1,deltas.length);
        const spikes = deltas.filter(d=>d>8).length;
        return this._addFinding("timingAnomaly", (avg>4 && spikes>=2), { avg, spikes, deltas }, "timingAnomaly");
      } catch { return this._addFinding("timingAnomaly", false, { error:true }, "timingAnomaly"); }
    }

    async _checkWindowProps() {
      try {
        const keys=["GM_info","GM","GM_addStyle","GM_getValue","unsafeWindow","Violentmonkey","VM","Tampermonkey","cloneInto","exportFunction"];
        const present = keys.filter(k => { try { return k in window; } catch { return false; }});
        return this._addFinding("checkWindowProps", present.length>0, { present }, "checkWindowProps");
      } catch { return this._addFinding("checkWindowProps", false, { error:true }, "checkWindowProps"); }
    }

    async _stackMozExtensionLeak() {
      try {
        const err = new Error("__am_stack_probe__");
        const stack = (err.stack||"")+""; // Safari-friendly
        const hit = /moz-extension:\/\//i.test(stack) || /chrome-extension:\/\//i.test(stack);
        return this._addFinding("stackMozExtensionLeak", hit, { stack: hit ? stack.slice(0,400) : null }, "stackMozExtensionLeak");
      } catch { return this._addFinding("stackMozExtensionLeak", false, { error:true }, "stackMozExtensionLeak"); }
    }

    async _detectExtensionIframes() {
      try {
        const hits = Array.from(document.getElementsByTagName("iframe")).map(f => f.src||"").filter(src => src.startsWith("chrome-extension://") || src.startsWith("moz-extension://"));
        return this._addFinding("detectExtensionIframes", hits.length>0, { hits }, "detectExtensionIframes");
      } catch { return this._addFinding("detectExtensionIframes", false, { error:true }, "detectExtensionIframes"); }
    }

    // --------------- anti-masking (fresh realms) ---------------
    async _withFreshRealm(cb) {
      return new Promise((resolve) => {
        const f = document.createElement("iframe");
        f.style.display="none";
        f.srcdoc = "<!doctype html><meta charset=utf-8>";
        f.onload = () => {
          try { const w = f.contentWindow; resolve(cb(w)); }
          catch (e) { resolve({ error:true, msg: String(e) }); }
          finally { try { f.remove(); } catch{} }
        };
        document.documentElement.appendChild(f);
      });
    }

    async _freshToStringMismatch() {
      try {
        const r = await this._withFreshRealm((fw) => {
          const freshTS = fw.Function.prototype.toString;
          const localTS = Function.prototype.toString;
          const eq = freshTS === localTS;
          const freshNative = NATIVE_RX.test(freshTS.call(localTS));
          const localAsSeenByFresh = NATIVE_RX.test(freshTS.call(freshTS));
          return { eq, freshNative, localAsSeenByFresh };
        });
        const passed = !!(r && (!r.eq || (r.freshNative && !r.localAsSeenByFresh)));
        return this._addFinding("freshToStringMismatch", passed, r, "freshToStringMismatch");
      } catch { return this._addFinding("freshToStringMismatch", false, { error:true }, "freshToStringMismatch"); }
    }

    async _crossRealmConsoleProbe() {
      try {
        const r = await this._withFreshRealm((fw) => {
          const sFreshOnPage = fw.Function.prototype.toString.call(console.log);
          const sLocal = Function.prototype.toString.call(console.log);
          const sFreshOnFresh = fw.Function.prototype.toString.call(fw.console.log);
          const looksNativeFreshOnPage = NATIVE_RX.test(sFreshOnPage);
          const looksNativeLocal = NATIVE_RX.test(sLocal);
          const looksNativeFreshOnFresh = NATIVE_RX.test(sFreshOnFresh);
          const mismatch = (sFreshOnPage !== sLocal) || !looksNativeFreshOnFresh;
          return { sFreshOnPage, sLocal, sFreshOnFresh, looksNativeFreshOnPage, looksNativeLocal, looksNativeFreshOnFresh, mismatch };
        });
        const passed = !!(r && (r.mismatch || (r.looksNativeFreshOnPage && !r.looksNativeLocal)));
        return this._addFinding("crossRealmConsoleProbe", passed, r, "crossRealmConsoleProbe");
      } catch { return this._addFinding("crossRealmConsoleProbe", false, { error:true }, "crossRealmConsoleProbe"); }
    }

    async _descriptorWeirdness() {
      try {
        const d = safeDesc(console, "log") || {};
        const weird = (typeof console.log === "function") && (d.configurable === true || d.enumerable === true);
        return this._addFinding("descriptorWeirdness", weird, { descriptor:d }, "descriptorWeirdness");
      } catch { return this._addFinding("descriptorWeirdness", false, { error:true }, "descriptorWeirdness"); }
    }

    // --------------- v1.2 heuristics ---------------
    async _detectEvalHook() {
      try {
        const native = looksNative(eval);
        return this._addFinding("detectEvalHook", !native, { evalNative: native }, "detectEvalHook");
      } catch { return this._addFinding("detectEvalHook", false, { error:true }, "detectEvalHook"); }
    }

    async _detectSetTimeoutHook() {
      try {
        const st = looksNative(setTimeout);
        const ct = looksNative(clearTimeout);
        return this._addFinding("detectSetTimeoutHook", !(st && ct), { setTimeoutNative: st, clearTimeoutNative: ct }, "detectSetTimeoutHook");
      } catch { return this._addFinding("detectSetTimeoutHook", false, { error:true }, "detectSetTimeoutHook"); }
    }

    async _detectRAFHook() {
      try {
        const rafN = looksNative(requestAnimationFrame);
        const cafN = looksNative(cancelAnimationFrame);
        return this._addFinding("detectRAFHook", !(rafN && cafN), { rafNative: rafN, cafNative: cafN }, "detectRAFHook");
      } catch { return this._addFinding("detectRAFHook", false, { error:true }, "detectRAFHook"); }
    }

    async _detectAddEventListenerHook() {
      try {
        const proto = (window.EventTarget || window.Node || window.HTMLElement)?.prototype || {};
        const addN = looksNative(proto.addEventListener);
        const remN = looksNative(proto.removeEventListener);
        return this._addFinding("detectAddEventListenerHook", !(addN && remN), { addNative: addN, removeNative: remN }, "detectAddEventListenerHook");
      } catch { return this._addFinding("detectAddEventListenerHook", false, { error:true }, "detectAddEventListenerHook"); }
    }

    async _detectNodeAppendHook() {
      try {
        const p = Node.prototype;
        const a = looksNative(p.appendChild);
        const i = looksNative(p.insertBefore);
        const r = looksNative(p.removeChild);
        return this._addFinding("detectNodeAppendHook", !(a && i && r), { appendNative: a, insertNative: i, removeNative: r }, "detectNodeAppendHook");
      } catch { return this._addFinding("detectNodeAppendHook", false, { error:true }, "detectNodeAppendHook"); }
    }

    async _detectCreateElementHook() {
      try {
        const dp = Document.prototype;
        const ep = Element.prototype;
        const ce = looksNative(dp.createElement);
        const sa = looksNative(ep.setAttribute);
        return this._addFinding("detectCreateElementHook", !(ce && sa), { createElementNative: ce, setAttributeNative: sa }, "detectCreateElementHook");
      } catch { return this._addFinding("detectCreateElementHook", false, { error:true }, "detectCreateElementHook"); }
    }

    async _detectMutationObserverHook() {
      try {
        const MO = window.MutationObserver;
        const ctor = looksNative(MO);
        const obs = MO && MO.prototype ? looksNative(MO.prototype.observe) : true;
        return this._addFinding("detectMutationObserverHook", !(ctor && obs), { ctorNative: ctor, observeNative: obs }, "detectMutationObserverHook");
      } catch { return this._addFinding("detectMutationObserverHook", false, { error:true }, "detectMutationObserverHook"); }
    }

    async _detectCSSInsertRuleHook() {
      try {
        const p = CSSStyleSheet && CSSStyleSheet.prototype;
        const ins = p && looksNative(p.insertRule);
        const del = p && looksNative(p.deleteRule);
        return this._addFinding("detectCSSInsertRuleHook", !(ins && del), { insertRuleNative: ins, deleteRuleNative: del }, "detectCSSInsertRuleHook");
      } catch { return this._addFinding("detectCSSInsertRuleHook", false, { error:true }, "detectCSSInsertRuleHook"); }
    }

    async _freshBoundConsoleProbe() {
      try {
        const r = await this._withFreshRealm((fw) => {
          const bound = console.log.bind(console);
          const sFreshOnBound = fw.Function.prototype.toString.call(bound);
          const sLocalOnBound = Function.prototype.toString.call(bound);
          const looksFresh = NATIVE_RX.test(sFreshOnBound);
          const looksLocal = NATIVE_RX.test(sLocalOnBound);
          const mismatch = sFreshOnBound !== sLocalOnBound;
          return { sFreshOnBound, sLocalOnBound, looksFresh, looksLocal, mismatch };
        });
        const passed = !!(r && (r.mismatch || (r.looksFresh && !r.looksLocal)));
        return this._addFinding("freshBoundConsoleProbe", passed, r, "freshBoundConsoleProbe");
      } catch { return this._addFinding("freshBoundConsoleProbe", false, { error:true }, "freshBoundConsoleProbe"); }
    }

    async _workerRealmToStringDrift() {
      try {
        const code = `
          self.onmessage = function(){
            const ts = Function.prototype.toString;
            const out = {
              tsString: ts.toString(),
              evalTS: ts.call(eval)
            };
            postMessage(out);
          };
        `;
        const blob = new Blob([code], { type: "text/javascript" });
        const url = URL.createObjectURL(blob);
        const w = new Worker(url);
        const r = await new Promise((resolve) => {
          let done = false;
          const settle = (data) => { if (done) return; done = true; try { w.terminate(); } catch{} try { URL.revokeObjectURL(url); } catch{} resolve(data); };
          w.onmessage = (e) => settle(e.data);
          w.onerror = () => settle({ error:true, why:"workerError" });
          w.postMessage(null);
          setTimeout(() => settle({ error:true, why:"timeout" }), 1200);
        });
        const local = {
          tsString: Function.prototype.toString.toString(),
          evalTS: Function.prototype.toString.call(eval)
        };
        const suspicious = !!(r && (r.tsString !== local.tsString || r.evalTS !== local.evalTS));
        return this._addFinding("workerRealmToStringDrift", suspicious, { worker:r, local }, "workerRealmToStringDrift");
      } catch { return this._addFinding("workerRealmToStringDrift", false, { error:true }, "workerRealmToStringDrift"); }
    }

    _prepareAdBaitPlus() {
      if (this._adBait2) return;
      try {
        const b = document.createElement("div");
        b.id=`ad-container-${Math.random().toString(36).slice(2)}`;
        b.className="adsbox ad-unit sponsor banner-ads ad-container";
        b.textContent = "advert";
        appendHidden(b);
        this._adBait2 = b;
      } catch {}
    }

    async _multiAdBaitPlusCheck() {
      try {
        if (!this._adBait2) return this._addFinding("multiAdBaitPlus", false, { prepared:false }, "multiAdBaitPlus");
        const cs = getComputedStyle(this._adBait2);
        const hidden = cs && (cs.display==="none"||cs.visibility==="hidden"||cs.opacity==="0");
        const r = this._adBait2.getBoundingClientRect();
        const collapsed = r.width===0 || r.height===0;
        const removed = !document.documentElement.contains(this._adBait2);
        return this._addFinding("multiAdBaitPlus", (hidden||collapsed||removed), { hidden, collapsed, removed }, "multiAdBaitPlus");
      } catch { return this._addFinding("multiAdBaitPlus", false, { error:true }, "multiAdBaitPlus"); }
    }

    // --------------- precision probe for Edge TM ---------------
    async _probeEdgeTampermonkeyUserscript() {
      const evid = { tried: [], hits: [], mode: [] };

      const tryIframe = (url) => new Promise((resolve) => {
        const fr = document.createElement("iframe");
        fr.style.display = "none";
        let done = false;
        const settle = (ok, why) => {
          if (done) return; done = true;
          try { fr.remove(); } catch {}
          resolve({ ok, via: "iframe", why, url });
        };
        fr.onload = () => settle(true, "load");
        fr.onerror = () => settle(false, "error");
        setTimeout(() => settle(false, "timeout"), 1200);
        fr.src = url + (url.includes("?") ? "&" : "?") + "r=" + Math.random().toString(36).slice(2);
        evid.tried.push(url);
        document.documentElement.appendChild(fr);
      });

      const tryLink = (url) => new Promise((resolve) => {
        let link; let done = false;
        const settle = (ok, why) => { if (done) return; done = true; try { link.remove(); } catch {} resolve({ ok, via: "css", why, url }); };
        try {
          link = document.createElement("link");
          link.rel = "stylesheet";
          link.onload = () => settle(true, "load");
          link.onerror = () => settle(false, "error");
          link.href = url + (url.includes("?") ? "&" : "?") + "r=" + Math.random().toString(36).slice(2);
          evid.tried.push(url);
          document.documentElement.appendChild(link);
          setTimeout(() => settle(false, "timeout"), 1200);
        } catch { settle(false, "exception"); }
      });

      const tryImg = (url) => new Promise((resolve) => {
        const img = new Image();
        let done = false;
        const settle = (ok, why) => { if (done) return; done = true; resolve({ ok, via: "img", why, url }); };
        img.onload = () => settle(true, "load");
        img.onerror = () => settle(false, "error");
        img.src = url + (url.includes("?") ? "&" : "?") + "r=" + Math.random().toString(36).slice(2);
        evid.tried.push(img.src);
        setTimeout(() => settle(false, "timeout"), 1200);
      });

      const base = `chrome-extension://${EDGE_TM_ID}`;
      const urls = EDGE_TM_PATHS.map(p => base + p);

      const attempts = [];
      for (const u of urls) {
        attempts.push(tryIframe(u));
        if (/\.(png|jpg|jpeg|gif|svg)$/i.test(u)) attempts.push(tryImg(u));
        else attempts.push(tryLink(u));
      }

      const results = await Promise.allSettled(attempts);
      const flat = results.map(r => r.status === "fulfilled" ? r.value : { ok: false, via: "error", why: "rejected" });
      const okHits = flat.filter(x => x && x.ok);
      evid.mode = flat;

      // perf entries sometimes record the attempt even on error
      let rtHits = [];
      try {
        await sleep(80);
        const entries = performance.getEntriesByType("resource") || [];
        rtHits = entries
          .filter(e => typeof e.name === "string" && e.name.startsWith(`chrome-extension://${EDGE_TM_ID}/`))
          .map(e => ({ name: e.name, type: e.initiatorType, t: Math.round((e.responseEnd||e.duration)||0) }));
      } catch {}
      if (rtHits.length) evid.resourceTiming = rtHits;

      const passed = okHits.length > 0 || rtHits.length > 0;
      return this._addFinding("probeEdgeTampermonkeyUserscript", passed, evid, "probeEdgeTampermonkeyUserscript");
    }

    // --------------- v1.3 NEW: extra heuristics (10) ---------------
    async _detectIndirectEvalHook() {
      try {
        const indirect = (0, eval);
        const native = looksNative(indirect);
        return this._addFinding("detectIndirectEvalHook", !native, { indirectEvalNative: native }, "detectIndirectEvalHook");
      } catch { return this._addFinding("detectIndirectEvalHook", false, { error:true }, "detectIndirectEvalHook"); }
    }

    async _detectNewFunctionHook() {
      try {
        const nf = Function;                    // ctor
        const nfNative = looksNative(nf);
        // Instances should stringify like native too
        const body = "return 1";
        const fn = new Function(body);
        const instTS = Function.prototype.toString.call(fn);
        const looks = NATIVE_RX.test(instTS);
        return this._addFinding("detectNewFunctionHook", !(nfNative && looks), { nfNative, instTS }, "detectNewFunctionHook");
      } catch { return this._addFinding("detectNewFunctionHook", false, { error:true }, "detectNewFunctionHook"); }
    }

    async _detectBindHook() {
      try {
        const b = Function.prototype.bind;
        const bNative = looksNative(b);
        const bound = console.log.bind(console);
        const ts = Function.prototype.toString.call(bound);
        const looks = NATIVE_RX.test(ts);
        return this._addFinding("detectBindHook", !(bNative && looks), { bindNative: bNative, boundToString: ts.slice(0,80) }, "detectBindHook");
      } catch { return this._addFinding("detectBindHook", false, { error:true }, "detectBindHook"); }
    }

    async _detectRequestResponseHeadersHook() {
      try {
        const RQ = window.Request, RS = window.Response, HD = window.Headers;
        const rqN = looksNative(RQ), rsN = looksNative(RS), hdN = looksNative(HD);
        const rqProto = RQ && RQ.prototype && looksNative(RQ.prototype.clone);
        const rsProto = RS && RS.prototype && looksNative(RS.prototype.clone);
        const hdProto = HD && HD.prototype && looksNative(HD.prototype.get);
        const ok = rqN && rsN && hdN && rqProto && rsProto && hdProto;
        return this._addFinding("detectRequestResponseHeadersHook", !ok, { rqN, rsN, hdN, rqProto, rsProto, hdProto }, "detectRequestResponseHeadersHook");
      } catch { return this._addFinding("detectRequestResponseHeadersHook", false, { error:true }, "detectRequestResponseHeadersHook"); }
    }

    async _detectMessageChannelHook() {
      try {
        const MC = window.MessageChannel;
        const nCtor = looksNative(MC);
        let postN = true;
        try { const ch = new MC(); postN = looksNative(ch.port1.postMessage) && looksNative(ch.port2.postMessage); } catch {}
        return this._addFinding("detectMessageChannelHook", !(nCtor && postN), { ctorNative: nCtor, postNative: postN }, "detectMessageChannelHook");
      } catch { return this._addFinding("detectMessageChannelHook", false, { error:true }, "detectMessageChannelHook"); }
    }

    async _detectPerformanceObserverHook() {
      try {
        const PO = window.PerformanceObserver;
        const ctorN = looksNative(PO);
        const disN = PO && PO.prototype ? looksNative(PO.prototype.disconnect) : true;
        return this._addFinding("detectPerformanceObserverHook", !(ctorN && disN), { ctorNative: ctorN, disconnectNative: disN }, "detectPerformanceObserverHook");
      } catch { return this._addFinding("detectPerformanceObserverHook", false, { error:true }, "detectPerformanceObserverHook"); }
    }

    async _detectHistoryHook() {
      try {
        const HP = window.History && window.History.prototype;
        const pushN = HP && looksNative(HP.pushState);
        const repN = HP && looksNative(HP.replaceState);
        return this._addFinding("detectHistoryHook", !(pushN && repN), { pushStateNative: pushN, replaceStateNative: repN }, "detectHistoryHook");
      } catch { return this._addFinding("detectHistoryHook", false, { error:true }, "detectHistoryHook"); }
    }

    async _detectAttachShadowHook() {
      try {
        const ASP = Element && Element.prototype && Element.prototype.attachShadow;
        const atN = looksNative(ASP);
        return this._addFinding("detectAttachShadowHook", !atN, { attachShadowNative: atN }, "detectAttachShadowHook");
      } catch { return this._addFinding("detectAttachShadowHook", false, { error:true }, "detectAttachShadowHook"); }
    }

    async _detectPermissionsHook() {
      try {
        const P = navigator.permissions && navigator.permissions.query;
        const qN = looksNative(P);
        return this._addFinding("detectPermissionsHook", !qN, { permissionsQueryNative: qN }, "detectPermissionsHook");
      } catch { return this._addFinding("detectPermissionsHook", false, { error:true }, "detectPermissionsHook"); }
    }

    async _detectClipboardHook() {
      try {
        const clip = navigator.clipboard;
        const ok = !!clip && looksNative(clip.writeText) && looksNative(clip.readText);
        return this._addFinding("detectClipboardHook", !ok, { writeTextNative: clip && looksNative(clip.writeText), readTextNative: clip && looksNative(clip.readText) }, "detectClipboardHook");
      } catch { return this._addFinding("detectClipboardHook", false, { error:true }, "detectClipboardHook"); }
    }

    // --------------- Watchdog ----------------
    _watchdogStart() {
      if (!this.opts.watchdog?.enable) return;
      // Mark presence in DOM via meta and in storage via heartbeat
      try {
        let meta = document.querySelector('meta[name="istria-am-presence"]');
        if (!meta) {
          meta = document.createElement("meta");
          meta.setAttribute("name", "istria-am-presence");
          meta.setAttribute("content", "alive");
          (document.head || document.documentElement).appendChild(meta);
        }
      } catch {}

      const beat = () => {
        const ts = Date.now();
        LS.set(this._hbKey, { t: ts });
        LS.set(this._verKey, this._ver);
      };
      beat();
      this._hbTimer = setInterval(beat, 5000 + Math.floor(Math.random()*1500)); // jittered
    }

    async _watchdogPresenceCheck() {
      try {
        if (!this.opts.watchdog?.enable) return this._addFinding("watchdogMissing", false, { enabled:false }, "watchdogMissing");
        // Indicators that the site expects AntiMonkey to be running:
        // 1) <meta name="istria-am-expected" content="1">
        // 2) <script data-istria-am ...>
        // 3) any script src/name hints configured by site (keep generic)
        const expectedMeta = !!document.querySelector('meta[name="istria-am-expected"][content="1"]');
        const expectedScript = Array.from(document.querySelectorAll('script[data-istria-am]')).length > 0;

        // A soft heuristic: presence of a script tag that "looks like" this detector
        const probableScript = Array.from(document.scripts || []).some(s => {
          const id = (s.id||"").toLowerCase();
          const data = s.getAttribute && (s.getAttribute("data-istria-am")||"");
          const src = (s.src||"").toLowerCase();
          return !!data || id.includes("antimonkey") || id.includes("istria") || src.includes("antimonkey") || src.includes("istria");
        });

        const expected = expectedMeta || expectedScript || probableScript;

        // Check heartbeat freshness
        const hb = LS.get(this._hbKey, null);
        const fresh = hb && typeof hb.t === "number" && (Date.now() - hb.t) <= this.opts.watchdog.staleMs;

        // If the site expects the script but heartbeat isn't fresh, flag missing
        const missing = !!expected && !fresh;
        return this._addFinding("watchdogMissing", missing, { expected, expectedMeta, expectedScript, probableScript, fresh, hb }, "watchdogMissing");
      } catch {
        return this._addFinding("watchdogMissing", false, { error:true }, "watchdogMissing");
      }
    }
  }

  // Expose + auto-start
  window.AntiMonkey = AntiMonkey;

  AntiMonkey.start({
    debug: true,          // turn off in production
    threshold: 30,        // adjust after observing false positives
    continuous: true,
    watchdog: { enable: true, staleMs: 15000 },
    onScore: ({ score, suspected, durationMs }) => {
      // telemetry hook (optional)
    },
    onDetect: (p) => {
      // respond to detection (optional)
    }
  });

})();
