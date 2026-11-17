/*!
 * HexAIRadio-BROWSER — Protection Widget v1.0.0
 * ---------------------------------------------------------------------------
 * Drop-in, dependency-free client-side hardening for a static site.
 *
 *   • Allow-list XSS sanitizer            → XSSGuard.sanitize(html)
 *   • DevTools watchdog                   → log-only by default
 *   • Developer-hotkey lockdown           → preventDefault (app handlers fire)
 *   • Context-menu / drag / selection     → form + media + data-hexguard-allow exempt
 *   • Console blackout                    → opt-in (off by default)
 *   • DOM source noise                    → opt-in (off by default)
 *
 * Usage:
 *   <script src="guard.js" defer></script>
 *
 *   XSSGuard.sanitize('<b onmouseover="alert(1)">hi</b>');  // => "<b>hi</b>"
 *   XSSGuard.sanitizeToElement(untrustedHtml);               // => HTMLElement
 *
 *   HexGuard.config.sourceNoise     = true;
 *   HexGuard.config.consoleBlackout = true;
 *   HexGuard.config.devtoolsDetect  = 'punish';   // 'off' | 'log' | 'punish'
 *   HexGuard.start('strict');                     // console muted + punish
 *   HexGuard.pause(); HexGuard.resume(); HexGuard.stop();
 *
 * Events (CustomEvent on document):
 *   hexguard:log     { time, message, level }
 *   hexguard:punish  { reason, time }
 *   hexguard:start   { status }
 *   hexguard:stop    { status }
 *
 * Exempt a region from a guard:
 *   <div data-hexguard-allow>…</div>
 *
 * Note: defence-in-depth, not a security boundary. Real XSS defence lives
 * server-side (output encoding, HttpOnly cookies) and in a strict CSP
 * delivered as an HTTP response header.
 * ---------------------------------------------------------------------------
 */
(function (window, document) {
  'use strict';

  /* Idempotent install — loading the script twice is a no-op. */
  if (window.XSSGuard && window.HexGuard) return;

  /* ======================================================================
     PART 1 — ALLOW-LIST XSS SANITIZER
     ====================================================================== */
  var XSSGuard = (function () {

    var ALLOWED_TAGS = new Set([
      'a','abbr','b','bdi','bdo','blockquote','br','caption','cite','code',
      'col','colgroup','dd','del','details','dfn','div','dl','dt','em',
      'figcaption','figure','h1','h2','h3','h4','h5','h6','hr','i','img',
      'ins','kbd','li','mark','ol','p','pre','q','rp','rt','ruby','s','samp',
      'small','span','strong','sub','summary','sup','table','tbody','td',
      'tfoot','th','thead','time','tr','u','ul','var','wbr'
    ]);

    var FORBID_TAGS = new Set([
      'script','style','iframe','frame','frameset','object','embed','applet',
      'link','meta','base','form','input','button','textarea','select',
      'option','optgroup','svg','math','template','noscript','noembed',
      'noframes','xmp','plaintext','title','head','body','html','marquee',
      'bgsound','audio','video','source','track','canvas','portal','dialog',
      'slot','param'
    ]);

    var ALLOWED_ATTRS = new Set([
      'abbr','align','alt','cite','class','colspan','datetime','dir','height',
      'href','hreflang','id','lang','loading','name','open','referrerpolicy',
      'rel','reversed','role','rowspan','scope','size','span','src','start',
      'target','title','type','value','width','decoding'
    ]);

    var URL_ATTRS = new Set([
      'href','src','cite','action','formaction','poster','background',
      'longdesc','usemap','xlink:href'
    ]);

    var SAFE_SCHEMES = /^(?:https?|mailto|tel|ftp):/i;
    var DATA_IMAGE   = /^data:image\/(?:png|gif|jpe?g|webp|bmp|avif);base64,[a-z0-9+/=]+$/i;
    var ATTR_NAME    = /^[a-z][a-z0-9-]*$/;
    var CTRL_CHARS   = /[\u0000-\u0020\u007f-\u00a0\u1680\u2000-\u200f\u2028\u2029\u202f\u205f\u3000\ufeff]/g;

    /* Strip control / zero-width characters used to smuggle "java\nscript:"
       style schemes past naive filters. */
    function compact(v) { return String(v).replace(CTRL_CHARS, ''); }

    function isSafeURL(value, allowDataImage) {
      var v = compact(value);
      if (!v) return true;
      if (v.charAt(0) === '#' || v.charAt(0) === '?' || v.charAt(0) === '/') return true;
      if (v.indexOf('./') === 0 || v.indexOf('../') === 0) return true;
      if (SAFE_SCHEMES.test(v)) return true;
      if (allowDataImage && DATA_IMAGE.test(v)) return true;
      return false;
    }

    function cleanNode(node, doc) {
      /* Text is always safe once re-serialised. */
      if (node.nodeType === 3) return doc.createTextNode(node.nodeValue);

      /* Comments, CDATA, processing instructions — drop. */
      if (node.nodeType !== 1) return null;

      var tag = node.tagName.toLowerCase();
      if (FORBID_TAGS.has(tag)) return null;

      var keep = ALLOWED_TAGS.has(tag);
      var target = keep ? doc.createElement(tag) : doc.createDocumentFragment();

      if (keep) {
        var attrs = Array.prototype.slice.call(node.attributes);
        for (var i = 0; i < attrs.length; i++) {
          var name  = attrs[i].name.toLowerCase();
          var value = attrs[i].value;

          if (!ATTR_NAME.test(name)) continue;                // weird names
          if (name.indexOf('on') === 0) continue;             // onerror, onload, …
          if (name === 'style') continue;                     // css exfil surface
          if (!ALLOWED_ATTRS.has(name) &&
              name.indexOf('aria-') !== 0 &&
              name.indexOf('data-') !== 0) continue;

          if (URL_ATTRS.has(name) &&
              !isSafeURL(value, tag === 'img' && name === 'src')) continue;

          try { target.setAttribute(name, value); } catch (e) { /* ignore */ }
        }

        if (tag === 'a' && target.getAttribute('href')) {
          target.setAttribute('rel', 'noopener noreferrer nofollow');
          if (!target.getAttribute('target')) target.setAttribute('target', '_blank');
        }
        if (tag === 'img') {
          if (!target.hasAttribute('alt')) target.setAttribute('alt', '');
          target.setAttribute('loading', 'lazy');
          target.setAttribute('referrerpolicy', 'no-referrer');
        }
      }

      var children = Array.prototype.slice.call(node.childNodes);
      for (var c = 0; c < children.length; c++) {
        var cleaned = cleanNode(children[c], doc);
        if (cleaned) target.appendChild(cleaned);
      }
      return target;
    }

    /**
     * Sanitize untrusted HTML.
     * @param {string} dirty
     * @returns {string} safe HTML
     */
    function sanitize(dirty) {
      if (dirty == null) return '';
      var doc = new DOMParser().parseFromString(
        '<!doctype html><html><body>' + String(dirty), 'text/html'
      );
      var out = doc.createElement('div');
      var kids = Array.prototype.slice.call(doc.body.childNodes);
      for (var i = 0; i < kids.length; i++) {
        var cleaned = cleanNode(kids[i], doc);
        if (cleaned) out.appendChild(cleaned);
      }
      return out.innerHTML;
    }

    /**
     * Sanitize and return a detached element ready to insert.
     * @param {string} dirty
     * @returns {HTMLElement}
     */
    function sanitizeToElement(dirty) {
      var holder = document.createElement('div');
      holder.innerHTML = sanitize(dirty);
      return holder;
    }

    return {
      sanitize: sanitize,
      sanitizeToElement: sanitizeToElement,
      ALLOWED_TAGS: ALLOWED_TAGS,
      FORBID_TAGS: FORBID_TAGS,
      ALLOWED_ATTRS: ALLOWED_ATTRS
    };
  })();

  /* ======================================================================
     PART 2 — RUNTIME HARDENING
     ====================================================================== */
  var HexGuard = (function () {

    var config = {
      autoStart:        true,        // boot on DOMContentLoaded
      profile:          'balanced',  // 'balanced' | 'strict'
      hotkeys:          true,
      contextMenu:      true,
      drag:             true,
      selection:        true,
      consoleBlackout:  false,       // off — SDR apps log status here
      devtoolsDetect:   'log',       // 'off' | 'log' | 'punish'
      sourceNoise:      false,       // off — mutates the live DOM
      punishWindowMs:   60000,
      punishStrikes:    3
    };

    var status = {
      started: false,
      hotkeys: false, contextMenu: false, drag: false, selection: false,
      console: false, devtools: false, sourceNoise: false
    };

    var timers    = [];
    var listeners = [];
    var punishState = { last: 0, strikes: 0 };

    /* --------------------------------------------------------- utilities */
    function nowStr() {
      var d = new Date();
      return String(d.getHours()).padStart(2, '0') + ':' +
             String(d.getMinutes()).padStart(2, '0') + ':' +
             String(d.getSeconds()).padStart(2, '0');
    }

    function emit(type, detail) {
      try {
        document.dispatchEvent(new CustomEvent('hexguard:' + type, { detail: detail }));
      } catch (e) { /* ignore */ }
    }

    function log(msg, level) {
      emit('log', { time: nowStr(), message: msg, level: level || 'info' });
    }

    function isNative(fn) {
      try {
        return typeof fn === 'function' &&
          /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn));
      } catch (e) { return false; }
    }

    function exempt(target) {
      if (!target || !target.closest) return false;
      return !!target.closest('[data-hexguard-allow]');
    }

    function isFormField(target) {
      if (!target || !target.closest) return false;
      return !!target.closest(
        'input, textarea, select, [contenteditable=""], [contenteditable="true"]'
      );
    }

    function isMedia(target) {
      if (!target || !target.closest) return false;
      return !!target.closest('audio, video, canvas, picture');
    }

    function addListener(target, type, handler, options) {
      target.addEventListener(type, handler, options);
      listeners.push({ target: target, type: type, handler: handler, options: options });
    }

    /* ------------------------------------------------------------ punish */
    function punish(reason) {
      var t = Date.now();
      if (t - punishState.last < config.punishWindowMs) {
        punishState.strikes++;
        if (punishState.strikes < config.punishStrikes) return;
      } else {
        punishState.strikes = 1;
      }
      punishState.last = t;

      emit('punish', { reason: reason, time: t });
      log('PUNISH: ' + reason, 'error');

      if (config.devtoolsDetect === 'punish') {
        try {
          document.documentElement.innerHTML = '';
          window.location.reload();
        } catch (e) { /* ignore */ }
      }
    }

    /* ------------------------------------------------------ DevTools watch */
    function startAntiDevTools() {
      if (status.devtools || config.devtoolsDetect === 'off') return;
      status.devtools = true;

      var TOL_MS       = 150;
      var VIEWPORT_TOL = 240;
      var strikes      = 0;

      function tick() {
        if (document.hidden) return;

        /* Spoof detection: primitives we rely on were patched. */
        if (!isNative(Date.now) ||
            !isNative(window.eval) ||
            !isNative(Function.prototype.toString)) {
          log('runtime tampering detected', 'warn');
          if (config.devtoolsDetect === 'punish') punish('runtime tampering detected');
          return;
        }

        /* `debugger` only pauses when a debugger is attached. */
        var t0 = performance.now();
        // eslint-disable-next-line no-debugger
        debugger;
        var delta = performance.now() - t0;

        var wDelta = Math.abs(window.outerWidth  - window.innerWidth);
        var hDelta = Math.abs(window.outerHeight - window.innerHeight);

        var suspicious = delta > TOL_MS ||
                         wDelta > VIEWPORT_TOL ||
                         hDelta > VIEWPORT_TOL;

        strikes = suspicious ? strikes + 1 : Math.max(0, strikes - 1);

        if (strikes >= 3) {
          strikes = 0;
          log('DevTools detected', 'warn');
          if (config.devtoolsDetect === 'punish') punish('DevTools detected');
        }
      }

      timers.push(window.setInterval(tick, 1000));
      log('DevTools watchdog started');
    }

    /* -------------------------------------------------------------- hotkeys */
    function startHotkeys() {
      if (status.hotkeys || !config.hotkeys) return;
      status.hotkeys = true;

      var BLOCKED = [
        { ctrl: false, shift: false, alt: false, meta: false, key: 'F12', code: 123, label: 'F12' },
        { ctrl: true,  shift: true,  alt: false, meta: false, key: 'I', code: 73,  label: 'Ctrl+Shift+I' },
        { ctrl: true,  shift: true,  alt: false, meta: false, key: 'J', code: 74,  label: 'Ctrl+Shift+J' },
        { ctrl: true,  shift: true,  alt: false, meta: false, key: 'C', code: 67,  label: 'Ctrl+Shift+C' },
        { ctrl: true,  shift: true,  alt: false, meta: false, key: 'K', code: 75,  label: 'Ctrl+Shift+K' },
        { ctrl: true,  shift: false, alt: false, meta: false, key: 'U', code: 85,  label: 'Ctrl+U' },
        { ctrl: false, shift: false, alt: true,  meta: true,  key: 'I', code: 73,  label: 'Cmd+Alt+I' },
        { ctrl: false, shift: false, alt: true,  meta: true,  key: 'J', code: 74,  label: 'Cmd+Alt+J' },
        { ctrl: false, shift: false, alt: true,  meta: true,  key: 'C', code: 67,  label: 'Cmd+Alt+C' }
      ];

      function match(ev, r) {
        return r.ctrl === ev.ctrlKey && r.shift === ev.shiftKey &&
               r.alt  === ev.altKey  && r.meta  === ev.metaKey &&
               ((ev.key || '').toUpperCase() === r.key ||
                ev.keyCode === r.code || ev.which === r.code);
      }

      addListener(document, 'keydown', function (ev) {
        for (var i = 0; i < BLOCKED.length; i++) {
          if (match(ev, BLOCKED[i])) {
            /* preventDefault only — the app's own handlers still fire. */
            ev.preventDefault();
            log('blocked hotkey ' + BLOCKED[i].label);
            return;
          }
        }
      }, true);

      log('hotkey lockdown active');
    }

    /* -------------------------------------------------------- context menu */
    function startContextMenu() {
      if (status.contextMenu || !config.contextMenu) return;
      status.contextMenu = true;
      addListener(document, 'contextmenu', function (ev) {
        if (isFormField(ev.target) || exempt(ev.target)) return;
        ev.preventDefault();
        log('context menu blocked');
      }, true);
    }

    /* --------------------------------------------------------------- drag */
    function startDrag() {
      if (status.drag || !config.drag) return;
      status.drag = true;
      addListener(document, 'dragstart', function (ev) {
        if (isFormField(ev.target) || isMedia(ev.target) || exempt(ev.target)) return;
        ev.preventDefault();
      }, true);
    }

    /* ---------------------------------------------------------- selection */
    function startSelection() {
      if (status.selection || !config.selection) return;
      status.selection = true;
      addListener(document, 'selectstart', function (ev) {
        if (isFormField(ev.target) || exempt(ev.target)) return;
        ev.preventDefault();
      }, true);
    }

    /* ------------------------------------------------------------ console */
    function startConsoleBlackout() {
      if (status.console || !config.consoleBlackout) return;
      status.console = true;
      var noop = function () { return null; };
      var methods = [
        'log','debug','warn','error','info','dir','dirxml','assert','table',
        'trace','group','groupCollapsed','groupEnd','time','timeEnd','timeLog',
        'profile','profileEnd','count','countReset'
      ];
      for (var i = 0; i < methods.length; i++) {
        try { console[methods[i]] = noop; } catch (e) { /* frozen console */ }
      }
      log('console output blacked out');
    }

    /* -------------------------------------------------------- source noise */
    var NOISE_SKIP = new Set([
      'script','style','link','meta','title','textarea','input','select',
      'option','iframe','canvas','svg','template','video','audio','picture',
      'object','embed'
    ]);

    function rnd(min, max) {
      return Math.floor(Math.random() * (max - min + 1)) + min;
    }
    function rndStr(min, max) {
      var a = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
      var out = '', n = rnd(min, max);
      for (var i = 0; i < n; i++) out += a.charAt(Math.floor(Math.random() * a.length));
      return out;
    }

    function applyNoise() {
      var body = document.body;
      if (!body) return;
      var els = body.querySelectorAll('*'), budget = 400;
      for (var i = 0; i < els.length && budget > 0; i++) {
        var el = els[i];
        if (el.hasAttribute('data-hexguard-done')) continue;
        if (el.closest('[data-hexguard-allow]')) continue;
        if (NOISE_SKIP.has(el.tagName.toLowerCase())) continue;
        el.setAttribute('data-hexguard-done', '');
        budget--;

        var ac = rnd(3, 10);
        for (var a = 0; a < ac; a++) {
          try { el.setAttribute(rndStr(6, 12), Math.random() < 0.5 ? rndStr(2, 8) : ''); }
          catch (e) { /* invalid name, ignore */ }
        }
        var cc = rnd(1, 3);
        for (var k = 0; k < cc; k++) {
          try { el.classList.add(rndStr(6, 20)); } catch (e) { /* ignore */ }
        }
      }
    }

    function startSourceNoise() {
      if (status.sourceNoise || !config.sourceNoise) return;
      status.sourceNoise = true;
      var run = function () { try { applyNoise(); } catch (e) { /* never break page */ } };
      if (typeof window.requestIdleCallback === 'function') {
        window.requestIdleCallback(run, { timeout: 2000 });
      } else {
        window.setTimeout(run, 700);
      }
      log('DOM source noise scheduled');
    }

    /* ----------------------------------------------------------- lifecycle */
    function start(profile) {
      if (profile === 'strict') {
        config.profile = 'strict';
        config.consoleBlackout = true;
        config.devtoolsDetect  = 'punish';
      }
      if (status.started) return status;
      status.started = true;
      startHotkeys();
      startContextMenu();
      startDrag();
      startSelection();
      startConsoleBlackout();
      startSourceNoise();
      startAntiDevTools();
      emit('start', status);
      return status;
    }

    function stop() {
      for (var i = 0; i < timers.length; i++) window.clearInterval(timers[i]);
      timers.length = 0;
      for (var j = 0; j < listeners.length; j++) {
        var l = listeners[j];
        try { l.target.removeEventListener(l.type, l.handler, l.options); } catch (e) { /* ignore */ }
      }
      listeners.length = 0;
      status.started = false;
      emit('stop', status);
    }

    function pause()  { stop(); }
    function resume() { return start(); }

    return {
      config: config,
      status: status,
      start: start, stop: stop, pause: pause, resume: resume,
      logEvent: log,
      isNative: isNative,
      randomInt: rnd, randomString: rndStr
    };
  })();

  /* ======================================================================
     PART 3 — EXPORT + AUTO-BOOT
     ====================================================================== */
  window.XSSGuard = XSSGuard;
  window.HexGuard = HexGuard;

  function boot() {
    if (HexGuard.config.autoStart) HexGuard.start();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }

})(window, document);