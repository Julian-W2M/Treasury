javascript:(async () => {
  'use strict';
  /* MacroRecorder - Treasury Team 1.0 - evolucion de Page_inspector.js 3.2 (solo comentarios de bloque: apto para bookmarklet) */

  if (window.__MacroRecorderAI__) {
    try { window.__MacroRecorderAI__.show(); } catch (e) {}
    return;
  }

  const CFG = {
    VERSION: '1.0',
    DEFAULT_DURATION_SEC: 60,
    MAX_TEXT: 180,
    MAX_ATTR: 160,
    MAX_TABLE_ROWS: 8,
    MAX_TABLE_COLS: 15,
    MAX_ITEMS: 500,
    CORRELATION_WINDOW_MS: 4000,
    MUTATION_ATTRIBUTION_MS: 3000,
    INPUT_MERGE_MS: 2500,
    SCROLL_QUIET_MS: 400,
    MAX_ACTIONS: 3000,
    MAX_NETWORK: 1500,
    MAX_MUTATIONS: 1500,
    MAX_NODES_PER_BATCH: 40,
    UPDATE_MIN_NODES: 3,
    STORAGE_KEY: '__MacroRecorderAI_state__',
    HANDOFF_KEY: '__MacroRecorderAI_handoff__'
  };

  const ALLOWED_EVENT_TYPES = new Set(['click', 'change', 'submit', 'input', 'dblclick', 'keydown', 'keyup', 'contextmenu']);
  const NOISE_CLASS_REGEX = /^(fui-|react-|fiber|layer|tooltip|provider|tabster|ms-layer|ms-callout|ms-fabric|css-|sc-|jsx-|emotion-)/i;
  const NOISE_URL_REGEX = /(react|fluentui|fluent-ui|webpack|fonts\.googleapis|fonts\.gstatic|\.woff2?(?:\?|$)|\.ttf(?:\?|$)|\.svg(?:\?|$)|\.png(?:\?|$)|\.jpe?g(?:\?|$)|\.gif(?:\?|$)|\.ico(?:\?|$)|\.css(?:\?|$)|github\.com|cdn\.|\/static\/|\/_next\/|node_modules|analytics|telemetry|beacon|\.map(?:\?|$)|\.js(?:\?|$))/i;

  const clean = (value, max = CFG.MAX_TEXT) => {
    if (value == null) return '';
    return String(value).replace(/\s+/g, ' ').trim().slice(0, max);
  };
  const iso = ts => new Date(ts).toISOString();
  const normalizeText = s => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();

  /* Estado compartido de la grabacion (serializable salvo _el en acciones) */
  const S = {
    recId: '', status: 'READY', startedAt: 0, endAt: 0, durationSec: CFG.DEFAULT_DURATION_SEC,
    includeLegacy: false, resumed: false, resumeCount: 0,
    stepCounter: 1, lastEventTs: 0, lastActionTs: 0, lastActionStep: 0, lastUrl: '',
    actions: [], used: new Map(), formSnaps: new Map(), tableSnaps: new Map(),
    navigation: [], mutations: [], network: [], listeners: [], seq: { req: 1, mut: 1, nav: 1 }
  };
  const resetState = () => {
    Object.assign(S, {
      recId: 'rec-' + Date.now().toString(36), status: 'READY', startedAt: 0, endAt: 0, resumed: false, resumeCount: 0,
      stepCounter: 1, lastEventTs: 0, lastActionTs: 0, lastActionStep: 0, lastUrl: location.href,
      actions: [], used: new Map(), formSnaps: new Map(), tableSnaps: new Map(),
      navigation: [], mutations: [], network: [], listeners: [], seq: { req: 1, mut: 1, nav: 1 }
    });
  };
  resetState();

  /* =====================================================================
     SecurityManager
     ===================================================================== */
  const SecurityManager = (() => {
    const REDACTED = '[REDACTED]';
    const SENSITIVE_RE = /(passw(or)?d|pwd|contrase[nñ]a|token|jwt|api[-_ ]?key|authori[sz]ation|cookie|secret|bearer|session|csrf|xsrf|one-time-code)/i;
    const SELECTOR_KEYS = new Set(['selector', 'primarySelector', 'robustSelector', 'xpath', 'domPath', 'alternateSelectors', 'tableSelector', 'framePath', 'key', 'id']);
    const URL_KEYS = new Set(['url', 'href', 'from', 'to', 'frameUrl', 'action', 'nextUrl', 'origin', 'pathname', 'endpoint', 'path', 'queryString', 'referrer', 'src', 'oldURL', 'newURL', 'urls']);
    let count = 0;

    const isSensitiveName = n => !!n && SENSITIVE_RE.test(String(n));
    const isSensitiveField = el => {
      if (!el || el.nodeType !== 1 || !el.getAttribute) return false;
      if ((el.getAttribute('type') || '').toLowerCase() === 'password') return true;
      return [el.id, el.getAttribute('name'), el.getAttribute('autocomplete'), el.getAttribute('aria-label'), el.getAttribute('placeholder'), el.getAttribute('data-testid')].some(isSensitiveName);
    };
    const redact = () => { count++; return REDACTED; };

    const sanitizeString = str => {
      let out = String(str);
      out = out.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[EMAIL]');
      out = out.replace(/Bearer\s+[A-Za-z0-9\-_.=]+/gi, 'Bearer ' + REDACTED);
      out = out.replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, REDACTED);
      out = out.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '[ID]');
      out = out.replace(/\b(tenantid|tenant_id)=[^&"'\s]+/gi, '$1=[TENANT]');
      out = out.replace(/\b(sessionid|session_id|sid)=[^&"'\s]+/gi, '$1=' + REDACTED);
      out = out.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP]');
      return out;
    };
    const redactUrl = url => String(url).replace(/([?&;])([^=&;#\s"']+)=([^&;#\s"']*)/g, (m, p, k) =>
      (isSensitiveName(k) || /^(sig|signature|code|key|sas_token)$/i.test(k)) ? p + k + '=' + redact() : m);

    const deep = (value, key) => {
      if (typeof value === 'string') {
        if (SELECTOR_KEYS.has(key)) return value;
        if (URL_KEYS.has(key)) return redactUrl(value);
        return sanitizeString(redactUrl(value));
      }
      if (Array.isArray(value)) return value.map(v => deep(v, key));
      if (value && typeof value === 'object') {
        const out = {};
        for (const k of Object.keys(value)) {
          if (isSensitiveName(k) && !SELECTOR_KEYS.has(k)) out[k] = redact();
          else out[k] = deep(value[k], k);
        }
        return out;
      }
      return value;
    };

    const redactBody = (body, max = 300) => {
      if (body == null) return '';
      let s;
      if (typeof body === 'string') s = body;
      else if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) s = body.toString();
      else if (typeof FormData !== 'undefined' && body instanceof FormData) {
        const o = {};
        body.forEach((v, k) => { o[k] = isSensitiveName(k) ? redact() : (typeof v === 'string' ? v : '[File]'); });
        s = JSON.stringify(o);
      } else s = '[' + Object.prototype.toString.call(body).slice(8, -1) + ']';
      try { return clean(JSON.stringify(deep(JSON.parse(s))), max); } catch (e) {}
      return clean(sanitizeString(redactUrl('?' + s).slice(1)), max);
    };
    const redactHeaders = h => {
      const out = {};
      for (const k of Object.keys(h || {})) out[k] = isSensitiveName(k) ? redact() : clean(h[k], 200);
      return out;
    };

    return { REDACTED, isSensitiveName, isSensitiveField, redact, sanitizeString, redactUrl, redactBody, redactHeaders, sanitize: v => deep(v, ''), redactionCount: () => count };
  })();

  /* =====================================================================
     SelectorEngine (robustSelector/pathSelector originales + XPath, alternativas, scoring)
     ===================================================================== */
  const SelectorEngine = (() => {
    const cache = new WeakMap();
    const escAttr = v => String(v).replace(/"/g, '\\"');
    const cssEsc = s => (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/[^\w-]/g, '\\$&');

    const isStableClass = c =>
      !!c && c.length <= 40 &&
      !/^(ng-|_ngcontent|_nghost|css-|sc-|jsx-|emotion-|style-|Mui[A-Z]|is-|has-|active$|selected$|open$)/.test(c) &&
      !/^[a-z0-9]{6,}$/i.test(c) && !/\d{3,}/.test(c);

    const isNumericLikeId = s => !s || /^\d+$/.test(s) || /^[a-f0-9]{8,}$/i.test(s) || /^(react|radix|mui|fui|ext)[-:]/i.test(s);

    const isFrameworkNoise = el => {
      if (!el || !el.classList) return false;
      const looksNoisy = [...el.classList].some(c => NOISE_CLASS_REGEX.test(c));
      if (!looksNoisy) return false;
      const hasStableId = el.id && !isNumericLikeId(el.id);
      const hasTestId = !!(el.getAttribute && el.getAttribute('data-testid'));
      const hasAutomationType = !!(el.getAttribute && (el.getAttribute('data-automation-type') || el.getAttribute('data-automationid') || el.getAttribute('data-automation-id')));
      const hasAriaLabel = !!(el.getAttribute && el.getAttribute('aria-label'));
      return !(hasStableId || hasTestId || hasAutomationType || hasAriaLabel);
    };

    const pathSelector = el => {
      if (!el || el.nodeType !== 1) return '';
      if (el.id) return '#' + cssEsc(el.id);
      const parts = [];
      let current = el;
      while (current && current.nodeType === 1 && current !== current.ownerDocument.body && parts.length < 5) {
        let part = current.tagName.toLowerCase();
        if (current.name) part += '[name="' + cssEsc(current.name) + '"]';
        else if (current.classList.length) part += '.' + [...current.classList].slice(0, 2).map(c => cssEsc(c)).join('.');
        const parent = current.parentElement;
        if (parent) {
          const siblings = [...parent.children].filter(x => x.tagName === current.tagName);
          if (siblings.length > 1) part += ':nth-of-type(' + (siblings.indexOf(current) + 1) + ')';
        }
        parts.unshift(part);
        current = current.parentElement;
      }
      return parts.join(' > ');
    };

    const robustSelector = el => {
      if (!el || el.nodeType !== 1) return { value: '', quality: 'low', score: 0 };
      const tag = el.tagName.toLowerCase();
      const testId = el.getAttribute && el.getAttribute('data-testid');
      if (testId) return { value: `[data-testid="${escAttr(testId)}"]`, quality: 'high', score: 95 };
      const automationAttr = el.getAttribute && ['data-automation-type', 'data-automationid', 'data-automation-id'].find(a => el.getAttribute(a));
      if (automationAttr) return { value: `${tag}[${automationAttr}="${escAttr(el.getAttribute(automationAttr))}"]`, quality: 'high', score: 90 };
      const ariaLabel = el.getAttribute && el.getAttribute('aria-label');
      if (ariaLabel) return { value: `[aria-label="${escAttr(ariaLabel)}"]`, quality: 'high', score: 85 };
      if (el.id && !isNumericLikeId(el.id)) return { value: '#' + cssEsc(el.id), quality: 'high', score: 80 };
      const name = el.getAttribute && el.getAttribute('name');
      if (name) return { value: `${tag}[name="${escAttr(name)}"]`, quality: 'medium', score: 70 };
      const role = el.getAttribute && el.getAttribute('role');
      const ownText = clean(el.textContent, 40);
      if (role && ownText && ownText.length <= 40) return { value: `${tag}[role="${escAttr(role)}"]`, quality: 'medium', score: 65 };
      if (el.id && isNumericLikeId(el.id)) return { value: '#' + cssEsc(el.id), quality: 'medium', score: 55 };
      const stableClasses = el.classList ? [...el.classList].filter(isStableClass) : [];
      if (stableClasses.length) return { value: `${tag}.${stableClasses.slice(0, 2).map(c => cssEsc(c)).join('.')}`, quality: 'medium', score: 50 };
      return { value: pathSelector(el), quality: 'low', score: 20 };
    };

    const selector = el => robustSelector(el).value;
    const robust = el => { let r = cache.get(el); if (!r) { r = robustSelector(el); cache.set(el, r); } return r; };

    const countCss = (doc, sel) => { try { return doc.querySelectorAll(sel).length; } catch (e) { return -1; } };
    const countXpath = (doc, xp) => { try { return doc.evaluate('count(' + xp + ')', doc, null, XPathResult.NUMBER_TYPE, null).numberValue; } catch (e) { return -1; } };

    const xpath = el => {
      const doc = el.ownerDocument;
      if (el.id && !isNumericLikeId(el.id) && countCss(doc, `[id="${escAttr(el.id)}"]`) === 1) return `//*[@id="${escAttr(el.id)}"]`;
      const parts = [];
      let cur = el;
      while (cur && cur.nodeType === 1) {
        let i = 1, sib = cur.previousElementSibling;
        while (sib) { if (sib.localName === cur.localName) i++; sib = sib.previousElementSibling; }
        parts.unshift(cur.localName + '[' + i + ']');
        cur = cur.parentElement;
      }
      return '/' + parts.join('/');
    };

    const uniquePath = el => {
      const doc = el.ownerDocument;
      const parts = [];
      let cur = el;
      while (cur && cur.nodeType === 1 && cur !== doc.documentElement) {
        if (cur.id && !isNumericLikeId(cur.id)) { parts.unshift('#' + cssEsc(cur.id)); break; }
        let part = cur.localName;
        const p = cur.parentElement;
        if (p) part += ':nth-child(' + ([...p.children].indexOf(cur) + 1) + ')';
        parts.unshift(part);
        if (countCss(doc, parts.join(' > ')) === 1) break;
        cur = cur.parentElement;
      }
      return parts.join(' > ');
    };

    const build = el => {
      let out = cache.get(el);
      if (out && out.__full) return out;
      const doc = el.ownerDocument;
      const base = robust(el);
      const tag = el.localName;
      const cands = [];
      const add = (type, sel, lang) => { if (sel && !cands.some(c => c.selector === sel)) cands.push({ type, selector: sel, language: lang || 'css' }); };
      const g = a => el.getAttribute && el.getAttribute(a);
      if (g('data-testid')) add('data-testid', `[data-testid="${escAttr(g('data-testid'))}"]`);
      if (el.id) add('id', '#' + cssEsc(el.id));
      if (g('name')) add('name', `${tag}[name="${escAttr(g('name'))}"]`);
      if (g('aria-label')) add('aria-label', `[aria-label="${escAttr(g('aria-label'))}"]`);
      if (g('role')) add('role', `${tag}[role="${escAttr(g('role'))}"]`);
      if (g('placeholder')) add('placeholder', `${tag}[placeholder="${escAttr(g('placeholder'))}"]`);
      if (g('title')) add('title', `${tag}[title="${escAttr(g('title'))}"]`);
      if (el.dataset) for (const k of Object.keys(el.dataset).slice(0, 4)) { if (!SecurityManager.isSensitiveName(k)) add('data-attribute', `${tag}[data-${k.replace(/[A-Z]/g, m => '-' + m.toLowerCase())}="${escAttr(el.dataset[k])}"]`); }
      const sc = [...(el.classList || [])].filter(isStableClass).slice(0, 2);
      if (sc.length) add('class', tag + '.' + sc.map(cssEsc).join('.'));
      add('css-path', uniquePath(el));
      const txt = clean(el.textContent, 60);
      if (txt && !SecurityManager.isSensitiveField(el) && el.children.length <= 3) add('text', `//${tag}[normalize-space(.)="${escAttr(txt)}"]`, 'xpath');
      const xp = xpath(el);
      add('xpath', xp, 'xpath');

      cands.forEach(c => { c.matches = c.language === 'xpath' ? countXpath(doc, c.selector) : countCss(doc, c.selector); });
      const robustMatches = countCss(doc, base.value);
      let primary = base.value, primaryMatches = robustMatches, primaryType = 'robust';
      if (robustMatches !== 1) {
        const u = cands.find(c => c.language === 'css' && c.matches === 1);
        if (u) { primary = u.selector; primaryMatches = 1; primaryType = u.type; }
      }
      const dynClasses = [...(el.classList || [])].filter(c => !isStableClass(c)).length;
      let score = base.score;
      if (primaryMatches === 1) score += 10; else if (primaryMatches > 1) score -= Math.min(30, (primaryMatches - 1) * 5); else score -= 20;
      if (primaryType === 'css-path' || /:nth-/.test(primary)) score -= 10;
      if (dynClasses && /\./.test(primary)) score -= 10;
      if (el.id && !isNumericLikeId(el.id)) score += 5;
      if (g('aria-label') || g('role') || g('data-testid')) score += 5;
      if (isFrameworkNoise(el)) score -= 10;
      score = Math.max(0, Math.min(100, Math.round(score)));

      out = {
        __full: true,
        primarySelector: primary,
        alternateSelectors: cands.filter(c => c.selector !== primary && c.language === 'css').slice(0, 6).map(c => ({ type: c.type, selector: c.selector, matches: c.matches }))
          .concat(cands.filter(c => c.language === 'xpath' && c.type === 'text').slice(0, 1).map(c => ({ type: 'text-xpath', selector: c.selector, matches: c.matches }))),
        xpath: xp,
        robustSelector: { value: base.value, quality: base.quality, score: base.score, matches: robustMatches },
        selectorReliabilityScore: score,
        reliabilityFactors: { uniqueMatches: primaryMatches, hasStableId: !!(el.id && !isNumericLikeId(el.id)), dynamicClasses: dynClasses, accessibleAttributes: !!(g('aria-label') || g('role') || g('data-testid')), frameworkNoise: isFrameworkNoise(el) }
      };
      cache.set(el, Object.assign(out, { value: base.value, quality: base.quality, score: base.score }));
      return out;
    };

    return { isStableClass, isNumericLikeId, isFrameworkNoise, pathSelector, robustSelector, selector, robust, xpath, build };
  })();

  /* =====================================================================
     DOMAnalyzer (inspector original + informacion de elementos/contexto)
     ===================================================================== */
  const DOMAnalyzer = (() => {
    const infoCache = new WeakMap();
    const headerCache = new WeakMap();
    let _all = null;
    const all = () => _all || (_all = [...document.querySelectorAll('*')]);

    const visible = el => {
      if (!el) return false;
      const style = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0' && rect.width > 0 && rect.height > 0;
    };

    const attrs = el => {
      const result = {};
      const sensitive = SecurityManager.isSensitiveField(el);
      for (const attr of el.attributes || []) {
        let value = attr.value;
        if (SecurityManager.isSensitiveName(attr.name) || (attr.name === 'value' && sensitive)) value = SecurityManager.redact();
        else if (value.length > CFG.MAX_ATTR) value = value.slice(0, CFG.MAX_ATTR) + '…';
        result[attr.name] = value;
      }
      return result;
    };
    const dataAttrs = el => {
      const result = {};
      if (!el || !el.dataset) return result;
      for (const key in el.dataset) result[key] = SecurityManager.isSensitiveName(key) ? SecurityManager.redact() : clean(el.dataset[key], CFG.MAX_ATTR);
      return result;
    };
    const valueOf = (el, max = CFG.MAX_ATTR) => SecurityManager.isSensitiveField(el) ? SecurityManager.redact() : clean(el.value, max);
    const textOf = (el, max) => SecurityManager.isSensitiveField(el) ? '' : clean(el.innerText || el.value || '', max);

    const elementInfo = el => {
      const selectorInfo = SelectorEngine.robust(el);
      return {
        tag: el.tagName.toLowerCase(), id: el.id || '', name: el.getAttribute('name') || '', type: el.getAttribute('type') || '',
        role: el.getAttribute('role') || '', text: textOf(el), placeholder: el.getAttribute('placeholder') || '',
        ariaLabel: el.getAttribute('aria-label') || '', title: el.getAttribute('title') || '', class: clean(el.className, CFG.MAX_ATTR),
        attributes: attrs(el), dataAttributes: dataAttrs(el), selector: selectorInfo.value, selectorQuality: selectorInfo.quality,
        selectorStabilityScore: selectorInfo.score, frameworkNoise: SelectorEngine.isFrameworkNoise(el), visible: visible(el)
      };
    };

    /* Informacion compacta del elemento usado en una accion */
    const actionInfo = el => {
      let i = infoCache.get(el);
      if (i) return i;
      const attributes = attrs(el);
      const keys = Object.keys(attributes);
      if (keys.length > 20) keys.slice(20).forEach(k => delete attributes[k]);
      let labelText = '';
      try { if (el.labels && el.labels[0]) labelText = clean(el.labels[0].innerText, 80); } catch (e) {}
      i = {
        tag: el.localName, id: el.id || '', name: el.getAttribute('name') || '', type: el.getAttribute('type') || '',
        role: el.getAttribute('role') || '', ariaLabel: el.getAttribute('aria-label') || '', placeholder: el.getAttribute('placeholder') || '',
        title: el.getAttribute('title') || '', labelText, classes: [...(el.classList || [])].slice(0, 10), text: textOf(el, 120), attributes
      };
      infoCache.set(el, i);
      return i;
    };

    const INTERACTIVE_CLOSEST = 'button,a[href],[role="button"],[role="menuitem"],[role="option"],[role="tab"],[role="link"],[role="checkbox"],input,select,textarea,label,summary';
    const resolveTarget = t => {
      if (!t || t.nodeType !== 1) return t;
      try { return t.closest(INTERACTIVE_CLOSEST) || t; } catch (e) { return t; }
    };

    const tableHeaders = table => {
      let h = headerCache.get(table);
      if (!h) { h = [...table.querySelectorAll('thead th, tr:first-child th')].map(th => clean(th.innerText, 60)).slice(0, CFG.MAX_TABLE_COLS); headerCache.set(table, h); }
      return h;
    };
    const tableContext = el => {
      const tr = el.closest && el.closest('tr');
      const table = tr && tr.closest('table');
      if (!table) return null;
      const td = el.closest('td,th');
      const cellIndex = td ? td.cellIndex : -1;
      return { tableSelector: SelectorEngine.robust(table).value, rowIndex: tr.rowIndex, cellIndex, columnHeader: tableHeaders(table)[cellIndex] || '', rowText: clean(tr.innerText, 150) };
    };

    const brief = e => e ? { tag: e.localName, id: e.id || '', classes: [...(e.classList || [])].filter(SelectorEngine.isStableClass).slice(0, 4), role: e.getAttribute('role') || '', selector: SelectorEngine.robust(e).value } : null;
    const context = el => {
      const p = el.parentElement, gp = p && p.parentElement;
      const kids = [...el.children];
      const tags = {};
      kids.slice(0, 50).forEach(k => { tags[k.localName] = (tags[k.localName] || 0) + 1; });
      const sibs = p ? [...p.children] : [];
      const idx = sibs.indexOf(el);
      const sibBrief = s => s ? { tag: s.localName, text: clean(s.textContent, 40), selector: SelectorEngine.robust(s).value } : null;
      const r = el.getBoundingClientRect();
      const path = [];
      let c = el;
      while (c && c.nodeType === 1 && path.length < 12) {
        const sc = [...(c.classList || [])].filter(SelectorEngine.isStableClass)[0];
        path.unshift(c.localName + (c.id && !SelectorEngine.isNumericLikeId(c.id) ? '#' + c.id : '') + (sc ? '.' + sc : ''));
        c = c.parentElement;
      }
      const form = el.closest && el.closest('form');
      return {
        parent: brief(p), grandParent: brief(gp),
        childrenSummary: { count: kids.length, tags, sample: kids.slice(0, 5).map(k => ({ tag: k.localName, text: clean(k.textContent, 40) })) },
        siblingsSummary: { count: sibs.length, index: idx, previous: sibBrief(sibs[idx - 1]), next: sibBrief(sibs[idx + 1]) },
        domPath: path.join(' > '),
        relativePosition: { indexInParent: idx, siblingsCount: sibs.length, rect: { x: Math.round(r.x), y: Math.round(r.y), width: Math.round(r.width), height: Math.round(r.height) }, viewportPct: { x: +(r.x / (innerWidth || 1) * 100).toFixed(1), y: +(r.y / (innerHeight || 1) * 100).toFixed(1) } },
        form: form ? SelectorEngine.robust(form).value : '',
        nearestHeading: (() => { const h = el.closest && el.closest('section,fieldset,form,div'); const hh = h && h.querySelector('h1,h2,h3,h4,legend'); return hh ? clean(hh.textContent, 80) : ''; })()
      };
    };

    const fieldInfo = el => ({ ...elementInfo(el), required: !!el.required, disabled: !!el.disabled, value: valueOf(el) });
    const formInfo = (form, index) => {
      const els = [...form.elements];
      const requiredFields = els.filter(el => !!el.required).length;
      const hiddenFields = els.filter(el => el.type === 'hidden').length;
      const submitButtons = form.querySelectorAll("button[type='submit'], input[type='submit'], button:not([type])").length;
      return {
        index, id: form.id || '', name: form.getAttribute('name') || '', method: (form.method || 'GET').toUpperCase(),
        action: SecurityManager.redactUrl(form.action || location.href), enctype: form.enctype || '', selector: SelectorEngine.selector(form),
        formSummary: { requiredFields, hiddenFields, submitButtons, target: form.target || '', action: SecurityManager.redactUrl(form.action || location.href) },
        fields: els.slice(0, CFG.MAX_ITEMS).map(fieldInfo)
      };
    };

    const tableInfo = (table, index) => {
      const rows = [...table.querySelectorAll('tr')];
      const headers = tableHeaders(table).filter(Boolean);
      const sampleRows = rows.slice(0, CFG.MAX_TABLE_ROWS).map(row => [...row.children].slice(0, CFG.MAX_TABLE_COLS).map(cell => clean(cell.innerText)));
      const containsLinks = !!table.querySelector('a[href]');
      const containsButtons = !!table.querySelector("button, [role='button'], input[type='button'], input[type='submit']");
      const containsInputs = !!table.querySelector('input, select, textarea');
      const sortableLikely = !!table.querySelector("th[class*='sort' i], th[aria-sort], th.sortable, th[onclick]");
      const wrapper = table.closest('div') || table.parentElement;
      const filterableLikely = !!(table.querySelector('thead input, thead select') || (wrapper && wrapper.querySelector("input[type='search'], [class*='filter' i] input")));
      const paginationLikely = !!((wrapper && wrapper.querySelector("[class*='pagination' i], [class*='paginator' i], [class*='pager' i]")) || (table.id && document.querySelector(`[aria-controls="${CSS.escape(table.id)}"]`)));
      return {
        index, id: table.id || '', class: clean(table.className, CFG.MAX_ATTR), selector: SelectorEngine.selector(table), visible: visible(table),
        rows: rows.length, columns: rows.length ? rows[0].children.length : 0, headers, sampleRows,
        containsLinks, containsButtons, containsInputs, sortableLikely, filterableLikely, paginationLikely
      };
    };

    /* Deteccion tecnologica (original + Material UI y otros) */
    const detectFrameworks = () => {
      const found = [];
      const push = (name, version, confidence) => found.push({ name, version: version || '', confidence });
      try { if (window.jQuery || window.$) push('jQuery', (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) || '', 'high'); } catch (e) {}
      try { if (window.jQuery && window.jQuery.fn && window.jQuery.fn.dataTable) push('DataTables', '', 'high'); } catch (e) {}
      try { if (document.querySelector('table.dataTable, [class*="dataTables_wrapper"]')) push('DataTables', '', 'medium'); } catch (e) {}
      try { if (window.React) push('React', window.React.version || '', 'high'); } catch (e) {}
      try { if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || document.querySelector('[data-reactroot]')) push('React', '', 'medium'); } catch (e) {}
      try { if (window.Vue) push('Vue', window.Vue.version || '', 'high'); } catch (e) {}
      try { if (window.__VUE__ || document.querySelector('[data-v-app]') || all().slice(0, 500).some(el => [...el.attributes].some(a => a.name.startsWith('data-v-')))) push('Vue', '', 'medium'); } catch (e) {}
      try { if (window.angular) push('AngularJS', (window.angular.version && window.angular.version.full) || '', 'high'); } catch (e) {}
      try { const ngHost = document.querySelector('[ng-version]'); if (ngHost) push('Angular', ngHost.getAttribute('ng-version') || '', 'high'); } catch (e) {}
      try {
        const hasBootstrapAsset = !!document.querySelector('link[href*="bootstrap"], script[src*="bootstrap"]');
        const hasBootstrapClasses = !!document.querySelector('.container, .row, [class*="col-"], .btn-primary');
        if (window.bootstrap || hasBootstrapAsset) push('Bootstrap', '', 'high');
        else if (hasBootstrapClasses) push('Bootstrap', '', 'low');
      } catch (e) {}
      try { if (window.PrimeFaces) push('PrimeFaces', '', 'high'); } catch (e) {}
      try { if (document.querySelector('script[src*="primefaces"], .ui-widget, [id*="j_idt"]')) push('PrimeFaces', '', 'medium'); } catch (e) {}
      try { if (document.querySelector('input[name="__VIEWSTATE"]')) push('ASP.NET WebForms', '', 'high'); } catch (e) {}
      try { if (document.querySelector('input[name="__RequestVerificationToken"]') && !document.querySelector('input[name="__VIEWSTATE"]')) push('ASP.NET MVC', '', 'medium'); } catch (e) {}
      try { if (window.Ext) push('ExtJS', window.Ext.version || '', 'high'); } catch (e) {}
      try { if (window.ko) push('Knockout', window.ko.version || '', 'high'); } catch (e) {}
      try { if (document.querySelector('[class*="MuiButton"], [class*="MuiPaper"], [class*="MuiInput"]')) push('Material UI', '', 'medium'); } catch (e) {}
      try { if (document.querySelector('[class^="mat-"], [class*=" mat-"], mat-form-field, .cdk-overlay-container')) push('Angular Material', '', 'medium'); } catch (e) {}
      try { if (window.__NEXT_DATA__) push('Next.js', '', 'high'); } catch (e) {}
      try { if (window.__NUXT__) push('Nuxt', '', 'high'); } catch (e) {}
      const seen = new Set();
      return found.filter(f => (seen.has(f.name) ? false : (seen.add(f.name), true)));
    };

    const FRAMEWORK_GLOBAL_NAMES = new Set(['$', 'jQuery', 'angular', 'Vue', 'React', 'ReactDOM', 'Ext', 'ko', 'Backbone', '_', 'moment', 'axios', 'System', 'define', 'require', 'regeneratorRuntime', 'Zone', 'PrimeFaces', 'bootstrap', 'Popper', 'webpackJsonp', '__webpack_require__', 'Symbol', 'Proxy', 'Reflect', '__MacroRecorderAI__']);
    const detectGlobalFunctions = () => {
      let nativeNames = new Set();
      try {
        const probe = document.createElement('iframe');
        probe.style.display = 'none';
        document.documentElement.appendChild(probe);
        nativeNames = new Set(Object.getOwnPropertyNames(probe.contentWindow));
        probe.parentNode.removeChild(probe);
      } catch (e) {}
      const results = [];
      for (const name of Object.getOwnPropertyNames(window)) {
        if (nativeNames.has(name) || FRAMEWORK_GLOBAL_NAMES.has(name)) continue;
        if (/^(webpack|__|on[A-Z])/.test(name)) continue;
        let value;
        try { value = window[name]; } catch (e) { continue; }
        if (typeof value !== 'function') continue;
        if (/^\s*class\s/.test(Function.prototype.toString.call(value))) continue;
        let preview = '';
        try { preview = clean(Function.prototype.toString.call(value), 200); } catch (e) {}
        results.push({ name, parameterCount: value.length, preview });
        if (results.length >= CFG.MAX_ITEMS) break;
      }
      return results;
    };

    const extractApiCandidates = text => {
      const callPattern = /(fetch|axios(?:\.\w+)?|\$\.ajax|XMLHttpRequest)\s*\(/g;
      const found = new Set();
      let m;
      while ((m = callPattern.exec(text)) && found.size < 300) {
        const snippet = text.slice(m.index, m.index + 220);
        const urlMatch = snippet.match(/(['"`])((?:https?:\/\/|\/)[^'"`]{2,200})\1/);
        if (urlMatch) found.add(urlMatch[2]);
      }
      return [...found];
    };

    const ACTION_KEYWORDS = ['Guardar', 'Eliminar', 'Buscar', 'Validar', 'Enviar', 'Reenviar', 'Archivar', 'Importar', 'Exportar', 'Imprimir', 'Descargar', 'Cargar', 'Filtrar', 'Ordenar', 'Responder', 'Nuevo', 'Agregar', 'Cancelar', 'Actualizar', 'Confirmar', 'Aceptar', 'Editar', 'Modificar', 'Cerrar'];
    const NORMALIZED_KEYWORDS = ACTION_KEYWORDS.map(k => ({ label: k, norm: normalizeText(k) }));
    const matchActionKeyword = label => {
      if (!label) return null;
      const norm = normalizeText(label);
      const found = NORMALIZED_KEYWORDS.find(k => new RegExp('\\b' + k.norm + '\\b').test(norm));
      return found ? found.label : null;
    };
    const inferAction = el => {
      for (const c of [el.getAttribute('aria-label') || '', el.getAttribute('title') || '', textOf(el, 61)]) {
        if (!c || c.length > 60) continue;
        const match = matchActionKeyword(c);
        if (match) return match;
      }
      return 'Unknown';
    };

    /* Inspeccion estatica completa (todas las secciones del Page_inspector original). Se ejecuta una vez al finalizar. */
    const inspect = () => {
      _all = null;
      const page = { title: document.title, url: SecurityManager.redactUrl(location.href), origin: location.origin, pathname: location.pathname, domain: location.hostname, readyState: document.readyState };
      const frameworks = detectFrameworks();
      const globalFunctions = detectGlobalFunctions();
      const forms = [...document.forms].map(formInfo);
      const formSummary = {
        totalForms: forms.length, requiredFields: forms.reduce((a, f) => a + f.formSummary.requiredFields, 0),
        hiddenFields: forms.reduce((a, f) => a + f.formSummary.hiddenFields, 0), submitButtons: forms.reduce((a, f) => a + f.formSummary.submitButtons, 0)
      };
      const interactiveSelector = "input,select,textarea,button,a,[role='button'],[onclick],[onchange],[onsubmit],[ondblclick]";
      const interactive = [...document.querySelectorAll(interactiveSelector)].slice(0, CFG.MAX_ITEMS).map(el => ({
        ...elementInfo(el), value: 'value' in el ? valueOf(el) : '', href: SecurityManager.redactUrl(el.href || ''), target: el.target || '',
        disabled: 'disabled' in el ? !!el.disabled : false, checked: 'checked' in el ? !!el.checked : false, required: 'required' in el ? !!el.required : false,
        events: { onclick: clean(el.getAttribute('onclick')), onchange: clean(el.getAttribute('onchange')), onsubmit: clean(el.getAttribute('onsubmit')), ondblclick: clean(el.getAttribute('ondblclick')) }
      }));
      const inputs = [...document.querySelectorAll('input')].slice(0, CFG.MAX_ITEMS).map(el => ({
        ...elementInfo(el), inputType: el.type, value: valueOf(el), autocomplete: el.autocomplete || '', checked: !!el.checked, disabled: !!el.disabled, readonly: !!el.readOnly, required: !!el.required
      }));
      const selects = [...document.querySelectorAll('select')].slice(0, CFG.MAX_ITEMS).map(el => ({
        ...elementInfo(el), value: valueOf(el), options: [...el.options].slice(0, 100).map(o => ({ value: o.value, text: clean(o.textContent), selected: o.selected }))
      }));
      const buttons = [...document.querySelectorAll("button, input[type='button'], input[type='submit'], input[type='reset'], [role='button']")].slice(0, CFG.MAX_ITEMS).map(el => ({
        ...elementInfo(el), buttonType: el.getAttribute('type') || el.type || 'button', value: valueOf(el), onclick: clean(el.getAttribute('onclick')),
        formAction: el.getAttribute('formaction') || '', formMethod: el.getAttribute('formmethod') || ''
      }));
      const links = [...document.querySelectorAll('a[href]')].slice(0, CFG.MAX_ITEMS).map(el => ({
        text: clean(el.innerText), href: SecurityManager.redactUrl(el.href), target: el.target || '', id: el.id || '', name: el.getAttribute('name') || '',
        onclick: clean(el.getAttribute('onclick')), selector: SelectorEngine.selector(el)
      }));
      const tables = [...document.querySelectorAll('table')].map(tableInfo).filter(t => t.visible || t.id || t.headers.length || t.rows > 1).slice(0, 300);
      const scripts = [...document.scripts].map((s, index) => ({
        index, src: s.src || '', type: s.type || '', async: !!s.async, defer: !!s.defer, inline: !s.src, inlinePreview: s.src ? '' : clean(s.textContent, 300)
      }));
      const iframes = [...document.querySelectorAll('iframe')].map((iframe, index) => {
        const base = { index, id: iframe.id || '', name: iframe.name || '', src: iframe.src || '', title: iframe.title || '', sandbox: iframe.getAttribute('sandbox') || '', selector: SelectorEngine.selector(iframe), sameOrigin: false };
        try {
          const d = iframe.contentDocument;
          if (d) { base.sameOrigin = true; base.innerTitle = d.title || ''; base.innerForms = d.forms.length; base.innerInputs = d.querySelectorAll('input').length; base.innerLinks = d.querySelectorAll('a[href]').length; }
        } catch (e) { base.accessError = clean(e.message, 150); }
        return base;
      });
      const javascriptElements = all().filter(el => [...el.attributes].some(a => a.name.toLowerCase().startsWith('on'))).slice(0, CFG.MAX_ITEMS).map(el => {
        const events = {};
        for (const a of el.attributes) if (a.name.toLowerCase().startsWith('on')) events[a.name] = clean(a.value, 300);
        return { ...elementInfo(el), events };
      });
      const sourceText = (document.documentElement.outerHTML.slice(0, 2000000) + '\n' + scripts.filter(s => s.inlinePreview).map(s => s.inlinePreview).join('\n'));
      const possibleUrls = [...new Set((sourceText.match(/https?:\/\/[^\s"'<>]+|\/[A-Za-z0-9_\-./?=&%]+/g) || []).map(u => u.replace(/[),;]+$/, '')))].slice(0, 500).map(SecurityManager.redactUrl);
      const staticApiUrls = extractApiCandidates(sourceText);
      const ids = [...document.querySelectorAll('[id]')].map(el => ({ id: el.id, tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', text: textOf(el), selector: SelectorEngine.selector(el) })).slice(0, CFG.MAX_ITEMS);
      const names = [...document.querySelectorAll('[name]')].map(el => ({ name: el.getAttribute('name'), tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '', id: el.id || '', value: 'value' in el ? valueOf(el) : '', selector: SelectorEngine.selector(el) })).slice(0, CFG.MAX_ITEMS);
      const visibleText = [...document.querySelectorAll('h1,h2,h3,h4,h5,label,legend,button,th,span,div,td')].slice(0, 4000).filter(visible)
        .map(el => clean(el.innerText || el.textContent)).filter(t => t && t.length >= 2 && t.length <= CFG.MAX_TEXT && !/^[\d\s.,%$€-]+$/.test(t));
      const uiText = [...new Set(visibleText)].slice(0, 500);
      const actions = [...document.querySelectorAll("button, input[type='button'], input[type='submit'], a[href], [role='button'], [onclick]")].slice(0, CFG.MAX_ITEMS)
        .filter(el => visible(el) && !SelectorEngine.isFrameworkNoise(el))
        .map(el => { const action = inferAction(el); return action === 'Unknown' ? null : { action, selector: SelectorEngine.selector(el), trigger: 'click' }; })
        .filter(Boolean).filter((it, i, arr) => arr.findIndex(x => x.selector === it.selector && x.action === it.action) === i);
      const summary = {
        totalElements: all().length, forms: document.forms.length, inputs: document.querySelectorAll('input').length, selects: document.querySelectorAll('select').length,
        textareas: document.querySelectorAll('textarea').length, buttons: document.querySelectorAll("button, input[type='button'], input[type='submit'], input[type='reset'], [role='button']").length,
        links: document.querySelectorAll('a[href]').length, tables: document.querySelectorAll('table').length, scripts: document.scripts.length, iframes: document.querySelectorAll('iframe').length,
        elementsWithInlineEvents: javascriptElements.length
      };
      const menus = [...document.querySelectorAll("[role='menu'],[role='menubar'],[role='tablist'],nav,[role='listbox'],[role='grid'],[role='treegrid']")].slice(0, 100)
        .map(el => ({ tag: el.localName, role: el.getAttribute('role') || '', selector: SelectorEngine.selector(el), items: el.querySelectorAll("a,button,[role='menuitem'],[role='tab'],[role='option'],[role='row']").length }));
      return { page, frameworks, globalFunctions, forms, formSummary, interactive, inputs, selects, buttons, links, tables, scripts, iframes, javascriptElements, possibleUrls, staticApiUrls, ids, names, uiText, actions, summary, menus, interactiveSelector };
    };

    /* Candidatos de automatizacion, resumen y plantillas (originales) */
    const deriveAutomation = (insp, apiCandidates, workflowCandidates, eventListeners) => {
      const PRIORITY = new Set(['Guardar', 'Buscar', 'Validar', 'Descargar', 'Exportar', 'Enviar']);
      const candidateEls = [...document.querySelectorAll("button, a[href], input, select, textarea, [role='button'], [role='link'], [role='checkbox'], [role='menuitem'], table")];
      const scored = candidateEls.filter(el => {
        if (!visible(el) || SelectorEngine.isFrameworkNoise(el)) return false;
        if (el.tagName.toLowerCase() === 'table' && el.querySelectorAll('tr').length <= 1) return false;
        return true;
      }).map(el => {
        const sel = SelectorEngine.robust(el);
        const tag = el.tagName.toLowerCase();
        const actionType = tag === 'table' ? 'grid' : (tag === 'a' ? 'link' : (tag === 'input' || tag === 'select' || tag === 'textarea' ? 'input' : 'button'));
        const text = SecurityManager.isSensitiveField(el) ? '' : clean(el.getAttribute('aria-label') || el.innerText || el.value || el.getAttribute('title') || '', 80);
        let score = sel.score;
        if (actionType === 'button') { const m = matchActionKeyword(text) || matchActionKeyword(el.getAttribute('title') || ''); if (m && PRIORITY.has(m)) score = Math.min(100, score + 10); }
        if (actionType === 'grid' && el.querySelectorAll('tr').length > 1) score = Math.min(100, score + 5);
        return { text, selector: sel.value, selectorScore: score, actionType };
      }).filter(i => i.selector && i.selectorScore >= 50).sort((a, b) => b.selectorScore - a.selectorScore);
      const automationCandidates = [];
      const seen = new Set();
      for (const it of scored) { if (seen.has(it.selector)) continue; seen.add(it.selector); automationCandidates.push(it); if (automationCandidates.length >= 100) break; }

      const automationSummary = {
        application: clean(document.title, 80).split(/\s[-:|]\s/)[0].trim() || location.hostname,
        keyFields: automationCandidates.filter(c => c.actionType === 'input').slice(0, 10).map(c => c.selector),
        keyActions: automationCandidates.filter(c => c.actionType === 'button').slice(0, 10).map(c => c.selector),
        likelyWorkflows: [...new Set(insp.actions.map(a => a.action))].slice(0, 8),
        keyEndpoints: apiCandidates.slice(0, 10).map(c => c.endpoint)
      };
      const f = automationSummary.keyFields[0] || '', a = automationSummary.keyActions[0] || '', fm = insp.forms.length ? insp.forms[0].selector : '';
      const javascript = [], playwright = [];
      if (f) { javascript.push(`document.querySelector('${f}').value = 'texto'; document.querySelector('${f}').dispatchEvent(new Event('input', { bubbles: true }));`); playwright.push(`await page.fill('${f}', 'texto');`); }
      if (a) { javascript.push(`document.querySelector('${a}').click();`); playwright.push(`await page.click('${a}');`); }
      if (fm) { javascript.push(`const f = document.querySelector('${fm}'); f.requestSubmit ? f.requestSubmit() : f.submit();`); playwright.push(`await page.locator('${fm}').evaluate(f => f.requestSubmit ? f.requestSubmit() : f.submit());`); }
      const automationTemplates = { playwright, javascript };

      const automationReadiness = (() => {
        let score = 0;
        score += Math.min(30, insp.forms.length * 5);
        score += Math.min(25, insp.interactive.length * 0.5);
        score += Math.min(15, apiCandidates.length * 1.5);
        score += Math.min(15, eventListeners.length * 0.3);
        score += Math.min(15, insp.ids.length * 0.1);
        return { score: Math.max(0, Math.min(100, Math.round(score))), formsDetected: insp.forms.length, actionableControls: insp.interactive.length, apiCandidates: apiCandidates.length, eventListeners: eventListeners.length };
      })();

      const importantSelectors = (() => {
        const els = [...document.querySelectorAll("input, select, textarea, button, a[href], [role='button'], [role='link'], [role='checkbox'], [role='menuitem'], [role='combobox'], [id]")];
        const seenS = new Set(), found = [];
        for (const el of els) {
          if (!visible(el) || SelectorEngine.isFrameworkNoise(el)) continue;
          const info = SelectorEngine.robust(el);
          if (info.quality !== 'high' && info.score < 80) continue;
          if (!info.value || seenS.has(info.value)) continue;
          seenS.add(info.value);
          const tag = el.tagName.toLowerCase();
          found.push({ selector: info.value, type: tag === 'a' ? 'link' : (tag === 'input' || tag === 'select' || tag === 'textarea' ? 'input' : 'button'), text: SecurityManager.isSensitiveField(el) ? '' : clean(el.getAttribute('aria-label') || el.innerText || el.value || el.getAttribute('placeholder') || '', 80), score: info.score });
        }
        return found.sort((x, y) => y.score - x.score).slice(0, 50);
      })();
      const scoreBySel = new Map(automationCandidates.map(c => [c.selector, c.selectorScore]));
      const importantActions = (() => {
        const out = [], s = new Set();
        for (const it of insp.actions.map(x => ({ action: x.action, selector: x.selector, score: scoreBySel.has(x.selector) ? scoreBySel.get(x.selector) : 50 })).sort((x, y) => y.score - x.score)) {
          if (s.has(it.selector)) continue; s.add(it.selector); out.push(it); if (out.length >= 50) break;
        }
        return out;
      })();
      const importantTables = [...insp.tables].sort((x, y) => y.rows - x.rows).slice(0, 20).map(t => ({ selector: t.selector, headers: t.headers, rows: t.rows, columns: t.columns, containsLinks: t.containsLinks, containsButtons: t.containsButtons, containsInputs: t.containsInputs }));
      return { automationCandidates, automationSummary, automationTemplates, automationReadiness, importantSelectors, importantActions, importantTables };
    };

    return { visible, attrs, dataAttrs, elementInfo, actionInfo, resolveTarget, tableContext, tableInfo, formInfo, context, inspect, deriveAutomation, matchActionKeyword, valueOf };
  })();

  /* =====================================================================
     NetworkAnalyzer (hooks fetch/XHR originales + tiempos y correlacion)
     ===================================================================== */
  const NetworkAnalyzer = (() => {
    const origAdd = EventTarget.prototype.addEventListener;
    let origFetch = null, OrigXHR = window.XMLHttpRequest, xo = null, xs = null, xh = null, hooked = false;
    const xhrEntries = new WeakMap();
    const isNoiseUrl = url => NOISE_URL_REGEX.test(url);
    const pathOf = url => { try { return new URL(url, location.href).pathname; } catch (e) { return String(url).split('?')[0]; } };

    const newEntry = (source, method, url, headers, body) => {
      const now = Date.now();
      const safeUrl = SecurityManager.redactUrl(clean(url, 500));
      const e = {
        id: 'req-' + (S.seq.req++), source, method: String(method || 'GET').toUpperCase(), url: safeUrl, path: pathOf(url),
        queryString: (() => { try { return SecurityManager.redactUrl(new URL(url, location.href).search || ''); } catch (er) { return ''; } })(),
        headers: SecurityManager.redactHeaders(headers), requestBodyPreview: body ? SecurityManager.redactBody(body) : '',
        responseStatus: null, responseSize: null, responseContentType: '', download: false,
        timestamp: now, startTimestamp: iso(now), endTimestamp: null, durationMs: null, error: '',
        triggeredByAction: (S.lastActionTs && now - S.lastActionTs <= CFG.CORRELATION_WINDOW_MS) ? S.lastActionStep : null
      };
      if (S.network.length < CFG.MAX_NETWORK) S.network.push(e);
      return e;
    };
    const finish = e => { const n = Date.now(); e.endTimestamp = iso(n); e.durationMs = n - e.timestamp; StorageManager.schedule(); };
    const readHeaders = (e, get) => {
      try {
        e.responseContentType = clean(get('content-type') || '', 100);
        const cd = get('content-disposition') || '';
        e.download = /attachment/i.test(cd) || /octet-stream|pdf|zip|excel|spreadsheet|msword/i.test(e.responseContentType);
        const len = get('content-length');
        if (len) e.responseSize = Number(len);
      } catch (er) {}
    };
    const jsonKeys = text => {
      try { const j = JSON.parse(text); const o = Array.isArray(j) ? j[0] : j; if (o && typeof o === 'object') return Object.keys(o).filter(k => !SecurityManager.isSensitiveName(k)).slice(0, 15); } catch (e) {}
      return null;
    };

    const hook = () => {
      if (hooked) return;
      hooked = true;
      origFetch = window.fetch ? window.fetch.bind(window) : null;
      if (origFetch) {
        window.fetch = function (...args) {
          const [resource, init] = args;
          const method = (init && init.method) || (resource && resource.method) || 'GET';
          const url = typeof resource === 'string' ? resource : (resource && resource.url) || String(resource);
          let headers = {};
          try {
            const h = (init && init.headers) || (resource && resource.headers);
            if (h) headers = h instanceof Headers ? Object.fromEntries(h.entries()) : { ...h };
          } catch (e) {}
          const entry = newEntry('fetch', method, url, headers, init && init.body);
          const promise = origFetch(...args);
          promise.then(res => {
            entry.responseStatus = res.status;
            readHeaders(entry, n => res.headers.get(n));
            finish(entry);
            if (/json|text|xml|html/i.test(entry.responseContentType) && !entry.download) {
              try { res.clone().text().then(t => { entry.responseSize = t.length; const k = jsonKeys(t.slice(0, 1000000)); if (k) entry.responseJsonKeys = k; }).catch(() => {}); } catch (e) {}
            }
          }).catch(err => { entry.error = clean(err && err.message, 120); finish(entry); });
          return promise;
        };
      }
      if (OrigXHR) {
        xo = OrigXHR.prototype.open; xs = OrigXHR.prototype.send; xh = OrigXHR.prototype.setRequestHeader;
        OrigXHR.prototype.open = function (method, url, ...rest) {
          xhrEntries.set(this, { method, url: String(url), headers: {}, entry: null });
          return xo.call(this, method, url, ...rest);
        };
        OrigXHR.prototype.setRequestHeader = function (name, value) {
          const p = xhrEntries.get(this);
          if (p) p.headers[name] = value;
          return xh.call(this, name, value);
        };
        OrigXHR.prototype.send = function (body) {
          const p = xhrEntries.get(this);
          if (p) {
            const entry = newEntry('xhr', p.method, p.url, p.headers, body);
            const self = this;
            origAdd.call(this, 'loadend', () => {
              entry.responseStatus = self.status;
              readHeaders(entry, n => self.getResponseHeader(n));
              try { if (!self.responseType || self.responseType === 'text') { entry.responseSize = (self.responseText || '').length; const k = jsonKeys(self.responseText.slice(0, 1000000)); if (k) entry.responseJsonKeys = k; } } catch (e) {}
              finish(entry);
            });
          }
          return xs.call(this, body);
        };
      }
    };
    const unhook = () => {
      if (!hooked) return;
      hooked = false;
      if (origFetch) window.fetch = origFetch;
      if (OrigXHR && xo) { OrigXHR.prototype.open = xo; OrigXHR.prototype.send = xs; OrigXHR.prototype.setRequestHeader = xh; }
    };

    /* Correlacion original accion -> request (click/submit, ventana 4 s) */
    const buildActionNetworkMap = () => {
      const meaningful = S.actions.filter(a => a.actionType === 'click' || a.actionType === 'submit');
      const used = new Set(), map = [];
      for (const it of meaningful) {
        const related = [];
        S.network.forEach((req, i) => {
          if (used.has(i)) return;
          const d = req.timestamp - it.timestampMs;
          if (d >= 0 && d <= CFG.CORRELATION_WINDOW_MS) { related.push({ method: req.method, url: req.url }); used.add(i); }
        });
        if (related.length) map.push({ action: { text: (it.element && (it.element.text || it.element.ariaLabel)) || '', selector: it.selectors ? it.selectors.primarySelector : '' }, step: it.step, requests: related });
      }
      return map.slice(0, CFG.MAX_ITEMS);
    };

    const buildApiCandidates = staticApiUrls => {
      const aggregate = new Map();
      const categorize = (path, methods) => {
        const p = path.toLowerCase();
        if (/login|logon|auth|token|signin|sso/.test(p)) return 'AUTH';
        if (/search|query|find|filter/.test(p)) return 'SEARCH';
        if (/export/.test(p)) return 'EXPORT';
        if (/import|upload/.test(p)) return 'IMPORT';
        if (/download|file|blob|attachment/.test(p)) return 'FILE DOWNLOAD';
        if (methods.some(m => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(m))) return 'CRUD';
        return 'READ';
      };
      const register = (url, method, req) => {
        if (!url || isNoiseUrl(url)) return;
        const path = pathOf(url);
        if (!path || path === '/') return;
        const mutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
        const functionalGet = method === 'GET' && /\/(api|rest|graphql|service|data)\b/i.test(path);
        if (!mutating && !functionalGet && !(req && req.triggeredByAction)) return;
        if (!aggregate.has(path)) aggregate.set(path, { endpoint: path, methods: new Set(), frequency: 0, steps: new Set(), statuses: new Set(), durations: [] });
        const e = aggregate.get(path);
        e.methods.add(method); e.frequency += 1;
        if (req) { if (req.triggeredByAction) e.steps.add(req.triggeredByAction); if (req.responseStatus != null) e.statuses.add(req.responseStatus); if (req.durationMs != null) e.durations.push(req.durationMs); }
      };
      S.network.forEach(r => register(r.url, r.method, r));
      (staticApiUrls || []).forEach(u => register(u, 'GET', null));
      return [...aggregate.values()].map(e => {
        const methods = [...e.methods];
        return {
          endpoint: e.endpoint, methods, category: categorize(e.endpoint, methods), frequency: e.frequency, triggeredByActions: [...e.steps], statuses: [...e.statuses],
          avgDurationMs: e.durations.length ? Math.round(e.durations.reduce((a, b) => a + b, 0) / e.durations.length) : null
        };
      }).sort((a, b) => b.frequency - a.frequency).slice(0, CFG.MAX_ITEMS);
    };

    return { hook, unhook, isNoiseUrl, buildActionNetworkMap, buildApiCandidates };
  })();

  /* =====================================================================
     MutationAnalyzer
     ===================================================================== */
  const MutationAnalyzer = (() => {
    let observer = null;
    const REL_ATTRS = ['aria-expanded', 'aria-hidden', 'aria-selected', 'aria-checked', 'aria-busy', 'hidden', 'disabled', 'open', 'class'];
    const own = n => { const h = UIManager.host(); return !!h && (n === h || h.contains(n)); };

    const overlayKind = el => {
      const g = a => (el.getAttribute(a) || '').toLowerCase();
      const role = g('role');
      if (g('aria-modal') === 'true') return 'modal';
      if (el.localName === 'dialog' || role === 'dialog' || role === 'alertdialog') return 'dialog';
      if (role === 'tooltip') return 'tooltip';
      if (role === 'menu' || role === 'listbox') return 'dropdown';
      const c = typeof el.className === 'string' ? el.className : '';
      if (!c) return null;
      if (/modal/i.test(c)) return 'modal';
      if (/dialog/i.test(c)) return 'dialog';
      if (/popup|popover/i.test(c)) return 'popup';
      if (/drawer|offcanvas/i.test(c)) return 'drawer';
      if (/dropdown|select-menu|autocomplete|listbox/i.test(c)) return 'dropdown';
      if (/toast|snackbar|notification/i.test(c)) return 'toast';
      return null;
    };
    const INNER_OVERLAY = '[role="dialog"],[role="alertdialog"],dialog,[aria-modal="true"],.modal,.ui-dialog,.p-dialog,.mat-dialog-container,.cdk-overlay-pane';

    const snapshotOverlay = el => {
      try {
        const h = el.querySelector('h1,h2,h3,h4,[class*="title" i],[class*="header" i]');
        return {
          title: h ? clean(h.textContent, 100) : clean(el.getAttribute('aria-label') || '', 100), text: clean(el.innerText, 200),
          buttons: [...el.querySelectorAll('button,[role="button"],a[href]')].slice(0, 10).map(b => ({ text: clean(b.innerText || b.getAttribute('aria-label'), 60), selector: SelectorEngine.robust(b).value })),
          fields: [...el.querySelectorAll('input,select,textarea')].slice(0, 15).map(f => ({ name: f.name || f.id || '', type: f.type || f.localName, selector: SelectorEngine.robust(f).value }))
        };
      } catch (e) { return null; }
    };

    const push = (kind, el, extra, after, ts) => {
      if (S.mutations.length >= CFG.MAX_MUTATIONS) return;
      S.mutations.push({
        id: 'mut-' + (S.seq.mut++), timestamp: iso(ts), timestampMs: ts, afterAction: after, kind,
        selector: SelectorEngine.robust(el).value, tag: el.localName, text: SecurityManager.isSensitiveField(el) ? '' : clean(el.textContent, 80), ...extra
      });
    };

    const onMut = records => {
      if (S.status !== 'RECORDING') return;
      const ts = Date.now();
      const after = (S.lastActionTs && ts - S.lastActionTs <= CFG.MUTATION_ATTRIBUTION_MS) ? S.lastActionStep : null;
      const updates = new Map();
      const attrSeen = new Set();
      let budget = CFG.MAX_NODES_PER_BATCH, attrBudget = 20;
      for (const m of records) {
        const t = m.target;
        if (!t || own(t)) continue;
        if (m.type === 'childList') {
          for (const n of m.addedNodes) {
            if (n.nodeType !== 1 || own(n)) continue;
            if (budget-- <= 0) break;
            let kind = overlayKind(n), el = n;
            if (!kind && n.firstElementChild) { const inner = n.querySelector(INNER_OVERLAY); if (inner) { el = inner; kind = overlayKind(inner) || 'dialog'; } }
            if (kind) push('appeared', el, { category: kind, details: snapshotOverlay(el) }, after, ts);
            else if (t.nodeType === 1) { const u = updates.get(t) || { added: 0, removed: 0 }; u.added++; updates.set(t, u); }
          }
          for (const n of m.removedNodes) {
            if (n.nodeType !== 1 || own(n)) continue;
            if (budget-- <= 0) break;
            const kind = overlayKind(n);
            if (kind) push('disappeared', n, { category: kind }, after, ts);
            else if (t.nodeType === 1) { const u = updates.get(t) || { added: 0, removed: 0 }; u.removed++; updates.set(t, u); }
          }
        } else if (m.type === 'attributes' && attrBudget > 0 && t.nodeType === 1) {
          const name = m.attributeName;
          const cat = overlayKind(t);
          if (name === 'class' && !cat) continue;
          const key = t.localName + (t.id || '') + name;
          if (attrSeen.has(key)) continue;
          attrSeen.add(key); attrBudget--;
          const newVal = name === 'class' ? clean(t.getAttribute(name), 120) : t.getAttribute(name);
          if (newVal === m.oldValue) continue;
          push('attributeChange', t, { category: cat || 'attribute', details: { attribute: name, oldValue: clean(m.oldValue, 120), newValue: clean(newVal, 120) } }, after, ts);
        }
      }
      if (after != null) {
        updates.forEach((u, parent) => {
          if (u.added + u.removed < CFG.UPDATE_MIN_NODES && u.added === 0) return;
          push('componentUpdate', parent, { category: 'dynamicRender', details: { added: u.added, removed: u.removed } }, after, ts);
        });
      }
      StorageManager.schedule();
    };

    const start = () => {
      if (observer) return;
      observer = new MutationObserver(onMut);
      observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: REL_ATTRS, attributeOldValue: true });
    };
    const stop = () => { if (observer) { try { onMut(observer.takeRecords()); } catch (e) {} observer.disconnect(); observer = null; } };
    return { start, stop };
  })();

  /* =====================================================================
     StorageManager (persistencia sessionStorage/localStorage)
     ===================================================================== */
  const StorageManager = (() => {
    let timer = null;
    const serialize = () => ({
      v: 1, recId: S.recId, status: S.status, startedAt: S.startedAt, endAt: S.endAt, durationSec: S.durationSec, includeLegacy: S.includeLegacy,
      resumeCount: S.resumeCount, stepCounter: S.stepCounter, lastEventTs: S.lastEventTs, lastActionTs: S.lastActionTs, lastActionStep: S.lastActionStep, lastUrl: S.lastUrl,
      actions: S.actions, used: [...S.used.values()], formSnaps: [...S.formSnaps.entries()], tableSnaps: [...S.tableSnaps.entries()],
      navigation: S.navigation, mutations: S.mutations, network: S.network, seq: S.seq, savedAt: Date.now()
    });
    const write = (obj, handoffAt) => {
      const payload = Object.assign({}, obj, handoffAt ? { handoffAt } : {});
      let json = JSON.stringify(payload);
      try { sessionStorage.setItem(CFG.STORAGE_KEY, json); } catch (e) {
        try {
          payload.network = payload.network.slice(-300); payload.mutations = payload.mutations.slice(-300);
          sessionStorage.setItem(CFG.STORAGE_KEY, JSON.stringify(payload));
        } catch (e2) {}
      }
      if (handoffAt) { try { localStorage.setItem(CFG.HANDOFF_KEY, json); } catch (e) {} }
    };
    const save = handoffAt => { clearTimeout(timer); timer = null; if (S.status === 'RECORDING') write(serialize(), handoffAt); };
    const schedule = () => { if (timer || S.status !== 'RECORDING') return; timer = setTimeout(() => save(), 400); };
    const clear = () => { clearTimeout(timer); timer = null; try { sessionStorage.removeItem(CFG.STORAGE_KEY); } catch (e) {} try { localStorage.removeItem(CFG.HANDOFF_KEY); } catch (e) {} };
    const load = () => {
      let st = null;
      try { const s = sessionStorage.getItem(CFG.STORAGE_KEY); if (s) st = JSON.parse(s); } catch (e) {}
      if (!st) {
        try {
          const l = localStorage.getItem(CFG.HANDOFF_KEY);
          if (l) { const p = JSON.parse(l); if (p.handoffAt && Date.now() - p.handoffAt < 30000) st = p; localStorage.removeItem(CFG.HANDOFF_KEY); }
        } catch (e) {}
      }
      return st && st.v === 1 && st.status === 'RECORDING' ? st : null;
    };
    const restore = st => {
      Object.assign(S, {
        recId: st.recId, startedAt: st.startedAt, endAt: st.endAt, durationSec: st.durationSec, includeLegacy: st.includeLegacy, resumeCount: (st.resumeCount || 0) + 1, resumed: true,
        stepCounter: st.stepCounter, lastEventTs: st.lastEventTs, lastActionTs: st.lastActionTs, lastActionStep: st.lastActionStep, lastUrl: st.lastUrl,
        actions: st.actions || [], used: new Map((st.used || []).map(u => [u.key, u])), formSnaps: new Map(st.formSnaps || []), tableSnaps: new Map(st.tableSnaps || []),
        navigation: st.navigation || [], mutations: st.mutations || [], network: st.network || [], seq: st.seq || S.seq
      });
    };
    return { save, schedule, clear, load, restore };
  })();

  /* =====================================================================
     RecordingManager
     ===================================================================== */
  const RecordingManager = (() => {
    let timer = null;

    const frameContextOf = el => {
      const doc = (el && el.ownerDocument) || document;
      const win = doc.defaultView;
      if (!win || win === window) return { isTop: true, frameUrl: SecurityManager.redactUrl(location.href), frameName: '', depth: 0, framePath: [] };
      let depth = 0; const path = [];
      try { let w = win; while (w !== window && w.frameElement) { path.unshift(SelectorEngine.robust(w.frameElement).value); w = w.parent; depth++; } } catch (e) {}
      return { isTop: false, frameUrl: SecurityManager.redactUrl(win.location.href), frameName: win.name || '', depth, framePath: path };
    };

    const registerForm = (f, fromEl) => {
      if (!f) return;
      const sel = SelectorEngine.robust(f).value;
      let snap = S.formSnaps.get(sel);
      if (!snap) { snap = { ...DOMAnalyzer.formInfo(f, -1), interactions: 0, usedFields: [] }; S.formSnaps.set(sel, snap); }
      snap.interactions++;
      if (fromEl && fromEl !== f) { const fs = SelectorEngine.robust(fromEl).value; if (!snap.usedFields.includes(fs) && snap.usedFields.length < 60) snap.usedFields.push(fs); }
    };
    const registerTable = el => {
      const table = el.closest && el.closest('table');
      if (!table) return;
      const sel = SelectorEngine.robust(table).value;
      if (!S.tableSnaps.has(sel)) S.tableSnaps.set(sel, { ...DOMAnalyzer.tableInfo(table, -1), interactions: 0 });
      S.tableSnaps.get(sel).interactions++;
    };

    const USED_TYPES = new Set(['click', 'dblclick', 'contextmenu', 'input', 'change', 'submit']);
    const markUsed = (el, element, selectors, type, step, frame) => {
      const key = selectors.primarySelector + (frame.framePath.length ? '|' + frame.framePath.join('>') : '');
      let u = S.used.get(key);
      if (!u) {
        u = { key, ...element, selectors, domContext: DOMAnalyzer.context(el), frameContext: frame, interactionCount: 0, actionTypes: {}, firstStep: step, lastStep: step, steps: [] };
        S.used.set(key, u);
      }
      u.interactionCount++; u.actionTypes[type] = (u.actionTypes[type] || 0) + 1; u.lastStep = step;
      if (u.steps.length < 50 && !u.steps.includes(step)) u.steps.push(step);
      registerForm(el.closest && el.closest('form'), el);
      registerTable(el);
    };

    const addAction = (actionType, el, detail = {}, opts = {}) => {
      if (S.status !== 'RECORDING' || S.actions.length >= CFG.MAX_ACTIONS) return null;
      const ts = Date.now();
      const step = S.stepCounter++;
      let element = null, selectors = null;
      const frame = frameContextOf(el);
      if (el && el.nodeType === 1) {
        element = DOMAnalyzer.actionInfo(el);
        selectors = SelectorEngine.build(el);
        const tc = DOMAnalyzer.tableContext(el);
        if (tc) element = { ...element, tableContext: tc };
        if (USED_TYPES.has(actionType)) markUsed(el, element, selectors, actionType, step, frame);
        if (selectors) selectors = { primarySelector: selectors.primarySelector, alternateSelectors: selectors.alternateSelectors, xpath: selectors.xpath, robustSelector: selectors.robustSelector, selectorReliabilityScore: selectors.selectorReliabilityScore, reliabilityFactors: selectors.reliabilityFactors };
      }
      const a = {
        step, timestamp: iso(ts), timestampMs: ts, deltaPreviousMs: ts - (S.lastEventTs || S.startedAt || ts), actionType,
        url: SecurityManager.redactUrl(location.href), pageTitle: document.title, frameContext: frame, element, selectors, detail, context: !!opts.context
      };
      Object.defineProperty(a, '_el', { value: el, writable: true, enumerable: false });
      S.actions.push(a);
      S.lastEventTs = ts;
      if (!opts.context && actionType !== 'scroll') { S.lastActionTs = ts; S.lastActionStep = step; }
      StorageManager.schedule();
      return a;
    };

    const addNavigation = (type, from, to) => {
      const ts = Date.now();
      const after = (S.lastActionTs && ts - S.lastActionTs <= CFG.MUTATION_ATTRIBUTION_MS) ? S.lastActionStep : null;
      S.navigation.push({ id: 'nav-' + (S.seq.nav++), type, timestamp: iso(ts), timestampMs: ts, from: SecurityManager.redactUrl(from || ''), to: SecurityManager.redactUrl(to || ''), title: document.title, afterAction: after });
      S.lastUrl = to || location.href;
      addAction('navigation', null, { navType: type, from: SecurityManager.redactUrl(from || ''), to: SecurityManager.redactUrl(to || '') }, { context: true });
    };

    const detachAll = () => { clearInterval(timer); timer = null; EventCaptureManager.detach(); NetworkAnalyzer.unhook(); MutationAnalyzer.stop(); };
    const attachAll = () => { NetworkAnalyzer.hook(); EventCaptureManager.attach(); MutationAnalyzer.start(); timer = setInterval(tick, 250); };

    const tick = () => {
      if (S.status !== 'RECORDING') return;
      if (Date.now() >= S.endAt) stop('timeout'); else UIManager.render();
    };

    const start = opts => {
      if (S.status === 'RECORDING') return;
      resetState();
      S.durationSec = Math.max(5, Math.min(3600, Number(opts && opts.durationSec) || CFG.DEFAULT_DURATION_SEC));
      S.includeLegacy = !!(opts && opts.includeLegacy);
      S.startedAt = Date.now();
      S.endAt = S.startedAt + S.durationSec * 1000;
      S.status = 'RECORDING';
      attachAll();
      addAction('start', null, { url: SecurityManager.redactUrl(location.href), viewport: { width: innerWidth, height: innerHeight }, userAgent: navigator.userAgent }, { context: true });
      S.navigation.push({ id: 'nav-' + (S.seq.nav++), type: 'start', timestamp: iso(S.startedAt), timestampMs: S.startedAt, from: '', to: SecurityManager.redactUrl(location.href), title: document.title, afterAction: null });
      StorageManager.save();
      UIManager.render();
    };

    const resume = st => {
      StorageManager.restore(st);
      S.status = 'RECORDING';
      attachAll();
      addNavigation('pageLoad', S.lastUrl, location.href);
      UIManager.render();
      if (Date.now() >= S.endAt) stop('timeout-after-navigation');
    };

    const stop = async reason => {
      if (S.status !== 'RECORDING') return;
      EventCaptureManager.flush();
      detachAll();
      S.status = 'STOPPED';
      S.stopReason = reason || 'manual';
      UIManager.render();
      await new Promise(r => setTimeout(r, 50));
      try { await ExportManager.exportAll(); } catch (e) { console.error('MacroRecorder - Treasury Team: error exportando', e); }
      S.status = 'FINISHED';
      StorageManager.clear();
      UIManager.render();
    };

    const cancel = () => {
      if (S.status !== 'RECORDING') return;
      detachAll();
      S.status = 'CANCELLED';
      StorageManager.clear();
      UIManager.render();
    };

    return { start, resume, stop, cancel, addAction, addNavigation, frameContextOf };
  })();

  /* =====================================================================
     EventCaptureManager
     ===================================================================== */
  const EventCaptureManager = (() => {
    const origAdd = EventTarget.prototype.addEventListener;
    const origRemove = EventTarget.prototype.removeEventListener;
    const origHistory = {};
    let origOpen = null;
    let docs = [], attached = false, scrollPending = null, scrollTimer = null, iframeObserver = null, lastScrollDoc = null;
    const DOC_EVENTS = ['click', 'dblclick', 'contextmenu', 'input', 'change', 'submit', 'keydown', 'keyup', 'scroll'];
    const eventListenersLog = [];

    const active = e => S.status === 'RECORDING' && e.target && e.target.nodeType === 1 && !UIManager.isOwn(e);

    const describeValue = el => {
      const tag = el.localName, type = (el.type || '').toLowerCase();
      if (SecurityManager.isSensitiveField(el)) return { value: SecurityManager.REDACTED, redacted: true };
      if (tag === 'select') { const o = [...el.selectedOptions]; return { value: o.map(x => x.value).join(','), selectedText: o.map(x => clean(x.textContent, 80)).join(', ') }; }
      if (type === 'checkbox' || type === 'radio') return { checked: !!el.checked, value: clean(el.value, 100) };
      if (type === 'file') return { files: [...(el.files || [])].map(f => ({ name: f.name, size: f.size, type: f.type })) };
      if (el.isContentEditable && tag !== 'input' && tag !== 'textarea') return { value: clean(el.textContent, 200) };
      return { value: clean(el.value, 300), length: (el.value || '').length };
    };

    const onPointer = e => {
      if (!active(e)) return;
      const el = DOMAnalyzer.resolveTarget(e.target);
      RecordingManager.addAction(e.type, el, { button: e.button, clientX: e.clientX, clientY: e.clientY, ctrl: e.ctrlKey, shift: e.shiftKey, alt: e.altKey, meta: e.metaKey, isTrusted: e.isTrusted, rawTargetTag: e.target.localName });
    };

    const onInput = e => {
      if (!active(e)) return;
      const el = e.target;
      const last = S.actions[S.actions.length - 1];
      const val = describeValue(el);
      const now = Date.now();
      if (last && last._el === el && last.actionType === 'input' && now - last.timestampMs < CFG.INPUT_MERGE_MS) {
        last.detail = { ...last.detail, ...val, events: [...(last.detail.events || ['input']), e.type] };
        last.actionType = e.type;
        last.timestampMs = now; last.timestamp = iso(now);
        S.lastActionTs = now; S.lastEventTs = now;
        StorageManager.schedule();
        return;
      }
      RecordingManager.addAction(e.type, el, { ...val, events: [e.type] });
    };

    const onSubmit = e => {
      if (!active(e)) return;
      const f = e.target;
      const fields = [...(f.elements || [])].slice(0, 40).filter(x => x.name || x.id).map(x => ({
        name: x.name || x.id, type: x.type || x.localName, value: SecurityManager.isSensitiveField(x) ? SecurityManager.REDACTED : (x.type === 'file' ? '[file]' : clean(x.value, 80))
      }));
      RecordingManager.addAction('submit', f, { method: (f.method || 'GET').toUpperCase(), action: SecurityManager.redactUrl(f.action || location.href), submitter: e.submitter ? clean(e.submitter.innerText || e.submitter.value, 60) : '', fields });
    };

    const SPECIAL_UP = new Set(['Enter', 'Escape', 'Tab']);
    const onKey = e => {
      if (!active(e)) return;
      const k = e.key;
      if (['Shift', 'Control', 'Alt', 'Meta', 'CapsLock'].includes(k)) return;
      const combo = e.ctrlKey || e.metaKey || e.altKey;
      const special = k.length > 1 || combo;
      if (!special) return;
      if (e.type === 'keyup' && !SPECIAL_UP.has(k)) return;
      const hide = SecurityManager.isSensitiveField(e.target) && k.length === 1;
      RecordingManager.addAction(e.type, e.target, { key: hide ? SecurityManager.REDACTED : k, code: e.code, ctrl: e.ctrlKey, shift: e.shiftKey, alt: e.altKey, meta: e.metaKey, contextOnly: true }, { context: true });
    };

    const flushScroll = () => {
      clearTimeout(scrollTimer); scrollTimer = null;
      const p = scrollPending; scrollPending = null;
      if (!p) return;
      RecordingManager.addAction('scroll', p.el, { target: p.el ? 'element' : 'window', from: p.from, to: p.to, events: p.count }, { context: true });
    };
    const onScroll = e => {
      if (S.status !== 'RECORDING') return;
      const t = e.target;
      if (t && t.nodeType === 1 && UIManager.isOwn(e)) return;
      const isDoc = !t || t.nodeType === 9;
      const win = isDoc ? ((t && t.defaultView) || window) : null;
      const pos = isDoc ? { x: Math.round(win.scrollX), y: Math.round(win.scrollY) } : { x: Math.round(t.scrollLeft), y: Math.round(t.scrollTop) };
      const el = isDoc ? null : t;
      if (scrollPending && (scrollPending.el !== el || scrollPending.win !== win)) flushScroll();
      if (!scrollPending) scrollPending = { el, win, from: pos, to: pos, count: 0 };
      scrollPending.to = pos; scrollPending.count++;
      clearTimeout(scrollTimer);
      scrollTimer = setTimeout(flushScroll, CFG.SCROLL_QUIET_MS);
    };

    const handlers = { click: onPointer, dblclick: onPointer, contextmenu: onPointer, input: onInput, change: onInput, submit: onSubmit, keydown: onKey, keyup: onKey, scroll: onScroll };

    const attachDoc = doc => {
      if (docs.includes(doc)) return;
      docs.push(doc);
      DOC_EVENTS.forEach(t => origAdd.call(doc, t, handlers[t], t === 'scroll' ? { capture: true, passive: true } : true));
    };
    const scanIframes = () => {
      document.querySelectorAll('iframe').forEach(f => {
        try { const d = f.contentDocument; if (d && d.documentElement) attachDoc(d); } catch (e) {}
        try { origAdd.call(f, 'load', () => { try { if (f.contentDocument) attachDoc(f.contentDocument); } catch (e) {} }); } catch (e) {}
      });
    };

    const onHash = e => { if (S.status === 'RECORDING') RecordingManager.addNavigation('hashchange', e.oldURL, e.newURL); };
    const onPop = () => { if (S.status === 'RECORDING') RecordingManager.addNavigation('popstate', S.lastUrl, location.href); };
    const onBeforeUnload = () => {
      if (S.status !== 'RECORDING') return;
      flushScroll();
      RecordingManager.addNavigation('beforeunload', location.href, '');
      StorageManager.save();
    };
    const onPageHide = () => { if (S.status === 'RECORDING') StorageManager.save(); };

    const logListener = (el, type, handler) => {
      try {
        if (!ALLOWED_EVENT_TYPES.has(type)) return;
        const isDelegated = el === document || el === window || el === document.body || el === document.documentElement;
        if (!isDelegated && !(el && el.nodeType === 1)) return;
        if (!isDelegated && UIManager.isOwnNode(el)) return;
        eventListenersLog.push({
          tag: isDelegated ? (el === window ? 'window' : 'document') : el.tagName.toLowerCase(), id: isDelegated ? '' : (el.id || ''), name: isDelegated ? '' : (el.getAttribute('name') || ''),
          selector: isDelegated ? '' : SelectorEngine.selector(el), eventType: type, handlerName: handler && handler.name ? handler.name : '(anonymous)', delegated: isDelegated
        });
      } catch (e) {}
    };

    const scanDevToolsListeners = () => {
      if (typeof getEventListeners !== 'function') return;
      for (const el of [...document.querySelectorAll("input,select,textarea,button,a,[role='button'],[onclick],[onchange],[onsubmit],[ondblclick]")].slice(0, CFG.MAX_ITEMS)) {
        try { const map = getEventListeners(el); for (const type of Object.keys(map)) for (const l of map[type]) logListener(el, type, l.listener); } catch (e) {}
      }
    };

    const attach = () => {
      if (attached) return;
      attached = true;
      attachDoc(document);
      scanIframes();
      iframeObserver = new MutationObserver(ms => { if (ms.some(m => [...m.addedNodes].some(n => n.nodeType === 1 && (n.localName === 'iframe' || (n.querySelector && n.querySelector('iframe')))))) scanIframes(); });
      iframeObserver.observe(document.documentElement, { childList: true, subtree: true });
      origAdd.call(window, 'hashchange', onHash);
      origAdd.call(window, 'popstate', onPop);
      origAdd.call(window, 'beforeunload', onBeforeUnload);
      origAdd.call(window, 'pagehide', onPageHide);
      ['pushState', 'replaceState'].forEach(fn => {
        const orig = history[fn];
        origHistory[fn] = orig;
        const wrapper = function () {
          const from = location.href;
          const r = orig.apply(this, arguments);
          try { if (S.status === 'RECORDING') RecordingManager.addNavigation(fn, from, location.href); } catch (e) {}
          return r;
        };
        origHistory[fn + '_w'] = wrapper;
        history[fn] = wrapper;
      });
      origOpen = window.open;
      window.open = function (url) {
        try { if (S.status === 'RECORDING') { RecordingManager.addAction('window.open', null, { url: SecurityManager.redactUrl(String(url || '')) }, { context: true }); StorageManager.save(Date.now()); } } catch (e) {}
        return origOpen.apply(this, arguments);
      };
      EventTarget.prototype.addEventListener = function (type, handler, options) {
        logListener(this, type, handler);
        return origAdd.call(this, type, handler, options);
      };
      scanDevToolsListeners();
    };

    const detach = () => {
      if (!attached) return;
      attached = false;
      docs.forEach(d => { try { DOC_EVENTS.forEach(t => origRemove.call(d, t, handlers[t], t === 'scroll' ? { capture: true } : true)); } catch (e) {} });
      docs = [];
      if (iframeObserver) { iframeObserver.disconnect(); iframeObserver = null; }
      origRemove.call(window, 'hashchange', onHash);
      origRemove.call(window, 'popstate', onPop);
      origRemove.call(window, 'beforeunload', onBeforeUnload);
      origRemove.call(window, 'pagehide', onPageHide);
      ['pushState', 'replaceState'].forEach(fn => { if (history[fn] === origHistory[fn + '_w']) history[fn] = origHistory[fn]; });
      if (origOpen && window.open !== origOpen) window.open = origOpen;
      EventTarget.prototype.addEventListener = origAdd;
    };

    const flush = () => flushScroll();

    const dedupeEventListeners = list => {
      const map = new Map();
      for (const item of list) {
        const key = `${item.delegated}|${item.tag}|${item.id}|${item.selector}|${item.eventType}`;
        if (!map.has(key)) map.set(key, { ...item, occurrences: 1 }); else map.get(key).occurrences += 1;
      }
      return [...map.values()];
    };
    const getEventListeners_ = () => dedupeEventListeners(eventListenersLog).slice(0, CFG.MAX_ITEMS);

    return { attach, detach, flush, getEventListeners: getEventListeners_ };
  })();

  /* =====================================================================
     WorkflowAnalyzer
     ===================================================================== */
  const WorkflowAnalyzer = (() => {
    const RX = {
      search: /\b(buscar|busqueda|filtrar|consultar|search|find|filter|query)\b/,
      save: /\b(guardar|grabar|enviar|aceptar|confirmar|crear|aprobar|registrar|save|submit|send|create|approve|apply|confirm|accept)\b/,
      download: /\b(descargar|exportar|imprimir|download|export|print)\b/,
      open: /\b(abrir|detalle|detalles|editar|ver|open|view|detail|details|edit)\b/
    };
    const MUT = /^(POST|PUT|PATCH|DELETE)$/;
    const labelOf = a => { const e = a.element || {}; return e.text || e.ariaLabel || e.title || e.labelText || e.placeholder || e.name || e.id || ''; };
    const fieldLabel = a => { const e = a.element || {}; return e.labelText || e.ariaLabel || e.placeholder || e.name || e.id || e.text || ''; };
    const q = s => '"' + s + '"';

    const analyze = (reqsByStep, obsByStep) => {
      const phases = [];
      let prev = null;
      for (const a of S.actions) {
        if (a.actionType === 'scroll' || a.context && a.actionType !== 'start' && a.actionType !== 'navigation') continue;
        const reqs = reqsByStep.get(a.step) || [];
        const obs = obsByStep.get(a.step) || {};
        const label = normalizeText(labelOf(a));
        const t = a.actionType;
        const hasMut = reqs.some(r => MUT.test(r.method));
        const hasSearch = reqs.some(r => RX.search.test(normalizeText(r.path)));
        let phase = null;
        if (t === 'start') phase = 'Abrir pantalla';
        else if (t === 'navigation') {
          const absorbed = prev && ['click', 'dblclick', 'submit'].includes(prev.actionType) && a.timestampMs - prev.timestampMs < 3000;
          phase = absorbed ? null : 'Abrir pantalla';
        } else if (t === 'input' || t === 'change') phase = 'Completar formulario';
        else if (t === 'submit') phase = hasSearch ? 'Buscar' : (reqs.some(r => r.download) ? 'Descargar' : 'Guardar');
        else if (t === 'click' || t === 'dblclick') {
          const opens = obs.navigated || obs.dialogOpened;
          if (reqs.some(r => r.download) || RX.download.test(label)) phase = 'Descargar';
          else if (RX.search.test(label) || hasSearch) phase = 'Buscar';
          else if (RX.save.test(label) || hasMut) phase = 'Guardar';
          else if (a.element && a.element.tableContext) phase = opens || t === 'dblclick' ? 'Abrir detalle' : 'Seleccionar fila';
          else if (opens || RX.open.test(label)) phase = 'Abrir detalle';
          else phase = 'Interactuar';
        }
        if (!a.context || t === 'start' || t === 'navigation') prev = a;
        if (phase) phases.push({ phase, action: a, reqs });
      }
      const groups = [];
      for (const p of phases) {
        const g = groups[groups.length - 1];
        if (g && g.phase === p.phase && p.phase !== 'Abrir pantalla') { g.items.push(p.action); g.reqs.push(...p.reqs); }
        else groups.push({ phase: p.phase, items: [p.action], reqs: [...p.reqs] });
      }
      return groups.map(g => {
        const steps = g.items.map(a => a.step);
        const range = steps.length === 1 ? 'paso ' + steps[0] : `pasos ${steps[0]}-${steps[steps.length - 1]}`;
        const names = [...new Set(g.items.map(a => g.phase === 'Completar formulario' ? fieldLabel(a) : labelOf(a)).filter(Boolean))].slice(0, 6).map(q).join(', ');
        const apis = [...new Map(g.reqs.map(r => [r.method + r.path, r])).values()].slice(0, 4).map(r => `${r.method} ${r.path} -> HTTP ${r.responseStatus == null ? '?' : r.responseStatus}`).join('; ');
        const first = g.items[0];
        let d;
        switch (g.phase) {
          case 'Abrir pantalla': d = 'Abrir la pantalla ' + (() => { try { return new URL(first.url).pathname + (new URL(first.url).hash || ''); } catch (e) { return first.url; } })(); break;
          case 'Completar formulario': d = `Completar ${new Set(g.items.map(a => a.selectors && a.selectors.primarySelector)).size} campo(s): ${names}`; break;
          case 'Buscar': d = 'Ejecutar la busqueda ' + (names ? 'con ' + names : ''); break;
          case 'Seleccionar fila': d = `Seleccionar fila ${first.element && first.element.tableContext ? first.element.tableContext.rowIndex : ''} de la tabla ${first.element && first.element.tableContext ? first.element.tableContext.tableSelector : ''}`; break;
          case 'Abrir detalle': d = 'Abrir el detalle ' + (names ? 'mediante ' + names : ''); break;
          case 'Guardar': d = 'Guardar/confirmar ' + (names ? 'mediante ' + names : ''); break;
          case 'Descargar': d = 'Descargar/exportar ' + (names ? 'mediante ' + names : ''); break;
          default: d = 'Interactuar con ' + names;
        }
        return { phase: g.phase, description: `${d.trim()} (${range})${apis ? ' [API: ' + apis + ']' : ''}`, stepRefs: steps, apis: apis ? apis.split('; ') : [] };
      });
    };

    const candidates = (groups, actionNetworkMap, insp, automationSummary, tables) => {
      const out = [];
      if (groups.length) {
        out.push({ workflow: 'Procedimiento grabado', description: groups.map(g => g.phase).join(' -> '), steps: groups.map(g => g.phase), details: groups.map(g => g.description), stepRefs: groups.map(g => g.stepRefs) });
        groups.forEach((g, i) => {
          if (['Buscar', 'Guardar', 'Descargar', 'Abrir detalle'].includes(g.phase)) {
            const pre = groups[i - 1] && groups[i - 1].phase === 'Completar formulario' ? groups[i - 1] : null;
            out.push({ workflow: g.phase === 'Buscar' ? 'Buscar registros' : g.phase === 'Guardar' ? 'Guardar registro' : g.phase === 'Descargar' ? 'Descargar archivo' : 'Abrir detalle de registro', steps: (pre ? [pre.phase] : []).concat(g.phase), details: (pre ? [pre.description] : []).concat(g.description), stepRefs: (pre ? [pre.stepRefs] : []).concat([g.stepRefs]) });
          }
        });
      }
      const searchField = automationSummary.keyFields[0];
      const searchBtn = insp.actions.find(a => a.action === 'Buscar');
      const mainTable = [...tables].sort((a, b) => b.rows - a.rows)[0];
      if (searchField && (searchBtn || mainTable)) {
        const steps = ['Fill Search Field'];
        if (searchBtn) steps.push('Click Search');
        if (mainTable) steps.push('Wait Table Refresh');
        out.push({ workflow: 'Search Records', steps });
      }
      for (const entry of actionNetworkMap) {
        const label = entry.action.text || 'Action';
        const steps = ['Click ' + label];
        entry.requests.forEach(r => steps.push(`Wait ${r.method} ${r.url}`));
        out.push({ workflow: label + ' Operation', steps, stepRefs: [entry.step] });
      }
      const dedup = [], seen = new Set();
      for (const wf of out) { const k = wf.workflow + '|' + wf.steps.join('>'); if (seen.has(k)) continue; seen.add(k); dedup.push(wf); }
      return dedup.slice(0, 50);
    };

    return { analyze, candidates };
  })();

  /* =====================================================================
     ExportManager
     ===================================================================== */
  const ExportManager = (() => {
    const pad = n => String(n).padStart(2, '0');
    const stamp = () => { const d = new Date(); return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`; };
    const download = (data, filename) => {
      const blob = new Blob([data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    };
    const wait = ms => new Promise(r => setTimeout(r, ms));

    const exportAll = async () => {
      const endedAt = Date.now();
      const insp = DOMAnalyzer.inspect();
      const eventListeners = EventCaptureManager.getEventListeners();
      const apiCandidates = NetworkAnalyzer.buildApiCandidates(insp.staticApiUrls);
      const actionNetworkMap = NetworkAnalyzer.buildActionNetworkMap();

      const reqsByStep = new Map();
      S.network.forEach(r => { if (r.triggeredByAction && !NetworkAnalyzer.isNoiseUrl(r.url)) { if (!reqsByStep.has(r.triggeredByAction)) reqsByStep.set(r.triggeredByAction, []); reqsByStep.get(r.triggeredByAction).push(r); } });
      const mutByStep = new Map(), navByStep = new Map();
      S.mutations.forEach(m => { if (m.afterAction != null) { if (!mutByStep.has(m.afterAction)) mutByStep.set(m.afterAction, []); mutByStep.get(m.afterAction).push(m); } });
      S.navigation.forEach(n => { if (n.afterAction != null) { if (!navByStep.has(n.afterAction)) navByStep.set(n.afterAction, []); navByStep.get(n.afterAction).push(n); } });

      const obsByStep = new Map();
      const observableFor = (a, i) => {
        const muts = mutByStep.get(a.step) || [], navs = navByStep.get(a.step) || [], next = S.actions[i + 1];
        const dialog = muts.find(m => m.kind === 'appeared' && ['modal', 'dialog', 'popup', 'drawer'].includes(m.category));
        const o = {
          urlChanged: navs.length ? { from: navs[0].from, to: navs[navs.length - 1].to } : ((next && next.url !== a.url) ? { from: a.url, to: next.url } : null),
          navigated: navs.length > 0 || !!(next && next.url !== a.url && next.timestampMs - a.timestampMs < 3000),
          dialogOpened: !!dialog, dialogSelector: dialog ? dialog.selector : null,
          dynamicContentUpdated: muts.some(m => m.kind === 'componentUpdate'),
          mutations: muts.slice(0, 10).map(m => ({ id: m.id, kind: m.kind, category: m.category, selector: m.selector, text: m.text })),
          requestsTriggered: (reqsByStep.get(a.step) || []).length
        };
        obsByStep.set(a.step, o);
        return o;
      };
      const observables = S.actions.map(observableFor);

      const groups = WorkflowAnalyzer.analyze(reqsByStep, obsByStep);
      const auto = DOMAnalyzer.deriveAutomation(insp, apiCandidates, [], eventListeners);
      const workflowCandidates = WorkflowAnalyzer.candidates(groups, actionNetworkMap, insp, auto.automationSummary, insp.tables);

      const updFormSnaps = () => [...S.formSnaps.entries()].map(([sel, snap]) => {
        try { const f = document.querySelector(sel); if (f) return { ...DOMAnalyzer.formInfo(f, -1), interactions: snap.interactions, usedFields: snap.usedFields }; } catch (e) {}
        return snap;
      });
      const updTableSnaps = () => [...S.tableSnaps.entries()].map(([sel, snap]) => {
        try { const t = document.querySelector(sel); if (t) return { ...DOMAnalyzer.tableInfo(t, -1), interactions: snap.interactions }; } catch (e) {}
        return snap;
      });
      const usedForms = updFormSnaps(), usedTables = updTableSnaps();

      const metadata = {
        tool: 'MacroRecorder - Treasury Team', version: CFG.VERSION, recordingId: S.recId, generatedAt: iso(endedAt), startedAt: iso(S.startedAt),
        requestedDurationSec: S.durationSec, actualDurationMs: endedAt - S.startedAt, stopReason: S.stopReason || 'manual',
        totalActions: S.actions.length, totalRequests: S.network.length, totalMutations: S.mutations.length, resumedAfterNavigation: S.resumed, resumeCount: S.resumeCount,
        pagesVisited: [...new Set(S.actions.map(a => a.url))], userAgent: navigator.userAgent, viewport: { width: innerWidth, height: innerHeight },
        security: { mode: 'redact-sensitive', redactedValues: SecurityManager.redactionCount(), policy: 'password, token, jwt, apikey, authorization, cookie, secret, bearer, session, csrf -> [REDACTED]' }
      };

      const used = [...S.used.values()];
      const modals = S.mutations.filter(m => m.kind === 'appeared' && ['modal', 'dialog', 'popup', 'drawer', 'dropdown'].includes(m.category))
        .map(m => ({ id: m.id, category: m.category, selector: m.selector, afterAction: m.afterAction, details: m.details || null }));

      const estructura = SecurityManager.sanitize({
        metadata,
        page: { ...insp.page, summary: insp.summary, formSummary: insp.formSummary, menus: insp.menus, automationReadiness: auto.automationReadiness, automationSummary: auto.automationSummary },
        frameworks: insp.frameworks,
        interactedElements: used,
        forms: usedForms.length ? usedForms : insp.forms.slice(0, 5),
        tables: usedTables.length ? usedTables : insp.tables.slice(0, 5),
        navigationEvents: S.navigation.map(({ timestampMs, ...n }) => n),
        observedMutations: S.mutations.map(({ timestampMs, ...m }) => m),
        apiCandidates,
        workflowCandidates,
        detectedModals: modals,
        actionNetworkMap,
        networkRequests: S.network.filter(r => !NetworkAnalyzer.isNoiseUrl(r.url)).map(r => ({ id: r.id, source: r.source, method: r.method, url: r.url, queryString: r.queryString, requestBodyPreview: r.requestBodyPreview, responseStatus: r.responseStatus, responseSize: r.responseSize, responseContentType: r.responseContentType, responseJsonKeys: r.responseJsonKeys, startTimestamp: r.startTimestamp, endTimestamp: r.endTimestamp, durationMs: r.durationMs, triggeredByAction: r.triggeredByAction, error: r.error })),
        legacyInspector: {
          importantSelectors: auto.importantSelectors, importantActions: auto.importantActions, importantTables: auto.importantTables,
          automationCandidates: auto.automationCandidates.slice(0, 40), automationTemplates: auto.automationTemplates, eventListeners: eventListeners.slice(0, 100),
          uiText: insp.uiText.slice(0, 100), globalFunctions: insp.globalFunctions.slice(0, 50)
        }
      });

      const secuencia = SecurityManager.sanitize({
        metadata: { ...metadata, startUrl: S.actions[0] ? S.actions[0].url : '', procedure: groups.map(g => g.description) },
        actions: S.actions.map((a, i) => ({
          step: a.step, timestamp: a.timestamp, deltaPreviousMs: a.deltaPreviousMs, url: a.url, pageTitle: a.pageTitle, frameContext: a.frameContext,
          action: { type: a.actionType, context: a.context, ...a.detail }, element: a.element, selectors: a.selectors, observableResult: observables[i],
          networkRequests: (reqsByStep.get(a.step) || []).map(r => ({ id: r.id, method: r.method, url: r.url, status: r.responseStatus, startTimestamp: r.startTimestamp, endTimestamp: r.endTimestamp, durationMs: r.durationMs, pending: r.responseStatus == null && !r.error, download: r.download, error: r.error || undefined }))
        }))
      });

      download(JSON.stringify(estructura, null, 2), 'estructura_pagina.json');
      await wait(400);
      download(JSON.stringify(secuencia, null, 2), 'secuencia_acciones.json');

      if (S.includeLegacy) {
        const full = SecurityManager.sanitize({
          inspector: { name: 'Compact Page Inspector', version: '3.2', generatedAt: iso(endedAt) },
          page: insp.page, summary: insp.summary, frameworks: insp.frameworks, forms: insp.forms, formSummary: insp.formSummary, inputs: insp.inputs, selects: insp.selects, buttons: insp.buttons,
          links: insp.links, tables: insp.tables, scripts: insp.scripts, iframes: insp.iframes, interactive: insp.interactive, eventListeners, globalFunctions: insp.globalFunctions,
          javascriptElements: insp.javascriptElements, networkActivity: S.network, apiCandidates, possibleUrls: insp.possibleUrls, ids: insp.ids, names: insp.names, uiText: insp.uiText,
          actions: insp.actions, interactionRecording: S.actions.filter(a => ALLOWED_EVENT_TYPES.has(a.actionType)).map(a => ({ timestamp: a.timestampMs, eventType: a.actionType, selector: a.selectors ? a.selectors.primarySelector : '', tag: a.element ? a.element.tag : '', id: a.element ? a.element.id : '', name: a.element ? a.element.name : '', text: a.element ? a.element.text : '', ariaLabel: a.element ? a.element.ariaLabel : '' })),
          actionNetworkMap, automationCandidates: auto.automationCandidates, automationSummary: auto.automationSummary, automationTemplates: auto.automationTemplates, workflowCandidates, automationReadiness: auto.automationReadiness
        });
        const ai = SecurityManager.sanitize({
          page: insp.page, frameworks: insp.frameworks, automationSummary: auto.automationSummary, importantSelectors: auto.importantSelectors, importantActions: auto.importantActions,
          importantTables: auto.importantTables, workflowCandidates, apiCandidates: apiCandidates.slice(0, 50), actionNetworkMap: actionNetworkMap.slice(0, 50).map(e => ({ action: e.action.text, selector: e.action.selector, requests: e.requests })),
          automationTemplates: auto.automationTemplates, automationReadiness: auto.automationReadiness
        });
        await wait(400);
        download(JSON.stringify(full, null, 2), `PageInspector_FULL_${stamp()}.json`);
        await wait(400);
        download(JSON.stringify(ai, null, 2), `PageInspector_AI_${stamp()}.json`);
        window.__MacroRecorderAI_legacy__ = { full, ai };
      }

      window.__MacroRecorderAI_last__ = { estructura, secuencia };
      console.log('MacroRecorder - Treasury Team: JSON generados', { acciones: S.actions.length, requests: S.network.length, mutaciones: S.mutations.length });
    };

    return { exportAll };
  })();

  /* =====================================================================
     UIManager (Shadow DOM, position:fixed, z-index maximo)
     ===================================================================== */
  const UIManager = (() => {
    let hostEl = null, els = {};
    const LABELS = { READY: 'READY', RECORDING: 'RECORDING', STOPPED: 'STOPPED', CANCELLED: 'CANCELLED', FINISHED: 'FINISHED' };
    const COLORS = { READY: '#2563eb', RECORDING: '#dc2626', STOPPED: '#d97706', CANCELLED: '#6b7280', FINISHED: '#16a34a' };

    const build = () => {
      hostEl = document.createElement('div');
      hostEl.id = '__macroRecorderAI_host';
      hostEl.style.cssText = 'all:initial;position:fixed;top:12px;right:12px;z-index:2147483647;';
      const root = hostEl.attachShadow({ mode: 'open' });
      root.innerHTML = `
        <style>
          .p{font:13px/1.4 Arial,sans-serif;background:#111827;color:#fff;border-radius:8px;padding:10px 12px;width:240px;box-shadow:0 8px 24px rgba(0,0,0,.35)}
          .h{display:flex;justify-content:space-between;align-items:center;cursor:move;font-weight:bold;margin-bottom:8px;user-select:none}
          .r{display:flex;justify-content:space-between;align-items:center;margin:4px 0}
          input[type=number]{width:70px;padding:2px 4px;border-radius:4px;border:1px solid #4b5563;background:#1f2937;color:#fff}
          button{font:12px Arial;padding:5px 8px;border:0;border-radius:4px;color:#fff;cursor:pointer;margin-right:4px}
          button:disabled{opacity:.4;cursor:not-allowed}
          .b{display:inline-block;padding:1px 8px;border-radius:10px;font-weight:bold;font-size:11px}
          label{font-size:11px;color:#d1d5db}
        </style>
        <div class="p">
          <div class="h" id="hd"><span>MacroRecorder - Treasury Team</span><span id="x" style="cursor:pointer">&times;</span></div>
          <div class="r"><span>Duracion (s)</span><input id="dur" type="number" min="5" max="3600" value="${CFG.DEFAULT_DURATION_SEC}"></div>
          <div class="r"><span>Estado</span><span class="b" id="st">READY</span></div>
          <div class="r"><span>Tiempo restante</span><span id="rem">--:--</span></div>
          <div class="r"><span id="cnt" style="font-size:11px;color:#9ca3af"></span></div>
          <div class="r"><label><input type="checkbox" id="leg"> Incluir inspector completo (FULL/AI)</label></div>
          <div class="r" style="margin-top:8px"><button id="bs" style="background:#16a34a">Iniciar</button><button id="bx" style="background:#d97706">Detener</button><button id="bc" style="background:#6b7280">Cancelar</button></div>
        </div>`;
      ['dur', 'st', 'rem', 'cnt', 'leg', 'bs', 'bx', 'bc', 'x', 'hd'].forEach(id => { els[id] = root.getElementById(id); });
      els.bs.addEventListener('click', () => RecordingManager.start({ durationSec: Number(els.dur.value), includeLegacy: els.leg.checked }));
      els.bx.addEventListener('click', () => RecordingManager.stop('manual'));
      els.bc.addEventListener('click', () => RecordingManager.cancel());
      els.x.addEventListener('click', () => { if (S.status !== 'RECORDING') { hostEl.remove(); delete window.__MacroRecorderAI__; } });
      let drag = null;
      els.hd.addEventListener('pointerdown', e => { const r = hostEl.getBoundingClientRect(); drag = { dx: e.clientX - r.left, dy: e.clientY - r.top }; els.hd.setPointerCapture(e.pointerId); });
      els.hd.addEventListener('pointermove', e => { if (drag) { hostEl.style.left = (e.clientX - drag.dx) + 'px'; hostEl.style.top = (e.clientY - drag.dy) + 'px'; hostEl.style.right = 'auto'; } });
      els.hd.addEventListener('pointerup', () => { drag = null; });
      (document.body || document.documentElement).appendChild(hostEl);
    };

    const fmt = ms => { const s = Math.max(0, Math.ceil(ms / 1000)); return pad2(Math.floor(s / 60)) + ':' + pad2(s - Math.floor(s / 60) * 60); };
    const pad2 = n => String(n).padStart(2, '0');

    const render = () => {
      if (!hostEl) return;
      const st = S.status, rec = st === 'RECORDING';
      els.st.textContent = LABELS[st]; els.st.style.background = COLORS[st];
      els.rem.textContent = rec ? fmt(S.endAt - Date.now()) : '--:--';
      els.cnt.textContent = (rec || st === 'STOPPED' || st === 'FINISHED') ? `${S.actions.length} acciones · ${S.network.length} requests · ${S.mutations.length} mutaciones` : '';
      els.bs.disabled = rec || st === 'STOPPED';
      els.bx.disabled = !rec; els.bc.disabled = !rec;
      els.dur.disabled = rec; els.leg.disabled = rec;
      if (rec && S.durationSec) els.dur.value = S.durationSec;
    };

    const isOwnNode = n => !!hostEl && (n === hostEl || hostEl.contains(n));
    const isOwn = e => { try { const p = e.composedPath ? e.composedPath() : []; return !!hostEl && (p.includes(hostEl) || isOwnNode(e.target)); } catch (er) { return false; } };
    const show = () => { if (hostEl && !hostEl.isConnected) (document.body || document.documentElement).appendChild(hostEl); render(); };

    return { build, render, show, isOwn, isOwnNode, host: () => hostEl };
  })();

  /* =====================================================================
     Arranque
     ===================================================================== */
  window.__MacroRecorderAI__ = {
    version: CFG.VERSION, show: () => UIManager.show(), start: o => RecordingManager.start(o), stop: () => RecordingManager.stop('manual'),
    cancel: () => RecordingManager.cancel(), state: () => ({ status: S.status, actions: S.actions.length, requests: S.network.length, mutations: S.mutations.length })
  };

  UIManager.build();
  const pending = StorageManager.load();
  if (pending) RecordingManager.resume(pending);
  else UIManager.render();
})();
