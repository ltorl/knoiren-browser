// ================================================================ Peekaboom (static)
//
// A port of proxy.js to a service worker. Everything the Node version did with
// sockets is done with libcurl.js over a Wisp relay, so the proxy needs no
// server of its own: index.html installs this file and it answers every
// request under its own directory.
//
// URLs keep proxy.js's shape: <this directory>__px/<absolute upstream URL>.

const CONFIG = {
  wisp: 'wss://anura.pro/',
  libcurl: 'https://cdn.jsdelivr.net/npm/libcurl.js@0.7.4/libcurl.js',
  wasm: 'https://cdn.jsdelivr.net/npm/libcurl.js@0.7.4/libcurl.wasm',
};

// Where this deployment lives. A worker's scope can never be wider than the
// directory it was served from, so a project page under /name/ proxies under
// /name/__px/ rather than /__px/.
const BASE = new URL(self.registration.scope).pathname;
const PREFIX = BASE + '__px/';
const SW_PATH = BASE + 'sw.js';
// rewriteJs and workerRuntime are shared with the page, where none of these
// constants are in scope; they read the prefix off this global instead.
globalThis.__px$p = PREFIX;
const ORIGIN_COOKIE = '__px_origin';
const UI_ORIGINS = ['*'];
const UPSTREAM_TIMEOUT_MS = 100000;
const MAX_BUFFERED_BYTES = 16 * 1024 * 1024;
const ME = self.location.origin;
// Paths the static host serves -- this worker, its page and the opener that
// writes the page into a blank window -- never proxied.
const HOME_PATH = new RegExp('^' + BASE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  + '(?:index\\.html|200\\.html|404\\.html|sw\\.js|open\\.svg)?$');
const STATE_CACHE = '__px-state';
const STATE_KEY = ME + BASE + '__px_state';

// ---------------------------------------------------------------- libcurl.js

// A service worker may only import scripts while it is first evaluated, so the
// transport is pulled in here and the wasm is compiled on the first request.
let bootError = null;
try { importScripts(CONFIG.libcurl); } catch (err) { bootError = err; }

let session = null;
let curlReady = null;

function curl() {
  if (curlReady) return curlReady;
  curlReady = (async () => {
    if (bootError) throw bootError;
    const st = await state();
    patchLibcurl();
    libcurl.set_websocket(st.wisp || CONFIG.wisp);
    await libcurl.load_wasm(CONFIG.wasm);
    session = new libcurl.HTTPSession();
    return session;
  })();
  curlReady.catch(() => { curlReady = null; });
  return curlReady;
}

let patched = false;
function patchLibcurl() {
  if (patched) return;
  patched = true;
  // Responses with a null-body status must be built without one.
  const make = libcurl.HTTPSession.create_response.bind(libcurl.HTTPSession);
  libcurl.HTTPSession.create_response = (data, info) =>
    make([204, 205, 304].includes(info.status) ? null : data, info);
}

// Upstream request. `headers` is a plain object: unlike fetch(), libcurl sends
// Cookie, Referer, Origin and Sec-* as given.
async function curlFetch(url, init) {
  const s = await curl();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    return await s.fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------- stored state

// Cookies, the Wisp relay and the last site browsed outlive the worker, which
// the browser stops whenever it has been idle for a few seconds.
let stateData = null;
let statePromise = null;

function state() {
  if (statePromise) return statePromise;
  statePromise = (async () => {
    const d = { wisp: CONFIG.wisp, jar: {}, lastSite: null };
    try {
      const hit = await (await caches.open(STATE_CACHE)).match(STATE_KEY);
      if (hit) Object.assign(d, await hit.json());
    } catch (err) {}
    stateData = d;
    return d;
  })();
  return statePromise;
}

let saving = false;
let dirty = false;
async function saveState() {
  dirty = true;
  if (saving) return;
  saving = true;
  while (dirty) {
    dirty = false;
    try {
      const cache = await caches.open(STATE_CACHE);
      await cache.put(STATE_KEY, new Response(JSON.stringify(stateData), {
        headers: { 'content-type': 'application/json' },
      }));
    } catch (err) { break; }
  }
  saving = false;
}

// ---------------------------------------------------------------- cookie jar

// Synthesized responses can't set cookies, so the jar upstream sees lives here
// and is mirrored into real "site~name" cookies for document.cookie to read.
// `visible` leaves out the HttpOnly ones, which a document may not see.
function jarHeader(site, visible) {
  const s = stateData && stateData.jar[site];
  if (!s) return '';
  const now = Date.now();
  const out = [];
  let changed = false;
  for (const name of Object.keys(s)) {
    if (s[name][1] && s[name][1] < now) { delete s[name]; changed = true; continue; }
    if (visible && s[name][2]) continue;
    out.push(name + '=' + s[name][0]);
  }
  if (changed) saveState();
  return out.join('; ');
}

function jarStore(site, cookie, fromPage) {
  if (!stateData || !site) return;
  const parts = String(cookie).split(';');
  const eq = parts[0].indexOf('=');
  if (eq < 0) return;
  const name = parts[0].slice(0, eq).trim();
  if (!name) return;
  const value = parts[0].slice(eq + 1).trim();
  let exp = 0;
  let maxAge = false;
  let httpOnly = false;
  for (const part of parts.slice(1)) {
    const p = part.trim();
    const i = p.indexOf('=');
    const key = (i < 0 ? p : p.slice(0, i)).toLowerCase();
    const v = i < 0 ? '' : p.slice(i + 1).trim();
    if (key === 'max-age') {
      const n = parseInt(v, 10);
      if (!isNaN(n)) { exp = Date.now() + n * 1000; maxAge = true; }
    } else if (key === 'expires' && !maxAge) {
      const t = Date.parse(v);
      if (!isNaN(t)) exp = t;
    } else if (key === 'httponly' && !fromPage) {
      httpOnly = true;
    }
  }
  const jar = stateData.jar[site] || (stateData.jar[site] = {});
  if (exp && exp <= Date.now()) delete jar[name];
  else jar[name] = httpOnly ? [value, exp, 1] : [value, exp];
  saveState();
}

// A write the page made to document.cookie, in stored "site~name=..." form.
function jarFromPage(raw) {
  const s = String(raw || '');
  const eq = s.indexOf('=');
  const semi = s.indexOf(';');
  const end = eq < 0 ? (semi < 0 ? s.length : semi) : eq;
  const full = s.slice(0, end).trim();
  const tilde = full.indexOf('~');
  if (tilde < 0) return;
  jarStore(full.slice(0, tilde), s.slice(tilde + 1), true);
}

// ---------------------------------------------------------------- from proxy.js

const DROP_REQUEST_HEADERS = new Set([
  'host', 'connection', 'keep-alive', 'proxy-connection', 'te', 'trailer', 'transfer-encoding',
  'accept-encoding', 'origin', 'referer', 'cookie', 'cdn-loop', 'x-real-ip', 'x-forwarded-for',
  'x-forwarded-proto', 'x-forwarded-host', 'true-client-ip', 'upgrade', 'expect', 'forwarded', 'via',
  'x-client-ip', 'x-forwarded-port', 'x-forwarded-scheme', 'x-px-dest',
]);

const DROP_RESPONSE_HEADERS = [
  'content-security-policy', 'content-security-policy-report-only', 'x-frame-options',
  'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy',
  'strict-transport-security', 'clear-site-data', 'report-to', 'reporting-endpoints', 'nel',
  'alt-svc', 'link', 'permissions-policy', 'origin-agent-cluster', 'referrer-policy',
  'access-control-allow-origin', 'access-control-allow-credentials',
];

const errText = (err) => String((err && err.cause && err.cause.message) || (err && err.message) || err);

function upstreamFromProxied(href, self) {
  const p = self.origin + PREFIX;
  if (!href || !href.startsWith(p)) return null;
  try { return new URL(href.slice(p.length)); } catch { return null; }
}

function blockedReason(u, self) {
  const h = u.hostname.toLowerCase();
  if (!/^https?:$/.test(u.protocol)) return 'Only http and https URLs can be proxied.';
  if (h === 'localhost' || /\.(localhost|local|internal|lan|home\.arpa)$/.test(h) || !h.includes('.')) {
    return 'Local and internal hostnames cannot be proxied.';
  }
  if (/^[\d.]+$/.test(h) || h.startsWith('[') || h.includes(':')) return 'IP addresses cannot be proxied.';
  if (h === self.hostname) return 'The proxy cannot proxy itself.';
  return null;
}

const SKIP_URL = /^(data|blob|javascript|about|mailto|tel|sms):/i;

// Any URL -> /__px/<absolute upstream URL>
function proxUrl(value, base) {
  const s = value.trim();
  if (!s || s[0] === '#' || s.startsWith(PREFIX) || SKIP_URL.test(s)) return value;
  let abs;
  try { abs = new URL(s, base); } catch { return value; }
  if (!/^(https?|wss?):$/.test(abs.protocol)) return value;
  return PREFIX + abs.href;
}

// Navigational links keep real paths for same-site targets so client-side
// routers see them; the runtime routes the click through the proxy.
function proxLink(value, base, upstream) {
  const s = value.trim();
  if (!s || s[0] === '#' || s.startsWith(PREFIX) || SKIP_URL.test(s)) return value;
  let abs;
  try { abs = new URL(s, base); } catch { return value; }
  if (!/^https?:$/.test(abs.protocol)) return value;
  if (abs.origin === upstream.origin) return abs.pathname + abs.search + abs.hash;
  return PREFIX + abs.href;
}

function proxSrcset(value, base) {
  return mapSrcset(value, (u) => proxUrl(u, base));
}

// Applies fn to each URL in a srcset. URLs may contain commas
// ("w_100,h_100/a.jpg 1x") and candidates needn't be followed by a space
// ("a.jpg 1x,b.jpg 2x"), so this follows the HTML parsing rules. Self-contained
// so it can be stringified into the page runtime.
function mapSrcset(value, fn) {
  const s = String(value);
  const out = [];
  let i = 0;
  while (i < s.length) {
    while (i < s.length && /[\s,]/.test(s[i])) i++;
    if (i >= s.length) break;
    let j = i;
    while (j < s.length && !/\s/.test(s[j])) j++;
    let url = s.slice(i, j);
    let desc = '';
    if (/,$/.test(url)) {
      url = url.replace(/,+$/, '');
    } else {
      let k = j;
      let depth = 0;
      for (; k < s.length; k++) {
        if (s[k] === '(') depth++;
        else if (s[k] === ')') depth--;
        else if (s[k] === ',' && depth <= 0) break;
      }
      desc = s.slice(j, k).trim();
      j = k + 1;
    }
    out.push(fn(url) + (desc ? ' ' + desc : ''));
    i = j;
  }
  return out.join(', ');
}

// `map` lets the page runtime reuse this with its own URL mapper.
function rewriteCss(css, base, map = (u) => proxUrl(u, base)) {
  return css
    .replace(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^"'\s)][^)]*?))\s*\)/gi, (m, dq, sq, bare) => {
      const q = dq != null ? '"' : sq != null ? "'" : '';
      return `url(${q}${map(dq ?? sq ?? bare)}${q})`;
    })
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (m, q, u) => `@import ${q}${map(u)}${q}`)
    // image-set() also takes bare strings: image-set("a.png" 1x, "b.png" 2x)
    .replace(/((?:-webkit-)?image-set\()((?:[^()]|\([^()]*\))*)\)/gi, (m, fn, args) =>
      fn + args.replace(/(^|,)(\s*)(["'])([^"']+)\3/g, (x, c, sp, q, u) => `${c}${sp}${q}${map(u)}${q}`) + ')');
}

function rewriteRefresh(value, base) {
  return value.replace(/(url\s*=\s*['"]?)([^'";]+)/i, (m, pre, u) => pre + proxUrl(u, base));
}

const HTML_CHARSET = /<meta[^>]+charset=["']?([\w-]+)/i;

// Decodes text using the charset from a BOM, the Content-Type header or the
// document itself (`sniff`), falling back to UTF-8, then windows-1252 if the
// bytes aren't valid UTF-8 (what browsers usually do for unlabelled pages).
function decodeText(bytes, contentType, sniff) {
  const charset = sniffCharset(bytes, contentType, sniff);
  if (charset) {
    try { return new TextDecoder(charset).decode(bytes); } catch {}
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return new TextDecoder('windows-1252').decode(bytes);
  }
}

// The declared charset (only the first 4 KB are looked at), or undefined.
function sniffCharset(bytes, contentType, sniff) {
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return 'utf-8';
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return 'utf-16le';
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return 'utf-16be';
  let charset = (/charset=["']?([\w-]+)/i.exec(contentType) || [])[1];
  if (!charset && sniff) {
    const head = new TextDecoder('latin1').decode(bytes.subarray(0, 4096));
    charset = (sniff.exec(head) || [])[1];
    // A document can't really declare itself UTF-16 in ASCII; browsers read that as UTF-8.
    if (/^utf-16/i.test(charset || '')) charset = 'utf-8';
  }
  return charset;
}

// Cookies land on the proxy's origin, which every proxied site shares. Each
// one is stored under its site's name ("example.com~sid") with Path=/ and
// only sent back to that site, and made usable inside a cross-site iframe.
function rewriteCookie(cookie, site, secure) {
  const parts = cookie.split(';').map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return cookie;
  const eq = parts[0].indexOf('=');
  const name = eq < 0 ? '' : parts[0].slice(0, eq);
  const kept = [storedCookieName(name, site) + '=' + parts[0].slice(eq + 1)];
  for (const attr of parts.slice(1)) {
    const a = attr.split('=')[0].trim().toLowerCase();
    if (['domain', 'path', 'samesite', 'secure', 'partitioned'].includes(a)) continue;
    kept.push(attr);
  }
  kept.push('Path=/');
  if (secure) kept.push('SameSite=None', 'Secure', 'Partitioned');
  return kept.join('; ');
}

// The site comes first, so __Host-/__Secure- name rules (which need https)
// don't apply to the stored cookie; the attributes they demand are added anyway.
function storedCookieName(name, site) {
  return site + '~' + name;
}

// The Cookie header for one site, with the site names taken off again.
function siteCookies(header, site) {
  const out = [];
  for (const c of (header || '').split(/;\s*/)) {
    const eq = c.indexOf('=');
    if (eq < 0) continue;
    const m = /^([^~]*)~(.*)$/s.exec(c.slice(0, eq));
    if (!m || m[1] !== site) continue;
    const name = m[2];
    out.push(name ? name + c.slice(eq) : c.slice(eq + 1));
  }
  return out.join('; ');
}

// Cookies are shared by a registrable domain (example.com, example.co.uk), approximately.
function cookieSite(hostname) {
  if (/^[\d.]+$|:/.test(hostname)) return hostname;
  const parts = hostname.toLowerCase().replace(/\.$/, '').split('.');
  const sld = parts[parts.length - 2] || '';
  const n = parts.length > 2 && parts[parts.length - 1].length === 2 &&
    /^(?:co|com|net|org|gov|edu|ac|or|ne|go|gob|nic|mil|ltd|plc|sch|nom|info|biz)$/.test(sld) ? 3 : 2;
  return parts.slice(-n).join('.');
}

// Secure / SameSite=None cookies need https (or localhost, which browsers treat as secure).
function isSecureOrigin(self) {
  return self.protocol === 'https:' || ['localhost', '127.0.0.1', '[::1]'].includes(self.hostname);
}

const URL_ATTRS = ['src', 'action', 'formaction', 'poster', 'background'];

// `base` differs from `upstream` for <iframe srcdoc>, whose document is
// about:srcdoc and resolves URLs against its parent's base.
function rewriteHtml(html, upstream, base = upstream) {
  return htmlRewriter(upstream, base)(html, true);
}

// Returns write(text, final) -> rewritten HTML, for a document arriving in pieces.
function htmlRewriter(upstream, base = upstream) {
  const script = runtimeScript(upstream, PREFIX, false);
  const ctx = { base };
  let injected = false;
  let held = ''; // output from before the runtime's place is known

  const write = htmlTransformer({
    tag(t) {
      const name = t.name;
      if (!injected && (name === 'html' || name === 'head' || name === 'body')) {
        injected = true;
        t.append(script);
      }

      for (const a of URL_ATTRS) {
        const v = t.get(a);
        if (v != null) t.set(a, proxUrl(v, ctx.base));
      }
      for (const a of ['srcset', 'imagesrcset']) {
        const v = t.get(a);
        if (v != null) t.set(a, proxSrcset(v, ctx.base));
      }
      const xlink = t.get('xlink:href');
      if (xlink != null) t.set('xlink:href', name === 'a' ? proxLink(xlink, ctx.base, upstream) : proxUrl(xlink, ctx.base));
      const style = t.get('style');
      if (style != null) t.set('style', rewriteCss(style, ctx.base));
      t.removeAttr('integrity');
      for (const a of t.attrs) {
        if (a.name.charCodeAt(0) === 111 && a.name.charCodeAt(1) === 110) t.set(a.name, rewriteJs(a.value)); // on*
      }

      const href = t.get('href');
      switch (name) {
        case 'base':
          if (href == null) break;
          try { ctx.base = new URL(href, upstream); } catch { break; }
          t.set('href', proxLink(ctx.base.href, upstream, upstream));
          break;
        case 'a':
        case 'area':
          if (href != null) t.set('href', /^\s*javascript:/i.test(href) ? jsHref(href) : proxLink(href, ctx.base, upstream));
          t.removeAttr('ping');
          break;
        case 'link':
        case 'use':
        case 'image':
          if (href != null) t.set('href', proxUrl(href, ctx.base));
          break;
        case 'iframe': {
          const doc = t.get('srcdoc');
          if (doc != null) t.set('srcdoc', rewriteHtml(doc, upstream, ctx.base));
          break;
        }
        case 'object': {
          const data = t.get('data');
          if (data != null) t.set('data', proxUrl(data, ctx.base));
          break;
        }
        case 'meta': {
          const eq = (t.get('http-equiv') || '').toLowerCase();
          if ((t.get('name') || '').toLowerCase() === 'referrer') t.remove();
          else if (eq.startsWith('content-security-policy') || eq === 'x-frame-options') t.remove();
          else if (eq === 'refresh') t.set('content', rewriteRefresh(t.get('content') || '', ctx.base));
          else if (eq === 'content-type') t.set('content', 'text/html; charset=utf-8');
          if (t.get('charset') != null) t.set('charset', 'utf-8');
          break;
        }
      }
    },
    rawText(t, text) {
      if (t.name === 'style') return rewriteCss(text, ctx.base);
      if (t.name === 'script' && (t.get('type') || '').trim().toLowerCase() === 'importmap') {
        return rewriteImportMap(text, ctx.base);
      }
      if (t.name === 'script' && isJsType(t.get('type'))) return cachedRewriteJs(text, ctx.base.href);
      return text;
    },
  });

  return (text, final) => {
    const out = write(text, final);
    if (injected) {
      if (!held) return out;
      const all = held + out;
      held = '';
      return all;
    }
    held += out;
    if (!final) return '';
    // No <html>/<head>/<body> tag: put the runtime first, after any doctype.
    return held.replace(/^(\s*<!doctype[^>]*>)?/i, (m) => m + script);
  };
}

// javascript: URLs keep their code, rewritten like any other script.
function jsHref(href) {
  const i = href.indexOf(':') + 1;
  return href.slice(0, i) + rewriteJs(href.slice(i));
}

function rewriteImportMap(json, base) {
  try {
    const map = JSON.parse(json);
    const fix = (obj) => {
      for (const k of Object.keys(obj || {})) {
        if (typeof obj[k] === 'string') obj[k] = proxUrl(obj[k], base);
      }
    };
    fix(map.imports);
    for (const scope of Object.values(map.scopes || {})) fix(scope);
    return JSON.stringify(map);
  } catch {
    return json;
  }
}

const PAGE_STYLE = `
  :root{color-scheme:light dark;--bg:#f7f7f5;--fg:#1d1d1b;--mute:#6b6b66;--card:#fff;--line:#e4e4df}
  @media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ececea;--mute:#9a9a94;--card:#1e1e1c;--line:#2e2e2b}}
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;padding:16px;box-sizing:border-box}
  .c{max-width:560px;width:100%;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px}
  .s{color:var(--mute);font-size:13px;letter-spacing:.04em;text-transform:uppercase}
  h1{margin:4px 0 12px;font-size:20px}
  pre,code{white-space:pre-wrap;word-break:break-all;font-size:13px}
  pre{color:var(--mute);margin:0}`;

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

function page(status, html) {
  return new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${PAGE_STYLE}</style>${html}`, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function errorPage(status, title, detail) {
  return page(status, `<title>${esc(title)}</title><div class="c"><div class="s">Error ${status}</div><h1>${esc(title)}</h1><pre>${esc(detail)}</pre></div>`);
}

function usagePage(self) {
  const example = `${self.origin}${PREFIX}https://example.com/`;
  return page(self.pathname === '/' ? 200 : 404, `<title>Peekaboom</title><div class="c"><div class="s">Peekaboom</div><h1>Embed a site</h1>
<pre>&lt;iframe src="${esc(example)}"&gt;&lt;/iframe&gt;</pre></div>`);
}

const RAW_TEXT = new Set(['script', 'style', 'textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes', 'noscript']);

const isSpace = (c) => c === 32 || c === 10 || c === 9 || c === 13 || c === 12;

const isAlpha = (c) => (c >= 97 && c <= 122) || (c >= 65 && c <= 90);

// One end-tag regex per raw-text element name, reused (lastIndex is set before each use).
const CLOSE_TAG = new Map();

const closeTag = (name) => {
  let re = CLOSE_TAG.get(name);
  if (!re) CLOSE_TAG.set(name, re = new RegExp(`</${name}[\\s/>]`, 'ig'));
  return re;
};

// Returns write(chunk, final): the input may arrive in pieces, and whatever
// can't be handled yet (a tag cut in half, a <script> without its end tag)
// waits for the next one. The output is the same however the input is split.
function htmlTransformer({ tag: onTag, rawText: onRawText }) {
  let rest = '';
  let raw = null; // { t, close, scan }: a raw-text element still waiting for its end tag

  return function write(chunk, final) {
    const html = rest + chunk;
    const n = html.length;
    const out = [];
    let i = 0;
    for (;;) {
      if (raw) {
        raw.close.lastIndex = raw.scan;
        const m = raw.close.exec(html);
        if (!m && !final) {
          // An end tag can't start before here without having been found already.
          raw.scan = Math.max(0, n - i - raw.t.name.length - 2);
          break;
        }
        const end = m ? m.index : n;
        const text = html.slice(i, end);
        out.push(onRawText ? onRawText(raw.t, text) ?? text : text);
        raw = null;
        i = end;
      }
      if (i >= n) break;
      const lt = html.indexOf('<', i);
      if (lt === -1) { out.push(html.slice(i)); i = n; break; }
      out.push(html.slice(i, lt));
      i = lt;
      if (lt + 1 >= n && !final) break;
      const c = html[lt + 1] || '';

      // Comments, doctype, processing instructions and end tags pass through.
      if (html.startsWith('<!--', lt)) {
        const e = html.indexOf('-->', lt + 4);
        if (e === -1 && !final) break;
        i = e === -1 ? n : e + 3;
        out.push(html.slice(lt, i));
        continue;
      }
      if (c === '!' || c === '?' || c === '/') {
        const e = html.indexOf('>', lt + 1);
        if (e === -1 && !final) break;
        i = e === -1 ? n : e + 1;
        out.push(html.slice(lt, i));
        continue;
      }
      if (!isAlpha(html.charCodeAt(lt + 1))) { out.push('<'); i = lt + 1; continue; }

      const t = parseTag(html, lt);
      if (!t) { // unterminated tag
        if (!final) break;
        out.push(html.slice(lt));
        i = n;
        break;
      }
      i = t.end;
      onTag(t);
      out.push(t.toString(), t.appended);
      if (RAW_TEXT.has(t.name)) raw = { t, close: closeTag(t.name), scan: i };
    }
    rest = i < n ? html.slice(i) : '';
    return out.join('');
  };
}

function parseTag(s, start) {
  const n = s.length;
  let i = start + 1;
  let c;
  while (i < n && !isSpace(c = s.charCodeAt(i)) && c !== 47 && c !== 62) i++; // '/' '>'
  const rawName = s.slice(start + 1, i);
  const attrs = [];
  while (i < n) {
    while (i < n && (isSpace(c = s.charCodeAt(i)) || c === 47)) i++;
    if (i >= n) return null;
    if (c === 62) {
      return new Tag(rawName, attrs, s.charCodeAt(i - 1) === 47, s.slice(start, i + 1), i + 1);
    }
    const nameStart = i;
    i++; // the first character always belongs to the name (even "=")
    while (i < n && !isSpace(c = s.charCodeAt(i)) && c !== 47 && c !== 62 && c !== 61) i++; // '/' '>' '='
    const name = s.slice(nameStart, i);
    let value = null;
    let p = i;
    while (p < n && isSpace(s.charCodeAt(p))) p++;
    if (s.charCodeAt(p) === 61) {
      p++;
      while (p < n && isSpace(s.charCodeAt(p))) p++;
      const q = s[p];
      if (q === '"' || q === "'") {
        const e = s.indexOf(q, p + 1);
        if (e === -1) return null;
        value = s.slice(p + 1, e);
        i = e + 1;
      } else {
        let e = p;
        while (e < n && !isSpace(c = s.charCodeAt(e)) && c !== 62) e++;
        value = s.slice(p, e);
        i = e;
      }
    }
    attrs.push({
      name: name.toLowerCase(),
      rawName: name,
      value: value == null ? null : decodeEntities(value),
      text: s.slice(nameStart, i),
    });
  }
  return null;
}

class Tag {
  constructor(rawName, attrs, selfClosing, raw, end) {
    this.name = rawName.toLowerCase();
    this.rawName = rawName;
    this.attrs = attrs;
    this.selfClosing = selfClosing;
    this.raw = raw;
    this.end = end;
    this.dirty = false;
    this.removed = false;
    this.appended = '';
  }

  attr(name) {
    const attrs = this.attrs;
    for (let i = 0; i < attrs.length; i++) if (attrs[i].name === name) return attrs[i];
    return undefined;
  }

  get(name) {
    const a = this.attr(name);
    return a ? a.value ?? '' : null;
  }

  set(name, value) {
    const a = this.attr(name);
    if (a) {
      if (a.value === value) return;
      a.value = value;
      a.text = null;
    } else {
      this.attrs.push({ name, rawName: name, value, text: null });
    }
    this.dirty = true;
  }

  removeAttr(name) {
    if (!this.attr(name)) return;
    const before = this.attrs.length;
    this.attrs = this.attrs.filter((x) => x.name !== name);
    if (this.attrs.length !== before) this.dirty = true;
  }

  remove() { this.removed = true; }

  // Insert HTML right after this start tag.
  append(html) { this.appended += html; }

  toString() {
    if (this.removed) return '';
    if (!this.dirty) return this.raw;
    const parts = this.attrs.map((a) => a.text ?? `${a.rawName}="${escapeAttr(a.value ?? '')}"`);
    return `<${this.rawName}${parts.length ? ' ' + parts.join(' ') : ''}${this.selfClosing ? ' /' : ''}>`;
  }
}

const NAMED = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0' };

function decodeEntities(s) {
  if (!s.includes('&')) return s;
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+)(;?)(?=(.?))/gi, (m, e, semi, next) => {
    // In attributes, "&lt=" or "&ampx" without a semicolon is left as written.
    if (!semi && /[=a-z0-9]/i.test(next)) return m;
    if (e[0] === '#') {
      const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      try { return String.fromCodePoint(code); } catch { return m; }
    }
    return NAMED[e.toLowerCase()] ?? m;
  });
}

function escapeAttr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
}

// Rewrites a script so it sees the site's own address instead of the proxy's:
// `location`, `window.location`, `document.location`, `top` and `parent` go
// through stand-ins the page runtime provides, eval() and import() arguments
// are rewritten / proxied at run time, and absolute static import specifiers
// point at the proxy. It tokenizes (strings, templates, regexes, comments)
// rather than fully parsing, so it is fast but heuristic; `check(code)`, when
// given, rejects output that no longer compiles. It never throws: on anything
// unexpected the original code is returned. Self-contained so it can be
// stringified into the page runtime and the service worker.
function rewriteJs(code, base, check) {
  const MARK = '/*__px*/';
  if (typeof code !== 'string') return code;
  const hb = /^#![^\n]*\n?/.exec(code);
  const head = hb ? hb[0] : '';
  const src = code.slice(head.length);
  if (src.startsWith(MARK)) return code;
  if (!/\b(?:location|eval|import|export|top|parent)\b/.test(src)) return code;

  try {
    const r = rewrite(src);
    const out = head + MARK + r.code;
    // Unchanged code needs no check, and a module never compiles as a script
    // (so the check would keep `out` anyway).
    if (check && r.edited && !r.module && !check(out) && check(code)) return code;
    return out;
  } catch (e) {
    return code;
  }

  function rewrite(src) {
    const toks = tokenize(src);
    const edits = [];
    let isModule = false;
    // Names the script declares itself (as a variable, parameter, ...) are left alone.
    const skip = { location: false, top: false, parent: false };
    // Each mention is checked by hand: one big regex with lookbehinds was the
    // slowest part of the rewrite.
    const ws = (c) => c === 32 || (c >= 9 && c <= 13) || (c > 127 && /\s/.test(String.fromCharCode(c)));
    const word = (c) => (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c === 95;
    const declared = (s, e) => {
      let a = s;
      while (a > 0 && ws(src.charCodeAt(a - 1))) a--;
      let b = e;
      while (b < src.length && ws(src.charCodeAt(b))) b++;
      // var top / function parent / class location
      if (a < s) {
        for (const kw of ['var', 'let', 'const', 'function', 'class']) {
          const k = a - kw.length;
          if (k >= 0 && src.startsWith(kw, k) && !word(src.charCodeAt(k - 1))) return true;
        }
      }
      const pc = src.charCodeAt(a - 1);
      const nc = src.charCodeAt(b);
      // A parameter or destructured name: (top, ...) / { parent = x }
      if ((pc === 40 || pc === 44 || (pc === 123 && src.charCodeAt(a - 2) !== 36)) &&
        (nc === 44 || nc === 41 || nc === 125 || (nc === 61 && src.charCodeAt(b + 1) !== 61))) return true;
      // top => ... / ...parent
      return (nc === 61 && src.charCodeAt(b + 1) === 62) || (a >= 3 && src.startsWith('...', a - 3));
    };
    const NAME = /\b(?:location|top|parent)\b/g;
    for (let m, found = 0; found < 3 && (m = NAME.exec(src));) {
      if (!skip[m[0]] && declared(m.index, NAME.lastIndex)) { skip[m[0]] = true; found++; }
    }
    const fake = (n) => (n === 'location' ? '(globalThis.__px$L||location)' : `(globalThis.__px$${n}||${n})`);
    const P = (t, v) => t && t.t === 'p' && t.v === v;
    const isDot = (t) => t && t.t === 'p' && (t.v === '.' || t.v === '?.');
    const ASSIGN = new Set(['=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '**=', '<<=', '>>=', '>>>=', '&&=', '||=', '??=']);
    const isAssign = (t) => t && t.t === 'p' && ASSIGN.has(t.v);
    const WIN = new Set(['window', 'self', 'globalThis', 'document', 'top', 'parent']);

    const stack = []; // open brackets: { cls, ev: [edit indexes] | null }
    let pendingClass = false;
    const inClass = () => stack.length > 0 && stack[stack.length - 1].cls;
    // A bare name in a class body right after `{ } ;`, a value or a modifier is a member name.
    const MEMBER_AFTER = new Set(['{', '}', ';', ')', ']', '*']);
    const classMember = (p) => inClass() && (!p || p.t !== 'p' || MEMBER_AFTER.has(p.v));
    const objectKey = (p, nx) => (P(p, '{') || P(p, ',')) && (P(nx, ':') || P(nx, '('));

    for (let k = 0; k < toks.length; k++) {
      const t = toks[k];
      const p = toks[k - 1];
      const nx = toks[k + 1];

      if (t.t === 'q') {
        if (t.cont) stack.pop();
        if (t.open) stack.push({ cls: false, ev: null });
        continue;
      }
      if (t.t === 'p') {
        if (t.v === '{') { stack.push({ cls: pendingClass, ev: null }); pendingClass = false; }
        else if (t.v === '(' || t.v === '[') stack.push({ cls: false, ev: t.ev || null, close: t.close });
        else if (t.v === '}' || t.v === ')' || t.v === ']') {
          const f = stack.pop();
          if (f && f.ev) {
            // `eval(x) {` / `import(x) {` was a method definition, not a call.
            if (P(toks[k + 1], '{')) for (const i of f.ev) edits[i] = null;
            else edits.push([t.s, t.s, f.close]);
          }
        } else if (t.v === ',') {
          const f = stack[stack.length - 1];
          if (f && f.ev && !f.closed) { f.ev.push(edits.length); edits.push([t.s, t.s, f.close]); f.close = ''; f.closed = true; }
        }
        continue;
      }
      if (t.t !== 'i' || isDot(p)) continue;
      // Top-level import / export declarations (and import.meta) only exist in modules.
      if (!stack.length && (t.v === 'export' || (t.v === 'import' && !P(nx, '(')))) isModule = true;

      if (t.v === 'class' && !objectKey(p, nx)) { pendingClass = true; continue; }

      // eval(x) -> eval(__px$js(x)), import(x) -> import(__px$u(x, base))
      if ((t.v === 'eval' || t.v === 'import') && P(nx, '(') && !classMember(p)) {
        const fn = t.v === 'eval' ? '__px$js' : '__px$u';
        nx.ev = [edits.length];
        edits.push([nx.e, nx.e, `(globalThis.${fn}||(x=>x))(`]);
        nx.close = t.v === 'import' && base ? `,${JSON.stringify(base)})` : ')';
        continue;
      }
      // Static imports: import "x" / ... from "x"
      if ((t.v === 'import' || t.v === 'from') && nx && nx.t === 's') {
        const spec = nx.v.slice(1, -1);
        if (/^(?:https?:)?\/\//i.test(spec) || (base && spec[0] === '/')) {
          try {
            const abs = new URL(spec, base || 'https://invalid/');
            if (/^https?:$/.test(abs.protocol)) edits.push([nx.s, nx.e, JSON.stringify((globalThis.__px$p || '/__px/') + abs.href)]);
          } catch (e) {}
        }
        continue;
      }

      // window.location / document.location / window.top / top.location ...
      if (WIN.has(t.v) && P(nx, '.') && toks[k + 2] && toks[k + 2].t === 'i' && !classMember(p) && !objectKey(p, nx)) {
        let obj = (t.v === 'top' || t.v === 'parent') && !skip[t.v] ? fake(t.v) : t.v;
        let j = k;
        let changed = false;
        if (t.v !== 'document' && (toks[j + 2].v === 'top' || toks[j + 2].v === 'parent') && !isAssign(toks[j + 3])) {
          const n = toks[j + 2].v;
          obj = `(${obj}.__px$${n}||${obj}.${n})`;
          j += 2;
          changed = true;
        }
        if (P(toks[j + 1], '.') && toks[j + 2] && toks[j + 2].t === 'i' && toks[j + 2].v === 'location') {
          obj = `(${obj}.__px$L||${obj}.location)` + (isAssign(toks[j + 3]) ? '.href' : '');
          j += 2;
          changed = true;
        }
        if (changed) {
          edits.push([t.s, toks[j].e, obj]);
          k = j;
          continue;
        }
      }

      // Bare location / top / parent.
      if ((t.v === 'location' || t.v === 'top' || t.v === 'parent') && !skip[t.v]) {
        if (objectKey(p, nx) || classMember(p) || P(nx, '(') || P(nx, '=>')) continue;
        if (p && p.t === 'i' && /^(?:var|let|const|function|class|get|set|static|async|typeof)$/.test(p.v) &&
          !(t.v === 'location' && p.v === 'typeof')) continue;
        if (t.v === 'location') {
          edits.push([t.s, t.e, fake('location') + (isAssign(nx) ? '.href' : '')]);
        } else if (!isAssign(nx) && !P(nx, '++') && !P(nx, '--')) {
          edits.push([t.s, t.e, fake(t.v)]);
        }
      }
    }

    const list = edits.filter(Boolean).sort((a, b) => a[0] - b[0]);
    let out = '';
    let pos = 0;
    for (const e of list) {
      out += src.slice(pos, e[0]) + e[2];
      pos = e[1];
    }
    return { code: out + src.slice(pos), edited: list.length > 0, module: isModule };
  }

  // Significant tokens: i(dent), p(unct), s(tring), n(umber), r(egex), q (template chunk).
  function tokenize(src) {
    const n = src.length;
    const toks = [];
    const parens = [];
    const braces = [];
    const KW = new Set(['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw',
      'case', 'do', 'else', 'yield', 'await', 'extends']);
    const CTL = new Set(['if', 'while', 'for', 'with']);
    const IDC = '\\w$\\u0080-\\u009f\\u00a1-\\u167f\\u1681-\\u1fff\\u200c\\u200d\\u2030-\\u205e\\u2060-\\u2fff\\u3001-\\ufefe\\uff00-\\uffff\\\\';
    const IDENT = new RegExp(`#?[${IDC.replace('\\w', 'A-Za-z_')}][${IDC}]*`, 'y');
    const NUM = /(?:0[xXbBoO][\da-fA-F_]+|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?[\d_]+)?)n?/y;
    const PUNCT = /\.\.\.|>>>=?|===|!==|\*\*=|<<=|>>=|&&=|\|\|=|\?\?=|=>|==|!=|<=|>=|&&|\|\||\?\?|\?\.(?!\d)|\+\+|--|[-+*/%&|^]=|\*\*|<<|>>|[{}()[\];,<>+\-*/%&|^!~?:=.@#]/y;
    let prev = null;
    const push = (t) => { toks.push(t); prev = t; };
    const regexOk = () => {
      if (!prev) return true;
      switch (prev.t) {
        case 'n': case 's': case 'r': return false;
        case 'q': return prev.open;
        case 'i': return KW.has(prev.v);
        default:
          if (prev.v === ')') return prev.ctl;
          return !(prev.v === ']' || prev.v === '++' || prev.v === '--');
      }
    };
    const tpl = (s, cont) => {
      let j = s;
      while (j < n) {
        const c = src[j];
        if (c === '\\') j += 2;
        else if (c === '`') { push({ t: 'q', s: s - 1, e: j + 1, open: false, cont }); return j + 1; }
        else if (c === '$' && src[j + 1] === '{') {
          braces.push('t');
          push({ t: 'q', s: s - 1, e: j + 2, open: true, cont });
          return j + 2;
        } else j++;
      }
      push({ t: 'q', s: s - 1, e: n, open: false, cont });
      return n;
    };

    let i = 0;
    while (i < n) {
      const c = src.charCodeAt(i);
      if (c === 32 || c === 10 || c === 9 || c === 13 || c === 11 || c === 12 ||
        (c > 127 && /\s/.test(src[i]))) { i++; continue; }
      const ch = src[i];
      if (ch === '/') {
        const d = src[i + 1];
        if (d === '/') { const e = src.indexOf('\n', i); i = e < 0 ? n : e; continue; }
        if (d === '*') { const e = src.indexOf('*/', i + 2); i = e < 0 ? n : e + 2; continue; }
        if (regexOk()) {
          let j = i + 1;
          let cls = false;
          for (; j < n; j++) {
            const x = src[j];
            if (x === '\\') j++;
            else if (x === '\n') { j = -1; break; }
            else if (x === '[') cls = true;
            else if (x === ']') cls = false;
            else if (x === '/' && !cls) break;
          }
          if (j > 0 && j < n) {
            j++;
            while (j < n && /[a-z]/i.test(src[j])) j++;
            push({ t: 'r', s: i, e: j });
            i = j;
            continue;
          }
        }
      }
      if (ch === '"' || ch === "'") {
        let j = i + 1;
        for (; j < n; j++) {
          const x = src[j];
          if (x === '\\') j++;
          else if (x === ch || x === '\n') break;
        }
        j = Math.min(j + 1, n);
        push({ t: 's', s: i, e: j, v: src.slice(i, j) });
        i = j;
        continue;
      }
      if (ch === '`') { i = tpl(i + 1, false); continue; }
      if (ch === '}' && braces[braces.length - 1] === 't') { braces.pop(); i = tpl(i + 1, true); continue; }

      // Plain ASCII names (nearly all of them) without the regex.
      if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90) || c === 95 || c === 36) {
        let j = i + 1;
        let d = src.charCodeAt(j);
        while ((d >= 97 && d <= 122) || (d >= 65 && d <= 90) || (d >= 48 && d <= 57) || d === 95 || d === 36) d = src.charCodeAt(++j);
        if (!(d > 127 || d === 92)) { push({ t: 'i', s: i, e: j, v: src.slice(i, j) }); i = j; continue; }
      }
      IDENT.lastIndex = i;
      let m = IDENT.exec(src);
      if (m) { push({ t: 'i', s: i, e: i + m[0].length, v: m[0] }); i += m[0].length; continue; }
      if ((c >= 48 && c <= 57) || (ch === '.' && /\d/.test(src[i + 1] || ''))) {
        NUM.lastIndex = i;
        m = NUM.exec(src);
        const e = i + (m ? m[0].length || 1 : 1);
        push({ t: 'n', s: i, e });
        i = e;
        continue;
      }
      // Punctuation that can't start a longer operator skips the regex.
      let v;
      const d = src.charCodeAt(i + 1);
      if (c === 40 || c === 41 || c === 123 || c === 125 || c === 91 || c === 93 || c === 59 || c === 44 || c === 58 ||
        c === 126 || c === 64 || (c === 46 && d !== 46) || (c === 61 && d !== 61 && d !== 62)) v = ch;
      else {
        PUNCT.lastIndex = i;
        m = PUNCT.exec(src);
        v = m ? m[0] : ch;
      }
      const tok = { t: 'p', s: i, e: i + v.length, v };
      if (v === '{') braces.push('b');
      else if (v === '}') braces.pop();
      else if (v === '(') parens.push(!!(prev && prev.t === 'i' && CTL.has(prev.v)));
      else if (v === ')') tok.ctl = !!parens.pop();
      push(tok);
      i += v.length;
    }
    return toks;
  }
}

function isJsType(type) {
  const t = (type || '').trim().toLowerCase().split(';')[0];
  return t === '' || t === 'module' || /^(?:text|application)\/(?:x-)?(?:javascript|ecmascript|jscript|livescript)/.test(t);
}

// Runs first in dedicated and shared workers loaded through the proxy, and in
// blob: workers made by proxied pages (blobSite is then the page's site).
// A module worker's static imports are fetched as "worker" too, so each of
// them gets it as well. data: workers don't get it.
function workerRuntime(PREFIX, blobSite) {
  if (self.__px$L) return;
  const real = self.location;
  const ME = real.origin;
  const MEU = new URL(ME);
  const P = ME + PREFIX;
  globalThis.__px$p = PREFIX;
  const WSP = (MEU.protocol === 'https:' ? 'wss://' : 'ws://') + MEU.host + PREFIX;
  let UP;
  try {
    // blob:<proxy>/<id> is reported as blob:<site>/<id>; like a real blob URL,
    // it can't resolve relative URLs.
    if (blobSite) UP = new URL('blob:' + blobSite + real.pathname.slice(real.pathname.lastIndexOf('/')));
    else if (real.href.startsWith(P)) UP = new URL(real.href.slice(P.length));
    else return;
  } catch (e) { return; }

  function prox(u) {
    if (u == null) return u;
    const s = String(u instanceof URL ? u.href : u).trim();
    if (!s || s.startsWith(PREFIX) || s.startsWith(P) || /^(data|blob|javascript|about):/i.test(s)) return u;
    let x;
    try { x = new URL(s, UP.href); } catch (e) { return u; }
    if (x.origin === ME) x = new URL(x.pathname + x.search + x.hash, UP.origin);
    if (x.protocol === 'ws:' || x.protocol === 'wss:') return WSP + x.href;
    return /^https?:$/.test(x.protocol) ? P + x.href : u;
  }
  function unprox(s) {
    if (typeof s !== 'string') return s;
    if (s.startsWith(P)) return s.slice(P.length);
    if (s.startsWith(WSP)) return s.slice(WSP.length);
    return s;
  }
  const hidden = (obj, name, value) => {
    try { Object.defineProperty(obj, name, { value, configurable: true }); } catch (e) {}
  };

  // WorkerLocation is read-only.
  const L = {};
  for (const k of ['href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash']) {
    Object.defineProperty(L, k, { get: () => UP[k], enumerable: true });
  }
  L.toString = () => UP.href;
  L[Symbol.toStringTag] = 'WorkerLocation';
  hidden(self, '__px$L', L);
  hidden(self, '__px$origin', UP.origin);
  hidden(self, '__px$u', (u, base) => {
    if (typeof u !== 'string' && !(u instanceof URL)) return u;
    try { return prox(new URL(String(u), base || UP.href).href); } catch (e) { return u; }
  });
  try { Object.defineProperty(self, 'origin', { get: () => UP.origin, configurable: true }); } catch (e) {}

  const _fetch = self.fetch;
  const reqUrl = Object.getOwnPropertyDescriptor(Request.prototype, 'url').get;
  self.fetch = async function (input, init) {
    if (input instanceof Request) {
      const r = input;
      const p = prox(reqUrl.call(r));
      if (p !== reqUrl.call(r)) {
        const o = {
          method: r.method, headers: r.headers, credentials: r.credentials, cache: r.cache,
          redirect: r.redirect, referrer: r.referrer, referrerPolicy: r.referrerPolicy,
          keepalive: r.keepalive, signal: r.signal, mode: r.mode,
        };
        if (r.body && !(init && 'body' in init)) o.body = await r.arrayBuffer();
        input = new Request(p, o);
      }
    } else {
      input = prox(input);
    }
    return _fetch.call(this, input, init);
  };
  if (self.XMLHttpRequest) {
    const _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url, ...rest) { return _open.call(this, method, prox(url), ...rest); };
  }
  if (self.importScripts) {
    const _import = self.importScripts;
    self.importScripts = function (...urls) { return _import.apply(this, urls.map(prox)); };
  }
  for (const name of ['WebSocket', 'EventSource', 'Worker', 'SharedWorker']) {
    const Orig = self[name];
    if (!Orig) continue;
    self[name] = new Proxy(Orig, {
      construct(target, args, newTarget) {
        if (name === 'WebSocket' && args.length) {
          try {
            const x = new URL(String(args[0] instanceof URL ? args[0].href : args[0]), UP.href);
            if (/^https?:$/.test(x.protocol)) x.protocol = x.protocol === 'https:' ? 'wss:' : 'ws:';
            args[0] = x.href;
          } catch (e) {}
        }
        if (args.length) args[0] = prox(args[0]);
        return Reflect.construct(target, args, newTarget);
      },
    });
  }
  const GETTERS = [['Response', 'url'], ['Request', 'url'], ['XMLHttpRequest', 'responseURL'],
    ['WebSocket', 'url'], ['EventSource', 'url'], ['PerformanceEntry', 'name']];
  for (const [cls, prop] of GETTERS) {
    const proto = self[cls] && self[cls].prototype;
    const desc = proto && Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || !desc.get) continue;
    Object.defineProperty(proto, prop, { ...desc, get() { return unprox(desc.get.call(this)); } });
  }
}

const WORKER_PRELUDE = `(function(__name){(${workerRuntime})(${JSON.stringify(PREFIX)});})(function(f){return f;});`;

// A leading "use strict" must stay first to keep applying to the script.
function withWorkerRuntime(js) {
  const strict = /^\s*(?:(?:\/\/[^\n]*|\/\*[\s\S]*?\*\/)\s*)*(['"])use strict\1/.test(js);
  return (strict ? '"use strict";' : '') + WORKER_PRELUDE + '\n' + js;
}

// Runs inside every proxied HTML page before any site script.
//
// Proxied URLs look like  <worker>/__px/https://site.com/path.  In the outermost
// proxied frame the address is immediately replaced with the site's real path
// (<worker>/path) so client-side routers see the paths they expect. Requests
// the page then makes are pointed back at /__px/... here, and anything that
// slips through is caught by the service worker, or resolved by the server
// from the Referer or __px_origin cookie. Scripts are rewritten (rewriteJs) to
// read location / top / parent through the stand-ins defined here.
function runtime(C, rewriteJs, mapSrcset, rewriteCss, workerRuntime) {
  // A frame's initial about:blank window is reused when it navigates to a
  // same-origin page, keeping everything installed here. The new document's
  // runtime then only switches the existing one over to its site.
  if (window.__pxRuntime) {
    if (!document.__px$L) window.__pxRuntime(C);
    return;
  }

  // location.origin is "null" in about:blank / srcdoc frames; self.origin is the
  // document's real (inherited) origin and isn't patched yet at this point.
  const ME = self.origin && self.origin !== 'null' ? self.origin : location.origin;
  const MEU = new URL(ME);
  const P = ME + C.prefix;
  globalThis.__px$p = C.prefix;
  const WSP = (MEU.protocol === 'https:' ? 'wss://' : 'ws://') + MEU.host + C.prefix;
  let UP = new URL(C.upstream);
  const fnSource = Function.prototype.toString;
  const baseDesc = Object.getOwnPropertyDescriptor(Node.prototype, 'baseURI');
  const _getAttr = Element.prototype.getAttribute;
  const _replaceState = history.replaceState;

  let nested = false;
  try { nested = window.parent !== window && !!window.parent.__pxRuntime; } catch (e) {}

  // Upstream URL of the current document / base.
  function upHere() {
    if (location.href.startsWith(P)) return location.href.slice(P.length);
    if (location.protocol === 'about:') return location.href;
    return UP.origin + location.pathname + location.search + location.hash;
  }
  function upBase() {
    const b = baseDesc.get.call(document);
    if (b.startsWith(P)) return b.slice(P.length);
    try {
      const x = new URL(b);
      if (x.origin === ME) return UP.origin + x.pathname + x.search;
    } catch (e) {}
    return upHere();
  }

  function isProxied(s) { return s.startsWith(C.prefix) || s.startsWith(P); }

  function prox(u) {
    if (u == null) return u;
    const s = String(u instanceof URL ? u.href : u).trim();
    if (!s || s[0] === '#' || isProxied(s) || /^(data|blob|javascript|about|mailto|tel|sms):/i.test(s)) return u;
    let x;
    try { x = new URL(s, upBase()); } catch (e) { return u; }
    if (x.origin === ME) x = new URL(x.pathname + x.search + x.hash, UP.origin);
    if (!/^(https?|wss?):$/.test(x.protocol)) return u;
    if (x.protocol === 'ws:' || x.protocol === 'wss:') {
      return WSP + x.href;
    }
    return P + x.href;
  }

  function proxSrcset(v) {
    return mapSrcset(v, prox);
  }
  function unproxSrcset(v) {
    return mapSrcset(v, unproxAttr);
  }

  // Secure / SameSite=None cookies need https (or localhost, which browsers treat as secure).
  const secureCtx = MEU.protocol === 'https:' || ['localhost', '127.0.0.1', '[::1]'].includes(MEU.hostname);
  const cookieAttrs = '; path=/' + (secureCtx ? '; SameSite=None; Secure; Partitioned' : '');


  // Storage. Cookies, localStorage, sessionStorage and IndexedDB all belong to
  // the proxy's origin, which every proxied site shares, so each site gets its
  // own namespace. Cookies match the server's naming ("example.com~sid").
  let CS = C.cookieSite + '~';
  const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
  if (cookieDesc && cookieDesc.get && cookieDesc.set) {
    Object.defineProperty(Document.prototype, 'cookie', {
      ...cookieDesc,
      get() {
        return cookieDesc.get.call(this).split(/;\s*/).filter((c) => c.startsWith(CS))
          .map((c) => c.slice(CS.length).replace(/^=/, '')).join('; ');
      },
      set(v) {
        const parts = String(v).split(';').map((x) => x.trim()).filter(Boolean);
        if (!parts.length) return;
        const kept = [CS + (parts[0].includes('=') ? parts[0] : '=' + parts[0])];
        for (const attr of parts.slice(1)) {
          const a = attr.split('=')[0].trim().toLowerCase();
          if (!['domain', 'path', 'samesite', 'secure', 'partitioned'].includes(a)) kept.push(attr);
        }
        cookieDesc.set.call(this, kept.join('; ') + cookieAttrs);
      },
    });
  }
  // The async Cookie Store API can't be namespaced the same way; sites fall back to document.cookie.
  try { delete window.cookieStore; } catch (e) {}
  try { if ('cookieStore' in window) Object.defineProperty(window, 'cookieStore', { value: undefined, configurable: true }); } catch (e) {}

  let SP = UP.origin + '~';
  for (const name of ['localStorage', 'sessionStorage']) {
    let st;
    try { st = window[name]; } catch (e) { continue; }
    if (!st) continue;
    const keys = () => {
      const out = [];
      for (let i = 0; i < st.length; i++) {
        const k = st.key(i);
        if (k != null && k.startsWith(SP)) out.push(k.slice(SP.length));
      }
      return out;
    };
    const api = {
      getItem: (k) => st.getItem(SP + k),
      setItem: (k, v) => st.setItem(SP + k, v),
      removeItem: (k) => st.removeItem(SP + k),
      clear: () => keys().forEach((k) => st.removeItem(SP + k)),
      key: (i) => { const k = keys()[i]; return k === undefined ? null : k; },
    };
    const facade = new Proxy(st, {
      get(t, p) {
        if (p === 'length') return keys().length;
        if (typeof p === 'string' && Object.prototype.hasOwnProperty.call(api, p)) return api[p];
        if (typeof p === 'symbol' || p in Storage.prototype) {
          const v = Reflect.get(t, p);
          return typeof v === 'function' ? v.bind(t) : v;
        }
        const v = st.getItem(SP + p);
        return v === null ? undefined : v;
      },
      set(t, p, v) {
        if (typeof p !== 'string') return false;
        st.setItem(SP + p, v);
        return true;
      },
      has(t, p) {
        return typeof p === 'string' && (p in Storage.prototype || st.getItem(SP + p) !== null);
      },
      deleteProperty(t, p) {
        if (typeof p === 'string') st.removeItem(SP + p);
        return true;
      },
      defineProperty(t, p, d) {
        if (typeof p === 'string' && 'value' in d) st.setItem(SP + p, d.value);
        return true;
      },
      ownKeys: () => keys(),
      getOwnPropertyDescriptor(t, p) {
        const v = typeof p === 'string' ? st.getItem(SP + p) : null;
        return v === null ? undefined : { value: v, writable: true, enumerable: true, configurable: true };
      },
    });
    try { Object.defineProperty(window, name, { get: () => facade, configurable: true, enumerable: true }); } catch (e) {}
  }
  const unSP = (k) => (typeof k === 'string' && k.startsWith(SP) ? k.slice(SP.length) : k);
  const skDesc = window.StorageEvent && Object.getOwnPropertyDescriptor(StorageEvent.prototype, 'key');
  if (skDesc && skDesc.get) {
    Object.defineProperty(StorageEvent.prototype, 'key', { ...skDesc, get() { return unSP(skDesc.get.call(this)); } });
  }
  if (window.IDBFactory) {
    const f = IDBFactory.prototype;
    const { open: idbOpen, deleteDatabase: idbDelete, databases: idbList } = f;
    f.open = function (n, ...rest) { return idbOpen.call(this, SP + n, ...rest); };
    f.deleteDatabase = function (n, ...rest) { return idbDelete.call(this, SP + n, ...rest); };
    if (idbList) {
      f.databases = function () {
        return idbList.call(this).then((l) => l.filter((d) => d.name.startsWith(SP)).map((d) => ({ ...d, name: unSP(d.name) })));
      };
    }
    const nameDesc = Object.getOwnPropertyDescriptor(IDBDatabase.prototype, 'name');
    if (nameDesc && nameDesc.get) {
      Object.defineProperty(IDBDatabase.prototype, 'name', { ...nameDesc, get() { return unSP(nameDesc.get.call(this)); } });
    }
  }

  // Network APIs
  // Streamed request bodies need HTTP/2, which the proxy may not be served
  // over (e.g. plain Node on http://), so read them into a buffer first.
  const isStream = (b) => typeof ReadableStream !== 'undefined' && b instanceof ReadableStream;
  const _fetch = window.fetch;
  const reqUrl = Object.getOwnPropertyDescriptor(Request.prototype, 'url').get;
  window.fetch = async function (input, init) {
    if (init && isStream(init.body)) {
      init = { ...init, body: await new Response(init.body).arrayBuffer() };
      delete init.duplex;
    }
    if (input instanceof Request) {
      const r = input;
      const u = reqUrl.call(r);
      const p = prox(u);
      const hasBody = !!r.body && !(init && 'body' in init);
      if (p !== u || hasBody) {
        const o = {
          method: r.method, headers: r.headers, credentials: r.credentials, cache: r.cache,
          redirect: r.redirect, referrer: r.referrer, referrerPolicy: r.referrerPolicy,
          keepalive: r.keepalive, signal: r.signal,
        };
        if (r.mode !== 'navigate') o.mode = r.mode;
        if (hasBody) o.body = await r.arrayBuffer();
        input = new Request(p, o);
      }
    } else {
      input = prox(input);
    }
    return _fetch.call(this, input, init);
  };

  const _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    return _open.call(this, method, prox(url), ...rest);
  };

  // blob: workers never reach the server or service worker, so remember each
  // blob's Blob and start such workers from a wrapper that runs the worker
  // runtime first. Classic workers then importScripts the original (keeping
  // its "use strict"); module workers import it after the runtime. Wrappers
  // are reused per URL so SharedWorkers stay shared, and are never revoked
  // because the worker may not have loaded them yet.
  const blobs = new Map();
  const wrappers = new Map();
  const _createURL = URL.createObjectURL;
  const _revokeURL = URL.revokeObjectURL;
  URL.createObjectURL = function (obj) {
    const url = _createURL.call(this, obj);
    if (obj instanceof Blob) blobs.set(url, obj);
    return url;
  };
  URL.revokeObjectURL = function (url) {
    blobs.delete(String(url));
    return _revokeURL.call(this, url);
  };
  function blobWorker(u, opts) {
    const s = String(u instanceof URL ? u.href : u);
    const blob = blobs.get(s);
    if (!blob) return u;
    const module = !!opts && typeof opts === 'object' && opts.type === 'module';
    const key = (module ? 'm ' : 'c ') + s;
    if (!wrappers.has(key)) {
      const pre = '(function(__name){(' + fnSource.call(workerRuntime) + ')(' + JSON.stringify(C.prefix) + ','
        + JSON.stringify(UP.origin) + ');})(function(f){return f;});\n';
      const js = (parts) => _createURL(new Blob(parts, { type: 'text/javascript' }));
      const orig = JSON.stringify(_createURL(blob));
      wrappers.set(key, module
        ? js(['import ' + JSON.stringify(js([pre])) + ';import ' + orig + ';'])
        : js([pre + 'importScripts(' + orig + ');']));
    }
    return wrappers.get(key);
  }

  for (const name of ['WebSocket', 'EventSource', 'Worker', 'SharedWorker']) {
    const Orig = window[name];
    if (!Orig) continue;
    window[name] = new Proxy(Orig, {
      construct(target, args, newTarget) {
        // WebSocket also takes http(s) and relative URLs, meaning ws(s) on the site.
        if (name === 'WebSocket' && args.length) {
          try {
            const x = new URL(String(args[0] instanceof URL ? args[0].href : args[0]), upBase());
            if (/^https?:$/.test(x.protocol)) x.protocol = x.protocol === 'https:' ? 'wss:' : 'ws:';
            args[0] = x.href;
          } catch (e) {}
        }
        if (args.length && /Worker$/.test(name)) args[0] = blobWorker(args[0], args[1]);
        if (args.length) args[0] = prox(args[0]);
        return Reflect.construct(target, args, newTarget);
      },
    });
  }

  if (navigator.sendBeacon) {
    const _beacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = (url, data) => _beacon(prox(url), data);
  }

  // A page embedding the outermost frame (the Knoiren UI) can take over new
  // windows: it answers a 'nav' report with { __px: 'host' }, and from then on
  // pop-ups and target=_blank links are posted to it as { __px: 'open' }.
  // The UI (and only the UI's origins; '*' is any) can also run bookmarklets
  // ({ __px: 'run' }) and mute the tab ({ __px: 'mute' }).
  let hostOpens = false;
  let uiOrigins = C.uiOrigins || [];
  if (!C.uiOrigins) try { uiOrigins = [new URL(location.protocol + '//' + location.hostname + ':' + C.uiPort).origin]; } catch (e) {}
  const fromUi = (e) => uiOrigins.indexOf('*') >= 0 || uiOrigins.indexOf(e.origin) >= 0;
  if (!nested && window.parent !== window) {
    addEventListener('message', (e) => {
      if (e.source !== window.parent || !e.data) return;
      if (e.data.__px === 'host') {
        hostOpens = true;
        e.stopImmediatePropagation();
      } else if (e.data.__px === 'run' && fromUi(e) && typeof e.data.code === 'string') {
        e.stopImmediatePropagation();
        try { (0, eval)(js(e.data.code)); } catch (err) { console.error(err); }
      } else if (e.data.__px === 'mute' && fromUi(e)) {
        e.stopImmediatePropagation();
        window.__px$setMuted(!!e.data.muted);
      }
    }, true);
  }
  const isNewWindow = (name) => name == null || name === '' || String(name).toLowerCase() === '_blank';
  function hostOpen(url, user) {
    try { window.parent.postMessage({ __px: 'open', url, user }, '*'); } catch (e) {}
  }

  const _wopen = window.open;
  window.open = function (url, name, ...rest) {
    if (hostOpens && isNewWindow(name)) {
      hostOpen(url == null || url === '' ? 'about:blank' : unprox(String(prox(url))), false);
      return null;
    }
    const t = frameTarget(name);
    return _wopen.call(this, url == null || url === '' ? url : prox(url), t == null ? name : t, ...rest);
  };

  // Our service worker catches whatever these patches miss. The site's own
  // service workers are refused, and it can't see or unregister ours.
  const sw = navigator.serviceWorker;
  if (sw) {
    try {
      sw.register(C.swPath, { scope: C.swScope }).catch(() => {});
      const hello = () => { if (sw.controller) sw.controller.postMessage({ __px: 'origin', origin: UP.origin }); };
      hello();
      sw.addEventListener('controllerchange', () => {
        hello();
        // First visit without server-side script rewriting: reload once now that scripts can be rewritten.
        if (C.swReload && !nested && !sessionStorage.getItem('__px_sw')) {
          sessionStorage.setItem('__px_sw', '1');
          location.reload();
        }
      });
    } catch (e) {}
    try {
      sw.register = () => Promise.reject(new DOMException('Service workers are disabled by the proxy', 'SecurityError'));
      sw.getRegistrations = () => Promise.resolve([]);
      sw.getRegistration = () => Promise.resolve(undefined);
    } catch (e) {}
  }

  // Stand-ins that rewritten scripts use for location, top and parent.
  const real = location;
  function go(u, replace) {
    let x;
    try { x = new URL(String(u), upBase()); } catch (e) { return; }
    if (!/^https?:$/.test(x.protocol)) return replace ? real.replace(String(u)) : real.assign(String(u));
    const here = upHere();
    if (x.hash && x.href.split('#')[0] === here.split('#')[0]) { real.hash = x.hash; return; }
    const p = prox(x.href);
    return replace ? real.replace(p) : real.assign(p);
  }

  // Safety net for navigations the rewriter missed (e.g. an aliased
  // `w.location.href = 'https://site/...'`): cancel any that would leave the
  // proxy and send them through it instead.
  try {
    window.navigation.addEventListener('navigate', (e) => {
      if (!e.cancelable || e.formData || e.downloadRequest || e.navigationType === 'traverse') return;
      let x;
      try { x = new URL(e.destination.url); } catch (err) { return; }
      if (x.origin === ME || !/^https?:$/.test(x.protocol)) return;
      e.preventDefault();
      const p = prox(x.href);
      e.navigationType === 'replace' ? real.replace(p) : real.assign(p);
    });
  } catch (e) {}
  const L = {};
  Object.defineProperty(L, 'href', { get: upHere, set: (v) => go(v), enumerable: true });
  for (const k of ['origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash']) {
    Object.defineProperty(L, k, {
      get: () => new URL(upHere())[k],
      set: k === 'origin' ? undefined : (v) => {
        if (k === 'hash') { real.hash = v; return; }
        const x = new URL(upHere());
        x[k] = v;
        go(x.href);
      },
      enumerable: true,
    });
  }
  // Only the proxied frames count as ancestors, under their sites' origins.
  Object.defineProperty(L, 'ancestorOrigins', {
    get() {
      const l = [];
      try { for (let w = window; w !== pxTop;) { w = w.parent; l.push(w.__px$origin); } } catch (e) {}
      return Object.freeze(Object.assign(l, { item: (i) => (l[i] === undefined ? null : l[i]), contains: (o) => l.includes(o) }));
    },
  });
  L.assign = (u) => go(u);
  L.replace = (u) => go(u, true);
  L.reload = () => real.reload();
  L.toString = upHere;
  L[Symbol.toStringTag] = 'Location';

  let pxTop = window;
  try { while (pxTop.parent !== pxTop && pxTop.parent.__pxRuntime) pxTop = pxTop.parent; } catch (e) {}

  // _top and _parent would leave the proxy for the page embedding it; aim
  // them at the outermost proxied frame instead. Returns null if unchanged.
  function frameTarget(t) {
    const n = String(t || '').toLowerCase();
    if (n === '_top' && pxTop !== window) {
      try {
        if (!pxTop.name) pxTop.name = '__px_top';
        return pxTop.name;
      } catch (e) { return '_self'; }
    }
    if (n === '_top' || (n === '_parent' && !nested)) return '_self';
    return null;
  }
  const baseTarget = () => { const b = document.querySelector('base[target]'); return b ? b.getAttribute('target') : ''; };
  addEventListener('submit', (e) => {
    const f = e.target;
    if (!(f instanceof HTMLFormElement)) return;
    const s = e.submitter;
    if (s && s.hasAttribute('formtarget')) {
      const t = frameTarget(s.getAttribute('formtarget'));
      if (t != null) _setAttr.call(s, 'formtarget', t);
      return;
    }
    const t = frameTarget(f.getAttribute('target') || baseTarget());
    if (t != null) _setAttr.call(f, 'target', t);
  }, true);
  const _submit = HTMLFormElement.prototype.submit; // doesn't fire 'submit'
  HTMLFormElement.prototype.submit = function () {
    const t = frameTarget(this.getAttribute('target') || baseTarget());
    if (t != null) _setAttr.call(this, 'target', t);
    return _submit.call(this);
  };
  const _F = Function;
  const jsCheck = (c) => { try { new _F(c); return true; } catch (e) { return false; } };
  const js = (s) => (typeof s === 'string' ? rewriteJs(s, upBase(), jsCheck) : s);
  const hidden = (obj, name, value) => {
    try { Object.defineProperty(obj, name, { value, configurable: true }); } catch (e) {}
  };
  hidden(window, '__px$L', L);
  hidden(window, '__px$top', pxTop);
  hidden(window, '__px$parent', nested ? window.parent : window);
  hidden(window, '__px$origin', UP.origin);
  hidden(window, '__pxRuntime', (c) => {
    C = c;
    UP = new URL(C.upstream);
    CS = C.cookieSite + '~';
    SP = UP.origin + '~';
    hidden(window, '__px$origin', UP.origin);
    perDoc();
  });
  hidden(window, '__px$js', js);
  hidden(window, '__px$u', (u, base) => {
    if (typeof u !== 'string' && !(u instanceof URL)) return u;
    try { return prox(new URL(String(u), base || upBase()).href); } catch (e) { return u; }
  });

  // Code built from strings: new Function(...), setTimeout("...").
  const FnProxy = new Proxy(_F, {
    apply: (t, self, a) => Reflect.apply(t, self, fnArgs(a)),
    construct: (t, a, nt) => Reflect.construct(t, fnArgs(a), nt === FnProxy ? t : nt),
  });
  function fnArgs(a) {
    a = Array.from(a);
    if (a.length && typeof a[a.length - 1] === 'string') a[a.length - 1] = js(a[a.length - 1]);
    return a;
  }
  try {
    window.Function = FnProxy;
    _F.prototype.constructor = FnProxy;
  } catch (e) {}
  for (const n of ['setTimeout', 'setInterval']) {
    const orig = window[n];
    window[n] = function (f, ...rest) { return orig.call(window, js(f), ...rest); };
  }

  // What the document says about its own address.
  function unprox(s) {
    if (typeof s !== 'string') return s;
    if (s.startsWith(P)) return s.slice(P.length);
    if (s.startsWith(WSP)) return s.slice(WSP.length);
    if (s === ME || s.startsWith(ME + '/')) return UP.origin + s.slice(ME.length);
    return s;
  }
  // Attribute values: only undo what the proxy wrote.
  function unproxAttr(s) {
    if (typeof s !== 'string' || !s.includes(C.prefix)) return s;
    if (s.startsWith(C.prefix)) return s.slice(C.prefix.length);
    return s.startsWith(P) || s.startsWith(WSP) ? unprox(s) : s;
  }
  const own = (obj, name, get) => {
    try { Object.defineProperty(obj, name, { get, configurable: true }); } catch (e) {}
  };
  own(window, 'origin', () => UP.origin);
  for (const cls of ['HTMLAnchorElement', 'HTMLAreaElement']) {
    const proto = window[cls].prototype;
    const d = Object.getOwnPropertyDescriptor(proto, 'href');
    if (!d) continue;
    Object.defineProperty(proto, 'href', { ...d, get() { return unprox(d.get.call(this)); } });
    for (const k of ['origin', 'protocol', 'host', 'hostname', 'port']) {
      const dk = Object.getOwnPropertyDescriptor(proto, k);
      if (!dk) continue;
      Object.defineProperty(proto, k, {
        ...dk,
        get() { try { return new URL(this.href)[k]; } catch (e) { return dk.get.call(this); } },
      });
    }
  }

  // postMessage between proxied frames: every frame really has the proxy's
  // origin, so target origins are mapped to it and event.origin back to the site.
  const _pm = window.postMessage;
  window.postMessage = function (msg, target, transfer) {
    if (target && typeof target === 'object') target = { ...target, targetOrigin: mapOrigin(target.targetOrigin) };
    else target = mapOrigin(target);
    return _pm.call(this || window, msg, target, transfer);
  };
  function mapOrigin(o) { return o == null || o === '*' || o === '/' ? o : ME; }
  const originDesc = Object.getOwnPropertyDescriptor(MessageEvent.prototype, 'origin');
  if (originDesc && originDesc.get) {
    Object.defineProperty(MessageEvent.prototype, 'origin', {
      ...originDesc,
      get() {
        const o = originDesc.get.call(this);
        if (o !== ME) return o;
        try { if (this.source && this.source.__px$origin) return this.source.__px$origin; } catch (e) {}
        return UP.origin;
      },
    });
  }


  // DOM URL attributes. Links (<a>, <area>) are left alone so routers can read
  // real paths; the click handler below routes them through the proxy.
  const isLink = (el) => el instanceof HTMLAnchorElement || el instanceof HTMLAreaElement;
  const URL_ATTRS = new Set(['src', 'href', 'action', 'formaction', 'poster', 'data']);
  const _setAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    const n = String(name).toLowerCase();
    if (URL_ATTRS.has(n) && !isLink(this)) value = prox(value);
    else if (n === 'srcset' || n === 'imagesrcset') value = proxSrcset(value);
    else if (n === 'integrity') return;
    else if (n === 'srcdoc' && this instanceof HTMLIFrameElement) value = withRuntime(value);
    else if (n === 'style') value = proxCss(value);
    else if (n.startsWith('on')) value = js(String(value));
    return _setAttr.call(this, name, value);
  };
  const _setAttrNS = Element.prototype.setAttributeNS;
  Element.prototype.setAttributeNS = function (ns, name, value) {
    const n = String(name).toLowerCase().replace(/^.*:/, '');
    if (URL_ATTRS.has(n) && !isLink(this)) value = prox(value);
    return _setAttrNS.call(this, ns, name, value);
  };

  const PROPS = [
    ['HTMLScriptElement', 'src'], ['HTMLImageElement', 'src'], ['HTMLImageElement', 'srcset', proxSrcset],
    ['HTMLSourceElement', 'src'], ['HTMLSourceElement', 'srcset', proxSrcset], ['HTMLMediaElement', 'src'],
    ['HTMLIFrameElement', 'src'], ['HTMLEmbedElement', 'src'], ['HTMLTrackElement', 'src'],
    ['HTMLLinkElement', 'href'], ['HTMLFormElement', 'action'], ['HTMLVideoElement', 'poster'],
    ['HTMLObjectElement', 'data'], ['HTMLLinkElement', 'imageSrcset', proxSrcset],
  ];
  for (const [cls, prop, fn = prox] of PROPS) {
    const proto = window[cls] && window[cls].prototype;
    const desc = proto && Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || !desc.set) continue;
    const un = fn === prox ? unprox : unproxSrcset;
    Object.defineProperty(proto, prop, {
      ...desc,
      get() { return un(desc.get.call(this)); },
      set(v) { desc.set.call(this, fn(v)); },
    });
  }
  // Read-only URLs the page can see.
  const GETTERS = [
    ['HTMLImageElement', 'currentSrc'], ['HTMLMediaElement', 'currentSrc'], ['Node', 'baseURI'],
    ['Response', 'url'], ['Request', 'url'], ['XMLHttpRequest', 'responseURL'], ['WebSocket', 'url'],
    ['EventSource', 'url'], ['PerformanceEntry', 'name'], ['StyleSheet', 'href'],
  ];
  for (const [cls, prop] of GETTERS) {
    const proto = window[cls] && window[cls].prototype;
    const desc = proto && Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || !desc.get) continue;
    Object.defineProperty(proto, prop, { ...desc, get() { return unprox(desc.get.call(this)); } });
  }
  Element.prototype.getAttribute = function (name) {
    const v = _getAttr.call(this, name);
    if (v == null || !v.includes(C.prefix)) return v;
    const n = String(name).toLowerCase();
    if (URL_ATTRS.has(n)) return unproxAttr(v);
    if (n === 'srcset' || n === 'imagesrcset') return mapSrcset(v, unproxAttr);
    return v;
  };

  // Frames the page creates start as about:blank (or srcdoc) documents on our
  // origin with none of the patches above, and sites borrow clean fetch, XHR
  // or location from them. They get this runtime too, set to this page's site.
  const runtimeCode = () => '(function(__name){(' + fnSource.call(runtime) + ')('
    + JSON.stringify({ ...C, upstream: location.protocol === 'about:' ? C.upstream : upHere(), swReload: false }).replace(/</g, '\\u003c') + ','
    + fnSource.call(rewriteJs) + ',' + fnSource.call(mapSrcset) + ',' + fnSource.call(rewriteCss) + ','
    + fnSource.call(workerRuntime) + ');})(function(f){return f;});';
  const RT_TAG = /^(\s*<!doctype[^>]*>)?\s*<script data-px-rt>[\s\S]*?<\/script>/i;
  const withRuntime = (html) => String(html).replace(RT_TAG, '$1').replace(/^(\s*<!doctype[^>]*>)?/i,
    (m) => m + '<script data-px-rt>' + runtimeCode().replace(/<\/(script)/gi, '<\\/$1') + '<\/script>');
  function adopt(frame, w) {
    try {
      if (!w || w.__pxRuntime || frame.hasAttribute('srcdoc')) return;
      // A pending src navigation brings its own runtime (and may reuse this window).
      const src = (_getAttr.call(frame, 'src') || '').trim();
      if (src && !/^about:blank$/i.test(src)) return;
      if (w.location.protocol !== 'about:') return;
      w.eval(runtimeCode());
    } catch (e) {}
  }
  for (const prop of ['contentWindow', 'contentDocument']) {
    const desc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, prop);
    if (!desc || !desc.get) continue;
    const cw = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow').get;
    Object.defineProperty(HTMLIFrameElement.prototype, prop, {
      ...desc,
      get() { adopt(this, cw.call(this)); return desc.get.call(this); },
    });
  }
  const srcdocDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
  if (srcdocDesc && srcdocDesc.set) {
    Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
      ...srcdocDesc,
      get() { return srcdocDesc.get.call(this).replace(RT_TAG, '$1'); },
      set(v) { srcdocDesc.set.call(this, withRuntime(v)); },
    });
  }

  // CSS added at runtime: <style> text, style attributes and the CSSOM. Rules
  // in an external sheet resolve against that sheet's (upstream) URL.
  function proxCss(css, base) {
    const s = String(css);
    if (!/url\(|@import|image-set\(/i.test(s)) return s;
    return rewriteCss(s, null, (u) => {
      if (!base || /^\s*#/.test(u)) return prox(u);
      try { return prox(new URL(u.trim(), base).href); } catch (e) { return u; }
    });
  }
  const sheetBase = (sheet) => (sheet && sheet.href ? unprox(sheet.href) : null);
  function fixStyle(el) {
    const v = el.textContent;
    const nv = proxCss(v);
    if (nv !== v) el.textContent = nv;
  }
  if (window.CSSStyleSheet) {
    const CSP = CSSStyleSheet.prototype;
    for (const m of ['insertRule', 'replace', 'replaceSync']) {
      const orig = CSP[m];
      if (orig) CSP[m] = function (css, ...rest) { return orig.call(this, proxCss(css, sheetBase(this)), ...rest); };
    }
  }
  if (window.CSSStyleDeclaration) {
    const SDP = CSSStyleDeclaration.prototype;
    const setProp = SDP.setProperty;
    SDP.setProperty = function (name, value, ...rest) {
      return setProp.call(this, name, value == null ? value : proxCss(value, sheetBase(this.parentRule && this.parentRule.parentStyleSheet)), ...rest);
    };
    const cssTextDesc = Object.getOwnPropertyDescriptor(SDP, 'cssText');
    if (cssTextDesc && cssTextDesc.set) {
      Object.defineProperty(SDP, 'cssText', { ...cssTextDesc, set(v) { cssTextDesc.set.call(this, proxCss(v)); } });
    }
  }

  // Elements inserted via innerHTML bypass the setters above.
  const ATTRS = { src: prox, srcset: proxSrcset, imagesrcset: proxSrcset, poster: prox, action: prox, data: prox };
  function fixTree(root) {
    if (root.nodeType === 3 && root.parentNode instanceof HTMLStyleElement) return fixStyle(root.parentNode);
    if (root.nodeType !== 1) return;
    if (root instanceof HTMLStyleElement) fixStyle(root);
    else for (const st of root.getElementsByTagName('style')) fixStyle(st);
    if (root.hasAttribute('style')) fixStyleAttr(root);
    for (const el of root.querySelectorAll('[style]')) fixStyleAttr(el);
    const els = [root, ...root.querySelectorAll('[src],[srcset],[imagesrcset],[poster],[action],link[href],object[data],iframe')];
    for (const el of els) {
      if (el instanceof HTMLIFrameElement) adopt(el, el.contentWindow);
      for (const a in ATTRS) {
        const v = _getAttr.call(el, a);
        if (v != null) {
          const nv = ATTRS[a](v);
          if (nv !== v) _setAttr.call(el, a, nv);
        }
      }
      if (el instanceof HTMLLinkElement) {
        const v = _getAttr.call(el, 'href');
        const nv = v != null && prox(v);
        if (nv && nv !== v) _setAttr.call(el, 'href', nv);
      }
      if (el.hasAttribute && el.hasAttribute('integrity')) el.removeAttribute('integrity');
    }
  }
  function fixStyleAttr(el) {
    const v = _getAttr.call(el, 'style');
    const nv = v && proxCss(v);
    if (nv && nv !== v) _setAttr.call(el, 'style', nv);
  }
  const observer = new MutationObserver((records) => {
    for (const r of records) {
      // el.style.backgroundImage = ... only shows up as a style attribute change.
      if (r.type === 'attributes') fixStyleAttr(r.target);
      else for (const n of r.addedNodes) fixTree(n);
    }
  });

  // Route link clicks through the proxy if no router handled them.
  addEventListener('click', (e) => {
    if (e.defaultPrevented) return;
    const a = e.target && e.target.closest && e.target.closest('a[href], area[href]');
    if (!a || a.hasAttribute('download')) return;
    const raw = _getAttr.call(a, 'href');
    if (!raw || raw[0] === '#') return;
    let x;
    try { x = new URL(a.href); } catch (err) { return; } // the site's URL (see the href getter above)
    if (!/^https?:$/.test(x.protocol)) return;
    const here = new URL(upHere());
    if (x.hash && x.origin === here.origin && x.pathname === here.pathname && x.search === here.search) return;
    // An empty link target means the same frame (unlike window.open's empty name).
    if (hostOpens && /^_blank$/i.test(a.getAttribute('target') || baseTarget() || '') && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
      e.preventDefault();
      hostOpen(x.href, true);
      return;
    }
    if (isProxied(raw)) return;
    const t = frameTarget(a.getAttribute('target') || baseTarget());
    if (t != null) _setAttr.call(a, 'target', t);
    _setAttr.call(a, 'href', prox(x.href));
  });

  // History: keep absolute upstream URLs on our origin and report navigation.
  for (const m of ['pushState', 'replaceState']) {
    const orig = history[m];
    history[m] = function (state, title, url) {
      if (url != null) {
        const s = String(url);
        if (s.startsWith(UP.origin + '/') || s === UP.origin) {
          url = nested || !C.bare ? prox(s) : s.slice(UP.origin.length) || '/';
        }
      }
      const r = orig.call(this, state, title, url);
      report();
      return r;
    };
  }

  // Tab mute. The UI sends { __px: 'mute', muted } to the outermost proxied
  // frame, which keeps the flag for all its frames. Media elements are muted on
  // top of whatever the page itself asked for (the page still reads its own
  // value), and Web Audio contexts are suspended. Each frame reports sound
  // changes to the outermost one, which tells the UI { __px: 'audio', audible }.
  const tabMuted = () => { try { return !!pxTop.__px$muted; } catch (e) { return false; } };
  const mutedDesc = Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'muted');
  const mediaWish = new WeakMap();
  const mediaSeen = new Set();
  const pageMuted = (el) => (mediaWish.has(el) ? mediaWish.get(el) : mutedDesc.get.call(el));
  function applyMediaMute(el) {
    const want = pageMuted(el) || tabMuted();
    if (mutedDesc.get.call(el) !== want) {
      if (!mediaWish.has(el)) mediaWish.set(el, mutedDesc.get.call(el));
      mutedDesc.set.call(el, want);
    }
  }
  Object.defineProperty(HTMLMediaElement.prototype, 'muted', {
    configurable: true, enumerable: true,
    get() { return pageMuted(this); },
    set(v) { mediaWish.set(this, !!v); mutedDesc.set.call(this, !!v || tabMuted()); },
  });
  function trackMedia(el) {
    mediaSeen.add(el);
    applyMediaMute(el);
  }
  const shadowRoots = new Set();
  function allMedia() {
    for (const el of mediaSeen) if (!el.isConnected && el.paused) mediaSeen.delete(el);
    const list = new Set(mediaSeen);
    try { document.querySelectorAll('audio, video').forEach((el) => list.add(el)); } catch (e) {}
    for (const r of shadowRoots) {
      if (!r.host.isConnected) continue;
      try { r.querySelectorAll('audio, video').forEach((el) => list.add(el)); } catch (e) {}
    }
    return list;
  }
  const _play = HTMLMediaElement.prototype.play;
  HTMLMediaElement.prototype.play = function () {
    trackMedia(this);
    return _play.apply(this, arguments);
  };
  const audioContexts = new Set();
  const ctxHeld = new WeakSet(); // suspended by us, or asked to resume while muted
  const acWrapped = new Map();
  for (const name of ['AudioContext', 'webkitAudioContext']) {
    const AC = window[name];
    if (typeof AC !== 'function' || AC.__px$wrapped) continue;
    if (acWrapped.has(AC)) { window[name] = acWrapped.get(AC); continue; }
    const _resume = AC.prototype.resume;
    AC.prototype.resume = function () {
      if (tabMuted() && audioContexts.has(this)) { ctxHeld.add(this); return Promise.resolve(); }
      return _resume.apply(this, arguments);
    };
    const Wrapped = class extends AC {
      constructor(...a) {
        super(...a);
        audioContexts.add(this);
        // Some contexts start or restart on their own (e.g. after a user gesture).
        this.addEventListener('statechange', () => {
          if (tabMuted() && this.state === 'running') { ctxHeld.add(this); this.suspend().catch(() => {}); }
          soundChanged();
        });
        if (tabMuted()) { ctxHeld.add(this); this.suspend().catch(() => {}); }
      }
    };
    Object.defineProperty(Wrapped, 'name', { value: name });
    Object.defineProperty(Wrapped, '__px$wrapped', { value: true });
    acWrapped.set(AC, Wrapped);
    window[name] = Wrapped;
  }
  // Speech synthesis is per window: cancelled on mute and blocked while muted.
  const speech = window.speechSynthesis;
  if (speech && typeof speech.speak === 'function') {
    const _speak = speech.speak;
    speech.speak = function (u) {
      if (tabMuted()) {
        try { u && u.dispatchEvent && u.dispatchEvent(new Event('end')); } catch (e) {}
        return;
      }
      const r = _speak.apply(this, arguments);
      soundChanged();
      try { u.addEventListener('end', soundChanged); u.addEventListener('error', soundChanged); } catch (e) {}
      return r;
    };
  }
  function applyMute() {
    const m = tabMuted();
    if (m && speech) { try { speech.cancel(); } catch (e) {} }
    allMedia().forEach(applyMediaMute);
    for (const c of audioContexts) {
      if (c.state === 'closed') { audioContexts.delete(c); continue; }
      if (m && c.state === 'running') { ctxHeld.add(c); c.suspend().catch(() => {}); }
      else if (!m && ctxHeld.has(c)) { ctxHeld.delete(c); c.resume().catch(() => {}); }
    }
  }
  // Sound the page is making or wants to make, ignoring the tab's mute.
  function audibleHere() {
    for (const el of allMedia()) {
      try { if (!el.paused && !el.ended && !pageMuted(el) && el.volume > 0) return true; } catch (e) {}
    }
    for (const c of audioContexts) if (c.state === 'running' || ctxHeld.has(c)) return true;
    try { if (speech && speech.speaking) return true; } catch (e) {}
    return false;
  }
  function audibleIn(w) {
    try {
      if (w.__px$audible && w.__px$audible()) return true;
      for (let i = 0; i < w.frames.length; i++) if (audibleIn(w.frames[i])) return true;
    } catch (e) {}
    return false;
  }
  function muteIn(w) {
    try {
      if (w.__px$applyMute) w.__px$applyMute();
      for (let i = 0; i < w.frames.length; i++) muteIn(w.frames[i]);
    } catch (e) {}
  }
  let lastAudible = false;
  let audioTimer = 0;
  function audioCheck() {
    audioTimer = 0;
    const a = audibleIn(window);
    if (a === lastAudible) return;
    lastAudible = a;
    try { window.parent.postMessage({ __px: 'audio', audible: a }, '*'); } catch (e) {}
  }
  function soundChanged() {
    try { pxTop.__px$soundChanged && pxTop.__px$soundChanged(); } catch (e) {}
  }
  // Media is caught as soon as it starts loading, before it can make a sound.
  function listenMedia(target) {
    for (const t of ['loadstart', 'loadedmetadata', 'play', 'playing', 'pause', 'ended', 'volumechange', 'emptied']) {
      target.addEventListener(t, (e) => {
        if (!(e.target instanceof HTMLMediaElement)) return;
        if (t !== 'pause' && t !== 'ended' && t !== 'emptied') trackMedia(e.target);
        soundChanged();
      }, true);
    }
  }
  listenMedia(window);
  const _attachShadow = Element.prototype.attachShadow;
  if (_attachShadow) {
    Element.prototype.attachShadow = function () {
      const r = _attachShadow.apply(this, arguments);
      shadowRoots.add(r);
      listenMedia(r);
      return r;
    };
  }
  hidden(window, '__px$audible', audibleHere);
  hidden(window, '__px$applyMute', applyMute);
  if (!nested) {
    hidden(window, '__px$muted', false);
    hidden(window, '__px$soundChanged', () => { if (!audioTimer) audioTimer = setTimeout(audioCheck, 60); });
    hidden(window, '__px$setMuted', (m) => {
      hidden(window, '__px$muted', !!m);
      muteIn(window);
    });
  }

  function report() {
    if (nested || window.parent === window) return;
    let icon = '';
    try {
      const l = document.querySelector("link[rel~='icon'][href], link[rel='apple-touch-icon'][href]");
      if (l) icon = unprox(l.href);
    } catch (e) {}
    lastAudible = audibleIn(window);
    try { window.parent.postMessage({ __px: 'nav', url: upHere(), title: document.title, icon, audible: lastAudible }, '*'); } catch (e) {}
  }
  addEventListener('popstate', report);
  addEventListener('hashchange', report);
  addEventListener('DOMContentLoaded', report);
  addEventListener('load', report);

  // Per document: a reused window gets a new one.
  function perDoc() {
    const ref = document.referrer;
    hidden(document, '__px$L', L);
    own(document, 'URL', upHere);
    own(document, 'documentURI', upHere);
    own(document, 'referrer', () => (ref.startsWith(ME + '/') ? unprox(ref) : ''));
    try {
      Object.defineProperty(document, 'domain', { get: () => UP.hostname, set: () => {}, configurable: true });
    } catch (e) {}
    observer.observe(document, { childList: true, subtree: true, attributes: true, attributeFilter: ['style'] });
    // Outermost proxied frame: show the real path and remember the site.
    if (!nested) {
      if (location.href.startsWith(P)) {
        const real = new URL(upHere());
        if (real.origin === UP.origin && C.bare) _replaceState.call(history, history.state, '', real.pathname + real.search + real.hash);
      }
      try {
        cookieDesc.set.call(document, '__px_origin=' + encodeURIComponent(UP.origin) + cookieAttrs);
      } catch (e) {}
      // Ask for the tab's mute state before the page can start any sound.
      if (window.parent !== window) {
        try { window.parent.postMessage({ __px: 'hello' }, '*'); } catch (e) {}
      }
    }
  }
  perDoc();
}

// __name: guard against bundlers that wrap functions with a name helper.
const RUNTIME_HEAD = `<script data-px-rt>(function(__name){(${runtime})(`;

const RUNTIME_TAIL = `,${rewriteJs},${mapSrcset},${rewriteCss},${workerRuntime});})(function(f){return f;});</script>`;

// Inline scripts repeat across a site's pages too; same idea, kept as strings.
const INLINE_CACHE_BYTES = 32 * 1024 * 1024;

const rewriteCache = new Map(); // key -> string

let rewriteCacheSize = 0;

function cached(kind, base, input, fn) {
  if (input.length < 2048) return fn(input);
  // Only imports depend on the page's address; other scripts are shared by every page.
  if (kind === 'js' && !/\b(?:import|from)\b/.test(input)) base = '';
  const key = kind + '\0' + base + '\0' + input.length + '\0' + strHash(input);
  const hit = rewriteCache.get(key);
  if (hit != null) {
    rewriteCache.delete(key);
    rewriteCache.set(key, hit);
    return hit;
  }
  const result = fn(input);
  if (result.length * 2 > INLINE_CACHE_BYTES / 4) return result;
  rewriteCache.set(key, result);
  rewriteCacheSize += result.length * 2;
  for (const [k, v] of rewriteCache) {
    if (rewriteCacheSize <= INLINE_CACHE_BYTES) break;
    rewriteCache.delete(k);
    rewriteCacheSize -= v.length * 2;
  }
  return result;
}

const cachedRewriteJs = (code, base) => cached('js', base, code, (s) => rewriteJs(s, base, vmCheck));

// job: { kind: 'css' | 'js', base, type (Content-Type), worker (prepend the worker runtime) }
function rewriteAssetSync({ kind, base, type, worker }, bytes) {
  let text;
  if (kind === 'css') {
    const css = decodeText(bytes, type, /^@charset\s+["']([\w-]+)/i);
    text = rewriteCss(css.replace(/^@charset\s+["'][\w-]+["']\s*;?/i, ''), new URL(base));
  } else {
    text = rewriteJs(decodeText(bytes, type), base, vmCheck);
    if (worker) text = withWorkerRuntime(text);
  }
  return new TextEncoder().encode(text);
}

// A script that parses is one the rewriter may have broken; proxy.js used
// node:vm for the same check.
const vmCheck = (code) => { try { new Function(code); return true; } catch (err) { return false; } };

// cached() keys rewrites by content. No node:crypto here, so a cheap string
// hash stands in; a collision would only serve one script's rewrite for another
// of the same length, and the key keeps the length and the base URL as well.
function strHash(s) {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 2654435761);
    h2 = Math.imul(h2 ^ c, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
}

// ---------------------------------------------------------------- page prelude

// Runs just before the injected runtime, in every proxied document. It holds
// the two things a service worker cannot do for the page itself: cookies (a
// synthesized response can't set them) and WebSockets (a service worker can't
// intercept them), both bridged back here.
function pagePrelude(C) {
  const sw = navigator.serviceWorker;
  const CS = C.cookieSite + '~';
  const attrs = '; path=/' + (C.secure ? '; SameSite=None; Secure; Partitioned' : '');

  const post = (msg, transfer) => {
    try {
      const c = sw && sw.controller;
      if (c) c.postMessage(msg, transfer || []);
    } catch (e) {}
  };

  // -------------------------------------------------- cookies
  const desc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
  if (desc && desc.get && desc.set) {
    const write = (c) => { try { desc.set.call(document, c); } catch (e) {} };
    for (const c of C.cookies || []) write(CS + c + attrs);
    Object.defineProperty(Document.prototype, 'cookie', {
      ...desc,
      set(v) {
        desc.set.call(this, v);
        post({ __px: 'cookie', cookie: String(v) });
      },
    });
    if (sw) {
      sw.addEventListener('message', (e) => {
        const d = e.data;
        if (d && d.__px === 'cookies' && d.site === C.cookieSite) for (const c of d.cookies || []) write(c);
      });
      // Messages from the worker stay queued until the flow is started by hand.
      try { sw.startMessages(); } catch (e) {}
    }
  }

  // -------------------------------------------------- WebSocket
  const Native = self.WebSocket;
  if (!Native || !sw) return;

  const priv = new WeakMap();
  const unprox = (u) => {
    let s = String(u instanceof URL ? u.href : u);
    const i = s.indexOf(C.prefix);
    if (i >= 0) s = s.slice(i + C.prefix.length);
    return s.replace(/^([a-z]+):\/(?!\/)/i, '$1://');
  };

  class PxWebSocket extends EventTarget {
    constructor(url, protocols) {
      super();
      if (arguments.length < 1) throw new TypeError('Failed to construct WebSocket: 1 argument required');
      let u;
      try { u = new URL(unprox(url), C.upstream); } catch (e) {
        throw new DOMException("Failed to construct WebSocket: The URL is invalid", 'SyntaxError');
      }
      if (u.protocol === 'http:') u.protocol = 'ws:';
      if (u.protocol === 'https:') u.protocol = 'wss:';
      if (u.protocol !== 'ws:' && u.protocol !== 'wss:') {
        throw new DOMException("Failed to construct WebSocket: The URL's scheme must be either 'ws' or 'wss'", 'SyntaxError');
      }
      u.hash = '';
      const list = protocols == null ? [] : typeof protocols === 'string' ? [protocols] : Array.from(protocols);
      const s = {
        url: u.href, state: 0, protocols: list, protocol: '', binaryType: 'blob',
        buffered: 0, queue: [], port: null, handlers: {},
      };
      priv.set(this, s);

      const ch = new MessageChannel();
      s.port = ch.port1;
      ch.port1.onmessage = (e) => this[RECV](e.data);
      post({ __px: 'ws-open', url: s.url, protocols: list, origin: new URL(C.upstream).origin }, [ch.port2]);
    }

    get url() { return priv.get(this).url; }
    get readyState() { return priv.get(this).state; }
    get bufferedAmount() { return priv.get(this).buffered; }
    get protocol() { return priv.get(this).protocol; }
    get extensions() { return ''; }
    get binaryType() { return priv.get(this).binaryType; }
    set binaryType(v) {
      if (v === 'blob' || v === 'arraybuffer') priv.get(this).binaryType = v;
    }

    send(data) {
      const s = priv.get(this);
      if (s.state === 0) throw new DOMException("Failed to execute 'send' on 'WebSocket': Still in CONNECTING state.", "InvalidStateError");
      if (s.state > 1) return;
      if (data instanceof Blob) {
        s.buffered += data.size;
        const p = data.arrayBuffer().then((b) => { s.buffered -= data.size; return b; });
        s.queue.push(p);
        p.then((b) => s.port.postMessage({ t: 'send', d: b }, [b])).catch(() => {});
        return;
      }
      let out = data;
      if (ArrayBuffer.isView(data)) out = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
      else if (data instanceof ArrayBuffer) out = data.slice(0);
      else out = String(data);
      try { s.port.postMessage({ t: 'send', d: out }, typeof out === 'string' ? [] : [out]); } catch (e) {}
    }

    close(code, reason) {
      const s = priv.get(this);
      if (code !== undefined && code !== 1000 && !(code >= 3000 && code <= 4999)) {
        throw new DOMException("Failed to execute 'close' on 'WebSocket': The code must be either 1000, or between 3000 and 4999.", "InvalidAccessError");
      }
      if (s.state > 1) return;
      const connecting = s.state === 0;
      s.state = 2;
      // What the close event should report: libcurl never sees the peer's close
      // frame, so a close the page asked for echoes its own code back.
      s.want = connecting ? null : { code: code === undefined ? 1000 : code, reason: reason === undefined ? '' : String(reason) };
      try { s.port.postMessage({ t: 'close', code, reason }); } catch (e) {}
    }

    [RECV](m) {
      const s = priv.get(this);
      if (m.t === 'open') {
        if (s.state !== 0) return;
        s.state = 1;
        s.protocol = m.protocol || '';
        this.dispatchEvent(new Event('open'));
      } else if (m.t === 'msg') {
        if (s.state !== 1) return;
        let data = m.d;
        if (data instanceof ArrayBuffer && s.binaryType === 'blob') data = new Blob([data]);
        this.dispatchEvent(new MessageEvent('message', { data, origin: new URL(s.url).origin }));
      } else if (m.t === 'close') {
        if (s.state === 3) return;
        s.state = 3;
        try { s.port.close(); } catch (e) {}
        if (m.error) this.dispatchEvent(new Event('error'));
        const want = !m.error && s.want;
        this.dispatchEvent(new CloseEvent('close', {
          code: want ? want.code : m.code || 1006,
          reason: want ? want.reason : m.reason || '',
          wasClean: want ? true : !!m.clean,
        }));
      }
    }
  }

  for (const name of ['open', 'message', 'close', 'error']) {
    Object.defineProperty(PxWebSocket.prototype, 'on' + name, {
      configurable: true, enumerable: true,
      get() { const s = priv.get(this); return (s && s.handlers[name]) || null; },
      set(fn) {
        const s = priv.get(this);
        if (!s) return;
        if (s.handlers[name]) this.removeEventListener(name, s.handlers[name]);
        s.handlers[name] = typeof fn === 'function' ? fn : null;
        if (s.handlers[name]) this.addEventListener(name, s.handlers[name]);
      },
    });
  }
  for (const [k, v] of [['CONNECTING', 0], ['OPEN', 1], ['CLOSING', 2], ['CLOSED', 3]]) {
    Object.defineProperty(PxWebSocket, k, { value: v, enumerable: true });
    Object.defineProperty(PxWebSocket.prototype, k, { value: v, enumerable: true });
  }
  // Keeps instanceof WebSocket, Symbol.toStringTag and anything the site
  // reaches for on the real prototype.
  try { Object.setPrototypeOf(PxWebSocket.prototype, Native.prototype); } catch (e) {}
  Object.defineProperty(PxWebSocket, 'name', { value: 'WebSocket', configurable: true });
  try { self.WebSocket = PxWebSocket; } catch (e) {}
}

// A private-ish name for the bridge's receive hook, so the site can't see it as
// an ordinary method.
const PRELUDE_HEAD = `<script data-px-pre>(function(){const RECV=Symbol('px');(${pagePrelude})(`;
const PRELUDE_TAIL = `);})();</script>`;

function preludeScript(upstream) {
  const site = cookieSite(upstream.hostname);
  const json = JSON.stringify({
    upstream: upstream.href, prefix: PREFIX, cookieSite: site, cookies: jarPairs(site),
    secure: isSecureOrigin(new URL(ME)),
  }).replace(/</g, '\\u003c');
  return PRELUDE_HEAD + json + PRELUDE_TAIL;
}

// The cookies a proxied document should be able to read, in the form the
// prelude writes them ("name=value", namespaced and given attributes there).
function jarPairs(site) {
  const header = jarHeader(site, true);
  return header ? header.split('; ') : [];
}

// htmlRewriter() injects this, so the prelude rides along with the runtime.
function runtimeScript(upstream, prefix, swReload) {
  const json = JSON.stringify({
    upstream: upstream.href, prefix, swReload, cookieSite: cookieSite(upstream.hostname),
    uiOrigins: UI_ORIGINS, bare: BASE === '/', swPath: SW_PATH, swScope: BASE,
  }).replace(/</g, '\\u003c');
  return preludeScript(upstream) + RUNTIME_HEAD + json + RUNTIME_TAIL;
}

// ---------------------------------------------------------------- bodies

const MEU = new URL(ME);
const ENC_FMT = { gzip: 'gzip', 'x-gzip': 'gzip', deflate: 'deflate' };

function restream(head, reader, done) {
  return new ReadableStream({
    start(c) {
      if (head && head.length) c.enqueue(head);
      if (done) c.close();
    },
    async pull(c) {
      try {
        const r = await reader.read();
        if (r.done) c.close();
        else c.enqueue(r.value);
      } catch (err) { c.error(err); }
    },
    cancel(reason) { try { reader.cancel(reason); } catch (err) {} },
  });
}

// Whether curl decoded the body already depends on how it was built, so the
// first bytes decide: a gzip or zlib header means it is still compressed.
async function decodedBody(body, enc) {
  const fmt = ENC_FMT[enc];
  if (!body || !fmt || typeof DecompressionStream !== 'function') return body;
  const reader = body.getReader();
  let first;
  try { first = await reader.read(); } catch (err) { return restream(null, reader, false); }
  const head = first.done ? null : first.value;
  const packed = !!head && head.length > 1 && (fmt === 'gzip'
    ? head[0] === 0x1f && head[1] === 0x8b
    : (head[0] & 0x0f) === 8 && ((head[0] << 8) + head[1]) % 31 === 0);
  const src = restream(head, reader, first.done);
  if (!packed) return src;
  try { return src.pipeThrough(new DecompressionStream(fmt)); } catch (err) { return src; }
}

async function readAll(body) {
  if (!body) return new Uint8Array(0);
  const chunks = [];
  let total = 0;
  const reader = body.getReader();
  for (;;) {
    const r = await reader.read();
    if (r.done) break;
    chunks.push(r.value);
    total += r.value.length;
  }
  return concat(chunks, total);
}

function concat(chunks, total) {
  if (chunks.length === 1) return chunks[0];
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) { out.set(c, at); at += c.length; }
  return out;
}

// The first chunk of a stream, with the rest still readable after it. Headers
// go out with it, so a rewriting failure can still become an error page.
async function peek(body) {
  const reader = body.getReader();
  let first;
  try { first = await reader.read(); } catch (err) {
    try { reader.releaseLock(); } catch (e) {}
    throw err;
  }
  return [first.done ? null : first.value, restream(first.done ? null : first.value, reader, first.done)];
}

// ---------------------------------------------------------------- HTML streaming

// A port of proxy.js's htmlStream(): same charset rules, as a TransformStream.
function htmlStream(contentType, upstream) {
  const rewrite = htmlRewriter(upstream);
  const encoder = new TextEncoder();
  const headNeeded = /charset=["']?[\w-]+/i.test(contentType || '') ? 3 : 4096;
  let head = [];
  let headLength = 0;
  let decoder = null;
  let whole = null; // chunks, when the page must be read whole
  const start = (bytes) => {
    try {
      const charset = sniffCharset(bytes, contentType, HTML_CHARSET);
      if (charset) decoder = new TextDecoder(charset);
    } catch (err) {}
    head = null;
    if (!decoder) { whole = [bytes]; return ''; }
    return rewrite(decoder.decode(bytes, { stream: true }), false);
  };
  const push = (c, s) => { if (s) c.enqueue(encoder.encode(s)); };
  return new TransformStream({
    transform(chunk, c) {
      if (whole) { whole.push(chunk); return; }
      if (decoder) { push(c, rewrite(decoder.decode(chunk, { stream: true }), false)); return; }
      head.push(chunk);
      headLength += chunk.length;
      if (headLength >= headNeeded) push(c, start(concat(head, headLength)));
    },
    flush(c) {
      let s = '';
      if (head) s = start(concat(head, headLength));
      s += whole
        ? rewrite(decodeText(concat(whole, whole.reduce((n, x) => n + x.length, 0)), contentType, HTML_CHARSET), true)
        : rewrite(decoder.decode(), true);
      push(c, s);
    },
  });
}

// ---------------------------------------------------------------- rewrite cache

const JS_CACHE_MIN = 8 * 1024;
const JS_CACHE_MAX = 300;
let jsCacheName = null;

const hex = (buf) => Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
const sha256 = async (data) => hex(await crypto.subtle.digest('SHA-256',
  typeof data === 'string' ? new TextEncoder().encode(data) : data));

// Named after the rewriter, so changing it retires the old entries.
async function jsCache() {
  if (!jsCacheName) {
    jsCacheName = '__px-js-' + (await sha256(String(rewriteJs) + String(workerRuntime))).slice(0, 16);
  }
  return caches.open(jsCacheName);
}

async function dropOldCaches() {
  await jsCache();
  for (const name of await caches.keys()) {
    if (name.startsWith('__px-js-') && name !== jsCacheName) await caches.delete(name);
  }
}

async function prune(cache) {
  const keys = await cache.keys();
  for (let i = 0; i < keys.length - JS_CACHE_MAX; i++) await cache.delete(keys[i]);
}

// Rewriting a big script costs more than reading it back, and a service worker
// starts cold every few seconds, so finished scripts are kept in a Cache.
async function rewriteAssetCached(job, bytes, keep) {
  if (job.kind !== 'js' || bytes.length < JS_CACHE_MIN) return rewriteAssetSync(job, bytes);
  let cache = null;
  let key = null;
  try {
    cache = await jsCache();
    key = ME + '/__px_js/' + await sha256(`${job.base}\n${job.type}\n${job.worker ? 'w' : ''}\n${bytes.length}\n`)
      + '-' + await sha256(bytes);
    const hit = await cache.match(key);
    if (hit) return new Uint8Array(await hit.arrayBuffer());
  } catch (err) {}
  const out = rewriteAssetSync(job, bytes);
  if (cache && key) {
    keep(cache.put(key, new Response(out)).then(() => prune(cache)).catch(() => {}));
  }
  return out;
}

// ---------------------------------------------------------------- upstream

async function refererUpstream(event, request) {
  const ref = request.referrer;
  if (!ref || ref === 'about:client') return null;
  const direct = upstreamFromProxied(ref, MEU);
  if (direct) return direct;
  // history.replaceState() leaves proxied pages on a bare path, so the
  // referrer has to be read against whichever site the client is showing.
  let u;
  try { u = new URL(ref); } catch (err) { return null; }
  if (u.origin !== ME || HOME_PATH.test(u.pathname)) return null;
  const origin = await siteOf(event, request);
  if (!origin) return null;
  try { return new URL(u.pathname + u.search + u.hash, origin); } catch (err) { return null; }
}

const ACCEPT = {
  document: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  iframe: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  style: 'text/css,*/*;q=0.1',
  image: 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
};

// proxy.js read Cookie, Referer, Origin and Sec-Fetch-* off the request. A
// service worker never sees them -- the browser adds them afterwards -- so they
// are rebuilt from the request's destination, mode and referrer.
function upstreamHeaders(request, target, refUp, method) {
  const h = {};
  for (const [k, v] of request.headers) {
    if (!DROP_REQUEST_HEADERS.has(k) && !k.startsWith('cf-')) h[k] = v;
  }
  const dest = request.destination || 'empty';
  const mode = request.mode || 'no-cors';

  const cookie = jarHeader(cookieSite(target.hostname));
  if (cookie) h.cookie = cookie;
  if (refUp) h.referer = refUp.href;
  if (mode === 'cors' || (method !== 'GET' && method !== 'HEAD')) {
    h.origin = refUp ? refUp.origin : target.origin;
  }
  h['sec-fetch-dest'] = /^i?frame$/.test(dest) ? 'document' : dest;
  h['sec-fetch-mode'] = mode;
  h['sec-fetch-site'] = refUp
    ? refUp.origin === target.origin ? 'same-origin'
      : refUp.protocol === target.protocol && cookieSite(refUp.hostname) === cookieSite(target.hostname) ? 'same-site'
        : 'cross-site'
    : mode === 'navigate' ? 'none' : 'same-origin';
  if (!h['user-agent']) h['user-agent'] = navigator.userAgent;
  if (!h['accept-language']) {
    h['accept-language'] = (navigator.languages && navigator.languages.join(',')) || navigator.language || 'en-US';
  }
  if (!h.accept) h.accept = ACCEPT[dest] || '*/*';
  h['accept-encoding'] = 'gzip, deflate';
  delete h['x-px-dest'];
  return h;
}

function setCookies(resp) {
  const raw = resp.raw_headers || [];
  const out = [];
  for (const [k, v] of raw) if (String(k).toLowerCase() === 'set-cookie') out.push(v);
  return out;
}

// ---------------------------------------------------------------- the pipeline

async function proxyUpstream(event, request, self_, target, refUp) {
  if (request.destination === 'serviceworker') {
    return new Response('Service workers are disabled by the proxy', { status: 404 });
  }
  const keep = (p) => { try { event.waitUntil(p); } catch (err) {} };

  let body = null;
  let method = request.method;
  if (method !== 'GET' && method !== 'HEAD') {
    try {
      const b = await request.arrayBuffer();
      if (b.byteLength) body = b;
    } catch (err) {}
  }

  // A 3xx can only be handed back for a navigation; anything else asked for
  // redirects to be followed, which has to happen here.
  const follows = request.redirect === 'follow' && request.mode !== 'navigate';
  let resp;
  let site = '';
  for (let hop = 0; ; hop++) {
    const headers = upstreamHeaders(request, target, refUp, method);
    try {
      resp = await curlFetch(target.href, {
        method, headers, body, redirect: 'manual', credentials: 'omit',
      });
    } catch (err) {
      const timedOut = /abort/i.test(errText(err));
      return errorPage(timedOut ? 504 : 502, timedOut ? 'Site timed out' : 'Could not reach site',
        `${target.href}\n${timedOut ? `No response within ${UPSTREAM_TIMEOUT_MS / 1000}s.` : errText(err)}`);
    }

    site = cookieSite(target.hostname);
    const cookies = setCookies(resp);
    if (cookies.length) {
      for (const c of cookies) jarStore(site, c);
      mirrorCookies(site, cookies);
    }

    const loc = resp.headers.get('location');
    if (!follows || !loc || resp.status < 300 || resp.status > 399 || hop >= 10) break;
    let next;
    try { next = new URL(loc, target.href); } catch (err) { break; }
    if (blockedReason(next, MEU)) break;
    if (resp.status === 303 || ((resp.status === 301 || resp.status === 302) && method === 'POST')) {
      method = 'GET';
      body = null;
    }
    try { if (resp.body) await resp.body.cancel(); } catch (err) {}
    refUp = target;
    self_ = new URL(PREFIX + next.href, ME);
    target = next;
  }

  const out = new Headers();
  for (const [k, v] of resp.raw_headers || []) {
    if (!/^(set-cookie|transfer-encoding|connection|keep-alive|content-encoding)$/i.test(k)) out.append(k, v);
  }
  for (const h of DROP_RESPONSE_HEADERS) out.delete(h);

  let enc = (resp.headers.get('content-encoding') || '').trim().toLowerCase();
  if (enc === 'identity') enc = '';
  const length = enc ? 0 : Number(out.get('content-length') || 0);
  if (enc) out.delete('content-length');

  const location = out.get('location');
  if (location) out.set('location', proxUrl(location, target));
  const refresh = out.get('refresh');
  if (refresh) out.set('refresh', rewriteRefresh(refresh, target));

  const type = (out.get('content-type') || '').toLowerCase();
  const init = { status: resp.status, statusText: resp.statusText, headers: out };

  if (request.method === 'HEAD' || [204, 205, 304].includes(resp.status) || !resp.body) {
    try { if (resp.body) await resp.body.cancel(); } catch (err) {}
    if (enc || /html|css|javascript|ecmascript/.test(type)) out.delete('content-length');
    return new Response(null, init);
  }

  const dest = request.destination || '';
  const asScript = /^(?:script|worker|sharedworker)$/.test(dest) && !/^(?:image|video|audio|font)\/|css|wasm|json/.test(type);
  const setType = (mime) => out.set('content-type', `${mime || type.split(';')[0].trim() || 'text/plain'}; charset=utf-8`);
  const stream = await decodedBody(resp.body, enc);

  if (!asScript && /text\/html|application\/xhtml\+xml/.test(type)) {
    out.delete('content-length');
    out.set('referrer-policy', 'same-origin');
    out.set('cache-control', 'no-store');
    // XHTML is served as HTML: the injected runtime isn't well-formed XML.
    setType('text/html');
    if (request.mode === 'navigate') {
      stateData.lastSite = target.origin;
      keep(saveState());
    }
    let rest;
    try {
      const piped = stream.pipeThrough(htmlStream(type, target));
      [, rest] = await peek(piped);
    } catch (err) {
      return errorPage(502, 'Could not reach site', `${target.href}\n${errText(err)}`);
    }
    return new Response(rest, init);
  }

  const css = !asScript && type.includes('text/css');
  const js = !css && (asScript || /javascript|ecmascript/.test(type));
  if ((!css && !js) || length > MAX_BUFFERED_BYTES) return new Response(stream, init);

  if (js) out.set('x-px-js', '1');
  const job = { kind: css ? 'css' : 'js', base: target.href, type, worker: js && /worker$/.test(dest) };
  let asset;
  try {
    asset = await rewriteAssetCached(job, await readAll(stream), keep);
  } catch (err) {
    return errorPage(502, 'Could not reach site', `${target.href}\n${errText(err)}`);
  }
  setType(js && asScript && !/javascript|ecmascript/.test(type) ? 'text/javascript' : null);
  out.set('content-length', String(asset.length));
  return new Response(asset, init);
}

// ---------------------------------------------------------------- clients

const origins = new Map(); // client id -> the upstream origin it is showing

async function mirrorCookies(site, cookies) {
  const secure = isSecureOrigin(MEU);
  // An HttpOnly cookie is the jar's business only: the document may not see it,
  // and document.cookie would refuse the write anyway.
  const open = cookies.filter((c) => !/;\s*httponly\s*(?:;|$)/i.test(c));
  if (!open.length) return;
  const msg = { __px: 'cookies', site, cookies: open.map((c) => rewriteCookie(c, site, secure)) };
  for (const client of await self.clients.matchAll({ type: 'window' })) {
    const seen = origins.get(client.id);
    const up = upstreamFromProxied(client.url, MEU);
    if ((seen && cookieSite(new URL(seen).hostname) === site)
      || (up && cookieSite(up.hostname) === site)) client.postMessage(msg);
  }
}

// A request that escaped rewriting ("/assets/app.js"): work out which site it
// belongs to from the client that made it, its referrer, or the last site seen.
async function siteOf(event, request) {
  const fromClient = async () => {
    if (!event.clientId) return undefined;
    const seen = origins.get(event.clientId);
    if (seen) return seen;
    let client;
    try { client = await self.clients.get(event.clientId); } catch (err) {}
    if (!client) return undefined;
    const up = upstreamFromProxied(client.url, MEU);
    if (up) return up.origin;
    try { if (new URL(client.url).origin === ME) return null; } catch (err) {}
    return undefined;
  };
  const byClient = await fromClient();
  if (byClient !== undefined) return byClient;
  const ref = upstreamFromProxied(request.referrer, MEU);
  if (ref) return ref.origin;
  return stateData.lastSite;
}

// ---------------------------------------------------------------- WebSockets

// Service workers can't intercept WebSockets, so the prelude's shim hands each
// one here over a MessagePort and curl opens it through the Wisp relay.
async function openSocket(event, msg, port) {
  let target;
  try { target = new URL(msg.url); } catch (err) { return; }
  const http = new URL(target.href);
  http.protocol = target.protocol === 'wss:' ? 'https:' : 'http:';
  if (blockedReason(http, MEU)) {
    port.postMessage({ t: 'close', code: 1006, error: true, clean: false });
    return;
  }

  let done = null;
  const alive = new Promise((resolve) => { done = resolve; });
  try { event.waitUntil(alive); } catch (err) {}

  let ws = null;
  let closed = false;
  const finish = (code, reason, clean, error) => {
    if (closed) return;
    closed = true;
    clearTimeout(timer);
    try { port.postMessage({ t: 'close', code, reason: reason || '', clean: !!clean, error: !!error }); } catch (err) {}
    try { port.close(); } catch (err) {}
    done();
  };
  const timer = setTimeout(() => {
    // A failed handshake never reports itself, so time it out here.
    if (ws && !ws.connected) { try { ws.close(); } catch (err) {} finish(1006, '', false, true); }
  }, 20000);

  try {
    await curl();
    const site = cookieSite(http.hostname);
    const headers = { Origin: msg.origin || http.origin, 'User-Agent': navigator.userAgent };
    const cookie = jarHeader(site);
    if (cookie) headers.Cookie = cookie;
    ws = new libcurl.CurlWebSocket(target.href, msg.protocols || [], { headers });
  } catch (err) {
    finish(1006, '', false, true);
    return;
  }

  ws.onopen = () => {
    clearTimeout(timer);
    try { port.postMessage({ t: 'open', protocol: (msg.protocols || [])[0] || '' }); } catch (err) {}
  };
  ws.onmessage = (data) => {
    if (closed) return;
    if (typeof data === 'string') port.postMessage({ t: 'msg', d: data });
    else {
      const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
      port.postMessage({ t: 'msg', d: buf }, [buf]);
    }
  };
  ws.onclose = () => finish(1005, '', true, false);
  ws.onerror = () => finish(1006, '', false, true);

  port.onmessage = (e) => {
    const m = e.data;
    if (!m || closed) return;
    if (m.t === 'send') {
      try { ws.send(typeof m.d === 'string' ? m.d : new Uint8Array(m.d)); } catch (err) {}
    } else if (m.t === 'close') {
      try { ws.close(); } catch (err) {}
      finish(m.code || 1005, m.reason, true, false);
    }
  };
}

// ---------------------------------------------------------------- events

self.addEventListener('install', (event) => {
  event.waitUntil(state().then(() => self.skipWaiting()).catch(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    try { await self.clients.claim(); } catch (err) {}
    try { await dropOldCaches(); } catch (err) {}
  })());
});

self.addEventListener('message', (event) => {
  const msg = event.data;
  if (!msg || typeof msg !== 'object') return;
  const source = event.source;
  event.waitUntil((async () => {
    await state();
    if (msg.__px === 'origin' && msg.origin) {
      // The runtime announcing which site a document is showing.
      if (source && source.id) origins.set(source.id, msg.origin);
      if (stateData.lastSite !== msg.origin) {
        stateData.lastSite = msg.origin;
        await saveState();
      }
    } else if (msg.__px === 'cookie') {
      jarFromPage(msg.cookie);
    } else if (msg.__px === 'ws-open' && event.ports && event.ports[0]) {
      await openSocket(event, msg, event.ports[0]);
    } else if (msg.__px === 'config') {
      if (msg.wisp && msg.wisp !== stateData.wisp) {
        stateData.wisp = msg.wisp;
        await saveState();
        // The relay is chosen when the transport starts, so start over.
        curlReady = null;
        session = null;
      }
      if (source) source.postMessage({ __px: 'config', wisp: stateData.wisp, ok: !bootError });
    } else if (msg.__px === 'reset') {
      stateData.jar = {};
      await saveState();
    }
  })().catch(() => {}));
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (!/^https?:$/.test(new URL(request.url).protocol)) return;
  const url = new URL(request.url);

  if (url.origin === ME) {
    // The worker's own script, and the files the static host serves: the page
    // handles ?url= itself, by opening it in a tab.
    if (url.pathname === SW_PATH) return;
    if (HOME_PATH.test(url.pathname)) return;
  }
  event.respondWith(route(event, request, url));
});

async function route(event, request, url) {
  try {
    await state();
    let target;
    let self_ = url;

    if (url.origin === ME && url.pathname.startsWith(PREFIX)) {
      const raw = url.pathname.slice(PREFIX.length).replace(/^([a-z]+):\/(?!\/)/i, '$1://') + url.search + url.hash;
      try { target = new URL(raw); } catch (err) { return errorPage(400, 'Invalid URL', raw); }
    } else if (url.origin === ME) {
      const origin = await siteOf(event, request);
      if (!origin) return usagePage(url);
      target = new URL(url.pathname + url.search + url.hash, origin);
      self_ = new URL(PREFIX + target.href, ME);
    } else {
      // An absolute cross-origin URL that escaped rewriting. Proxied pages get
      // it proxied; anything else (our own page) goes straight to the network.
      const origin = await siteOf(event, request);
      if (!origin) return fetch(request);
      target = url;
      self_ = new URL(PREFIX + target.href, ME);
    }

    if (target.protocol === 'wss:') target.protocol = 'https:';
    if (target.protocol === 'ws:') target.protocol = 'http:';
    const blocked = blockedReason(target, MEU);
    if (blocked) return errorPage(403, 'Blocked', blocked);
    if (bootError) {
      return errorPage(502, 'Transport unavailable', `Could not load libcurl.js from\n${CONFIG.libcurl}\n\n${errText(bootError)}`);
    }
    return await proxyUpstream(event, request, self_, target, await refererUpstream(event, request));
  } catch (err) {
    return errorPage(500, 'Proxy error', errText(err));
  }
}
