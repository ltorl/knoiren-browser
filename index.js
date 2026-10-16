// Peekaboom (Node): serves any public site so it can be embedded in an <iframe>.
//
//   node index.js              (Node 20+, no dependencies)
//   open http://localhost:8080/ for the Knoiren Browser UI
//   <iframe src="https://<host>:8787/__px/https://example.com/"></iframe>
//
// Two servers: the proxy on PORT (8787) and the browser UI on UI_PORT (8080),
// both on HOST (0.0.0.0). They are separate origins so proxied sites can't
// reach the UI's storage. If the proxy is reachable at a different address
// than the UI's host name with PORT (e.g. behind a reverse proxy), set
// PROXY_ORIGIN=https://proxy.example.com. Likewise UI_ORIGIN for the UI's
// address as the browser sees it; only that origin may run bookmarklets in pages.
//
// Everything is in this one file: the HTTP servers, the proxy, a small HTML
// rewriter, the script injected into every page and the UI page.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import zlib from 'node:zlib';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import os from 'node:os';
import { Transform, pipeline } from 'node:stream';
import vm from 'node:vm';
import crypto from 'node:crypto';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { pathToFileURL } from 'node:url';

const PORT = Number(process.env.PORT) || 8787;
const HOST = process.env.HOST || '0.0.0.0';
const UI_PORT = Number(process.env.UI_PORT) || 8080;
const PROXY_ORIGIN = process.env.PROXY_ORIGIN ? process.env.PROXY_ORIGIN.replace(/\/+$/, '') : null;
const UI_ORIGIN = process.env.UI_ORIGIN ? process.env.UI_ORIGIN.replace(/\/+$/, '') : null;
const PREFIX = '/__px/';
const ORIGIN_COOKIE = '__px_origin';
const UPSTREAM_TIMEOUT_MS = 100_000; // time to response headers; slow origins can take 30s+
const MAX_BUFFERED_BYTES = 16 * 1024 * 1024; // CSS / JS rewriting buffers the body (HTML streams)

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

// ---------------------------------------------------------------- upstream connections

// Unlike a Cloudflare Worker, a Node server can reach your private network, so refuse
// hostnames that resolve to private, loopback or link-local addresses.
async function checkHost(hostname) {
  let addrs;
  try {
    addrs = await lookupAll(hostname);
  } catch {
    return null; // let fetch report the DNS failure
  }
  return addrs.some((a) => isPrivate(a.address)) ? `${hostname} resolves to a private address.` : null;
}

// getaddrinfo runs on libuv's small thread pool (shared with zlib and crypto)
// and every request needs an answer, so keep results briefly.
const DNS_TTL_MS = 30_000;
const dnsCache = new Map(); // hostname -> { at, p: Promise<addrs> }

function lookupAll(hostname) {
  const hit = dnsCache.get(hostname);
  if (hit && Date.now() - hit.at < DNS_TTL_MS) return hit.p;
  const p = dns.lookup(hostname, { all: true, verbatim: true });
  p.catch(() => dnsCache.delete(hostname));
  dnsCache.delete(hostname);
  dnsCache.set(hostname, { at: Date.now(), p });
  if (dnsCache.size > 1000) dnsCache.delete(dnsCache.keys().next().value);
  return p;
}

function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19));
  }
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isPrivate(v.slice(7));
  return v === '::' || v === '::1' || /^f[cd]/.test(v) || /^fe[89ab]/.test(v) || v.startsWith('ff');
}

// Refuse private addresses at connect time too, so DNS rebinding can't slip past checkHost.
function safeLookup(hostname, options, callback) {
  lookupAll(hostname).then((all) => {
    const bad = all.find((a) => isPrivate(a.address));
    if (bad) return callback(new Error(`${hostname} resolves to a private address.`));
    const addrs = options.family === 4 || options.family === 6 ? all.filter((a) => a.family === options.family) : all;
    if (!addrs.length) return callback(Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), { code: 'ENOTFOUND' }));
    if (options.all) return callback(null, addrs);
    callback(null, addrs[0].address, addrs[0].family);
  }, callback);
}

const agentOpts = { keepAlive: true, lookup: safeLookup, maxCachedSessions: 1000 };
const agents = { 'http:': new http.Agent(agentOpts), 'https:': new https.Agent(agentOpts) };

// Many servers send an incomplete certificate chain. Browsers fill the gap by
// downloading the missing intermediates (named in the certificate's AIA
// extension); Node doesn't, so do the same and keep an agent per host that
// trusts them.
const hostAgents = new Map(); // host:port -> Promise<https.Agent | null>
const CHAIN_ERRORS = new Set(['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_GET_ISSUER_CERT']);
const rootCAs = () => (tls.getCACertificates ? tls.getCACertificates('default') : tls.rootCertificates);

function chainAgent(host, port) {
  const key = `${host}:${port}`;
  if (!hostAgents.has(key)) {
    const p = fetchIntermediates(host, port).then((pems) => (pems.length
      ? new https.Agent({ ...agentOpts, ca: [...rootCAs(), ...pems] })
      : null)).catch(() => null);
    hostAgents.set(key, p);
    if (hostAgents.size > 1000) hostAgents.delete(hostAgents.keys().next().value);
  }
  return hostAgents.get(key);
}

async function fetchIntermediates(host, port) {
  let cert = await new Promise((resolve, reject) => {
    const s = tls.connect({ host, port, servername: host, rejectUnauthorized: false, lookup: safeLookup });
    s.setTimeout(10_000, () => s.destroy(new Error('timeout')));
    s.once('secureConnect', () => { resolve(s.getPeerX509Certificate()); s.destroy(); });
    s.once('error', reject);
  });
  const pems = [];
  for (let depth = 0; cert && depth < 4; depth++) {
    const uri = /CA Issuers - URI:(http:\/\/\S+)/.exec(cert.infoAccess || '');
    if (!uri) break;
    const der = await download(uri[1]);
    try { cert = new crypto.X509Certificate(der); } catch { break; }
    pems.push(cert.toString());
    if (cert.issuer === cert.subject) break;
  }
  return pems;
}

function download(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { agent: agents['http:'], timeout: 10_000 }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > 64 * 1024) req.destroy(new Error('too large'));
        else chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

const ENCODINGS = ['gzip', 'deflate', 'br', ...(zlib.createZstdDecompress ? ['zstd'] : [])];
const DECODERS = {
  gzip: () => zlib.createGunzip(),
  'x-gzip': () => zlib.createGunzip(),
  deflate: () => zlib.createInflate(),
  br: () => zlib.createBrotliDecompress(),
  ...(zlib.createZstdDecompress && { zstd: () => zlib.createZstdDecompress() }),
};

// fetch() replacement built on node:http(s). Node's global fetch rewrites
// sec-fetch-mode to "cors" and adds its own defaults, which makes many sites
// treat page loads as API calls; this sends the browser's headers as given.
async function nodeFetch(url, init = {}) {
  const u = new URL(url);
  const port = Number(u.port) || 443;
  let agent = agents[u.protocol];
  if (u.protocol === 'https:' && hostAgents.has(`${u.hostname}:${port}`)) {
    agent = (await chainAgent(u.hostname, port)) || agent;
  }
  try {
    return await nodeRequest(u, init, agent);
  } catch (err) {
    // A streamed body can't be replayed; the next request to the host will use the fixed agent.
    if (agent !== agents['https:'] || !CHAIN_ERRORS.has(err.code) || init.body) throw err;
    const fixed = await chainAgent(u.hostname, port);
    if (!fixed) throw err;
    return nodeRequest(u, init, fixed);
  }
}

// Resolves to { status, statusText, headers, body }, where body is the raw
// (still compressed) node:http response stream, or null. Web streams cost a
// lot per chunk, so bodies stay Node streams all the way to the client.
function nodeRequest(u, init, agent) {
  return new Promise((resolve, reject) => {
    const headers = {};
    for (const [k, v] of new Headers(init.headers)) headers[k] = v;
    headers['accept-encoding'] = ENCODINGS.join(', ');

    const req = (u.protocol === 'https:' ? https : http).request(u, {
      method: init.method || 'GET',
      headers,
      agent,
      signal: init.signal,
      // Browsers accept large and slightly malformed responses; so should we.
      insecureHTTPParser: true,
      maxHeaderSize: 256 * 1024,
    });
    req.on('error', reject);
    req.on('response', (res) => {
      const out = new Headers();
      for (let i = 0; i < res.rawHeaders.length; i += 2) {
        try { out.append(res.rawHeaders[i], res.rawHeaders[i + 1]); } catch {}
      }
      const noBody = init.method === 'HEAD' || [204, 205, 304].includes(res.statusCode);
      if (noBody) res.resume();
      // Response only allows 200-599 (some sites use e.g. 999) and a plain reason phrase.
      const status = res.statusCode < 200 || res.statusCode > 599 ? 502 : res.statusCode;
      const statusText = (res.statusMessage || '').replace(/[^\t\x20-\x7e\x80-\xff]/g, '');
      resolve({ status, statusText, headers: out, body: noBody ? null : res });
    });
    if (init.body) init.body.on('error', (e) => req.destroy(e)).pipe(req);
    else req.end();
  });
}

// ---------------------------------------------------------------- request handling

async function handle(request) {
  try {
    const r = await resolveTarget(request);
    return r.response || await proxy(request, r.self, r.target);
  } catch (err) {
    return errorPage(500, 'Proxy error', errText(err));
  }
}

// Works out which upstream URL a request is for: { self, target } or { response }.
async function resolveTarget(request) {
  const url = new URL(request.url);

  // Convenience entry point: /?url=example.com
  if (url.pathname === '/' && url.searchParams.has('url')) {
    const target = normalizeInput(url.searchParams.get('url'));
    if (!target) return { response: errorPage(400, 'Invalid URL', 'Pass a public http(s) URL.') };
    return { response: Response.redirect(url.origin + PREFIX + target.href, 302) };
  }

  if (url.pathname === '/__px_sw.js') return { response: serviceWorkerResponse() };

  let target;
  if (url.pathname.startsWith(PREFIX)) {
    const raw = url.pathname.slice(PREFIX.length).replace(/^([a-z]+):\/(?!\/)/i, '$1://') + url.search;
    try { target = new URL(raw); } catch {
      return { response: errorPage(400, 'Invalid URL', raw) };
    }
  } else {
    // A request that escaped rewriting (e.g. "/assets/app.js"): work out which
    // site it belongs to from the Referer, then the origin cookie.
    const origin = originFromReferer(request, url) || originFromCookie(request);
    if (!origin) return { response: usagePage(url) };
    target = new URL(url.pathname + url.search, origin);
  }

  if (target.protocol === 'wss:') target.protocol = 'https:';
  if (target.protocol === 'ws:') target.protocol = 'http:';
  const blocked = blockedReason(target, url) || (await checkHost(target.hostname));
  if (blocked) return { response: errorPage(403, 'Blocked', blocked) };

  return { self: url, target };
}

// Headers to send upstream: hop-by-hop and identifying headers dropped,
// Origin / Referer translated back to the upstream site.
function upstreamHeaders(request, self, target) {
  const headers = new Headers();
  for (const [k, v] of request.headers) {
    if (!DROP_REQUEST_HEADERS.has(k) && !k.startsWith('cf-')) headers.set(k, v);
  }
  const cookie = siteCookies(request.headers.get('cookie'), cookieSite(target.hostname));
  if (cookie) headers.set('cookie', cookie);

  const refUp = refererUpstream(request, self);
  if (refUp) headers.set('referer', refUp.href);
  if (request.headers.has('origin')) headers.set('origin', refUp ? refUp.origin : target.origin);

  // Describe the request as the site would see it loaded directly: frames
  // become top-level documents and sec-fetch-site compares the real sites.
  if (/^i?frame$/.test(headers.get('sec-fetch-dest') || '')) headers.set('sec-fetch-dest', 'document');
  if (headers.has('sec-fetch-site')) {
    let site = headers.get('sec-fetch-site');
    if (refUp) {
      site = refUp.origin === target.origin ? 'same-origin'
        : refUp.protocol === target.protocol && cookieSite(refUp.hostname) === cookieSite(target.hostname) ? 'same-site'
          : 'cross-site';
    } else if (headers.get('sec-fetch-mode') === 'navigate') {
      site = 'none';
    }
    headers.set('sec-fetch-site', site);
  }
  return headers;
}

// The upstream page a request came from. The outermost frame shows the site's
// real path on the proxy's origin, so a plain same-origin Referer is mapped
// back using the origin cookie.
function refererUpstream(request, self) {
  const ref = request.headers.get('referer');
  if (!ref) return null;
  const up = upstreamFromProxied(ref, self);
  if (up) return up;
  try {
    const r = new URL(ref);
    const origin = r.origin === self.origin && originFromCookie(request);
    return origin ? new URL(r.pathname + r.search, origin) : null;
  } catch {
    return null;
  }
}

const errText = (err) => String((err && err.cause && err.cause.message) || (err && err.message) || err);

function normalizeInput(input) {
  let s = (input || '').trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  try {
    const u = new URL(s);
    return /^https?:$/.test(u.protocol) ? u : null;
  } catch {
    return null;
  }
}

function upstreamFromProxied(href, self) {
  const p = self.origin + PREFIX;
  if (!href || !href.startsWith(p)) return null;
  try { return new URL(href.slice(p.length)); } catch { return null; }
}

function originFromReferer(request, self) {
  const up = upstreamFromProxied(request.headers.get('referer'), self);
  return up && up.origin;
}

function originFromCookie(request) {
  const m = (request.headers.get('cookie') || '').match(new RegExp(`(?:^|;\\s*)${ORIGIN_COOKIE}=([^;]+)`));
  if (!m) return null;
  try {
    const u = new URL(decodeURIComponent(m[1]));
    return /^https?:$/.test(u.protocol) ? u.origin : null;
  } catch {
    return null;
  }
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

// ---------------------------------------------------------------- URL rewriting

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

// ---------------------------------------------------------------- proxy

async function proxy(request, self, target) {
  const headers = upstreamHeaders(request, self, target);

  if (request.headers.get('service-worker') === 'script') {
    return new Response('Service workers are disabled by the proxy', { status: 404 });
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), UPSTREAM_TIMEOUT_MS);
  let resp;
  try {
    resp = await nodeFetch(target.href, {
      method: request.method,
      headers,
      body: request.nodeBody,
      redirect: 'manual',
      signal: ctrl.signal,
    });
  } catch (err) {
    const timedOut = ctrl.signal.aborted;
    return errorPage(timedOut ? 504 : 502, timedOut ? 'Site timed out' : 'Could not reach site',
      `${target.href}\n${timedOut ? `No response within ${UPSTREAM_TIMEOUT_MS / 1000}s.` : errText(err)}`);
  } finally {
    clearTimeout(timer);
  }

  const out = new Headers(resp.headers);
  for (const h of DROP_RESPONSE_HEADERS) out.delete(h);
  // nodeFetch leaves the body compressed. Decoded, its length is unknown.
  let enc = (out.get('content-encoding') || '').trim().toLowerCase();
  if (enc === 'identity') enc = '';
  const length = enc ? 0 : Number(out.get('content-length') || 0);
  out.delete('content-encoding');
  const withBody = (body) => Object.assign(new Response(null, init), { nodeBody: body });
  const decoded = () => (DECODERS[enc] ? pipeline(resp.body, DECODERS[enc](), () => {}) : resp.body);
  const bytes = async () => {
    const buf = await readAll(resp.body);
    const fn = DECODERS[enc] && INFLATE[enc];
    return fn ? new Promise((res, rej) => fn(buf, (e, r) => (e ? rej(e) : res(r)))) : buf;
  };
  // Bodies that aren't rewritten keep their encoding if the client accepts it.
  const passthrough = () => {
    if (enc && DECODERS[enc]) {
      if (acceptsEncoding(request.headers.get('accept-encoding'), enc === 'x-gzip' ? 'gzip' : enc)) {
        out.set('content-encoding', enc);
        out.append('vary', 'accept-encoding');
        return withBody(resp.body);
      }
      out.delete('content-length');
    }
    return withBody(decoded());
  };

  const location = out.get('location');
  if (location) out.set('location', proxUrl(location, target));
  const refresh = out.get('refresh');
  if (refresh) out.set('refresh', rewriteRefresh(refresh, target));

  const cookies = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
  out.delete('set-cookie');
  const site = cookieSite(target.hostname);
  for (const c of cookies) out.append('set-cookie', rewriteCookie(c, site, isSecureOrigin(self)));

  const init = { status: resp.status, statusText: resp.statusText, headers: out };
  if (request.method === 'HEAD' || [204, 205, 304].includes(resp.status) || !resp.body) {
    if (resp.body) resp.body.resume();
    // The upstream length is of the encoded or not yet rewritten body.
    if (enc || /html|css|javascript|ecmascript/.test(out.get('content-type') || '')) out.delete('content-length');
    return new Response(null, init);
  }

  const type = (out.get('content-type') || '').toLowerCase();

  // What the body is used for decides how it is rewritten: a JSONP script
  // served as text/html is still a script.
  // The service worker's re-fetches arrive as "empty"; it passes the real destination along.
  const dest = request.headers.get('x-px-dest') || request.headers.get('sec-fetch-dest') || '';
  const asScript = /^(?:script|worker|sharedworker)$/.test(dest) && !/^(?:image|video|audio|font)\/|css|wasm|json/.test(type);
  // Rewritten text is always sent as UTF-8.
  const setType = (mime) => out.set('content-type', `${mime || type.split(';')[0].trim() || 'text/plain'}; charset=utf-8`);

  if (!asScript && /text\/html|application\/xhtml\+xml/.test(type)) {
    out.delete('content-length');
    out.set('referrer-policy', 'same-origin');
    out.set('cache-control', 'no-store');
    // XHTML is served as HTML: the injected runtime isn't well-formed XML.
    setType('text/html');
    const body = pipeline(decoded(), htmlStream(type, target), () => {}).on('error', () => {});
    // Headers go out with the first rewritten chunk, so a failure before it
    // (the runtime is injected only once <head> or <html> arrives) still gets an error page.
    let first;
    try {
      first = await firstChunk(body);
    } catch (err) {
      return errorPage(502, 'Could not reach site', `${target.href}\n${errText(err)}`);
    }
    if (first === null) return withBody(Buffer.alloc(0));
    body.unshift(first);
    return withBody(body);
  }
  const css = !asScript && type.includes('text/css');
  const js = !css && (asScript || /javascript|ecmascript/.test(type));
  if ((!css && !js) || length > MAX_BUFFERED_BYTES) return passthrough();

  if (js) out.set('x-px-js', '1');
  const job = { kind: css ? 'css' : 'js', base: target.href, type, worker: js && /worker$/.test(dest) };
  const asset = await rewriteAsset(job, await bytes());
  setType(js && asScript && !/javascript|ecmascript/.test(type) ? 'text/javascript' : null);
  return withBody(await assetBody(asset, request.headers.get('accept-encoding'), out));
}

const INFLATE = { gzip: zlib.gunzip, 'x-gzip': zlib.gunzip, deflate: zlib.inflate, br: zlib.brotliDecompress, zstd: zlib.zstdDecompress };

// The first chunk a stream produces (null if it ends empty), leaving it paused.
function firstChunk(stream) {
  return new Promise((resolve, reject) => {
    const done = (fn, v) => {
      stream.off('data', onData).off('end', onEnd).off('error', onError);
      fn(v);
    };
    const onData = (chunk) => { stream.pause(); done(resolve, chunk); };
    const onEnd = () => done(resolve, null);
    const onError = (err) => done(reject, err);
    stream.on('data', onData).on('end', onEnd).on('error', onError);
  });
}

async function readAll(stream) {
  const chunks = [];
  for await (const c of stream) chunks.push(c);
  return Buffer.concat(chunks);
}

// ---------------------------------------------------------------- CSS / JS rewriting

// Rewriting a large bundle takes tens of milliseconds of CPU, and sites load
// the same bundles on every page, so results are kept by content and base URL,
// along with their compressed forms. Large files are rewritten on worker
// threads so one bundle doesn't hold up every other request.
const REWRITE_CACHE_BYTES = 64 * 1024 * 1024;
const WORKER_MIN_BYTES = 32 * 1024;
const assetCache = new Map(); // key -> { key, buf, size, br?, gzip? } (least recently used first)
const assetJobs = new Map(); // key -> Promise<entry>, rewrites in progress
let assetCacheSize = 0;

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

function rewriteAsset(job, bytes) {
  const toBuf = (u8) => Buffer.from(u8.buffer, u8.byteOffset, u8.length);
  if (bytes.length < 2048) return { buf: toBuf(rewriteAssetSync(job, bytes)) };
  const key = crypto.createHash('sha1')
    .update(`${job.kind}\0${job.base}\0${job.type}\0${job.worker ? 1 : 0}\0`).update(bytes).digest('base64');
  const hit = assetCache.get(key);
  if (hit) {
    assetCache.delete(key);
    assetCache.set(key, hit);
    return hit;
  }
  let p = assetJobs.get(key);
  if (!p) {
    const run = bytes.length < WORKER_MIN_BYTES ? Promise.resolve().then(() => rewriteAssetSync(job, bytes)) : runInWorker(job, bytes);
    p = run.then((u8) => {
      const entry = { key, buf: toBuf(u8), size: 0 };
      if (u8.length <= REWRITE_CACHE_BYTES / 4) {
        assetCache.set(key, entry);
        growAssetCache(entry, u8.length);
      }
      return entry;
    }).finally(() => assetJobs.delete(key));
    assetJobs.set(key, p);
  }
  return p;
}

function growAssetCache(entry, n) {
  if (assetCache.get(entry.key) !== entry) return;
  entry.size += n;
  assetCacheSize += n;
  for (const [k, v] of assetCache) {
    if (assetCacheSize <= REWRITE_CACHE_BYTES) break;
    assetCache.delete(k);
    assetCacheSize -= v.size;
  }
}

// The rewritten body in the best encoding the client accepts. Compressed forms
// are made once (off the main thread) and kept with the entry.
async function assetBody(entry, accept, headers) {
  if (entry.buf.length < 1024) {
    headers.set('content-length', String(entry.buf.length));
    return entry.buf;
  }
  headers.append('vary', 'accept-encoding');
  const enc = acceptsEncoding(accept, 'br') ? 'br' : acceptsEncoding(accept, 'gzip') ? 'gzip' : null;
  let body = entry.buf;
  if (enc) {
    entry[enc] ||= new Promise((res, rej) => {
      const cb = (e, r) => (e ? rej(e) : res(r));
      if (enc === 'gzip') zlib.gzip(entry.buf, { level: 6 }, cb);
      else {
        zlib.brotliCompress(entry.buf, {
          params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5, [zlib.constants.BROTLI_PARAM_SIZE_HINT]: entry.buf.length },
        }, cb);
      }
    }).then((z) => { growAssetCache(entry, z.length); return z; }, () => { entry[enc] = null; return null; });
    const z = await entry[enc];
    if (z) {
      body = z;
      headers.set('content-encoding', enc);
    }
  }
  headers.set('content-length', String(body.length));
  return body;
}

// Worker threads run this same file; see the bottom of it. Piped in
// (`curl … | node`) there is no file for them to load, so rewriting runs inline.
const WORKER_URL = (() => {
  try {
    const u = new URL(import.meta.url);
    return u.protocol === 'file:' && fs.existsSync(u) ? u : null;
  } catch {
    return null;
  }
})();
const POOL_SIZE = Math.max(1, Math.min(8, (os.availableParallelism ? os.availableParallelism() : os.cpus().length) - 1));
const pool = []; // { w, task }
const jobQueue = [];
let workerFailures = 0;

function runInWorker(job, bytes) {
  if (!WORKER_URL || workerFailures >= 3) return Promise.resolve().then(() => rewriteAssetSync(job, bytes));
  return new Promise((resolve, reject) => {
    jobQueue.push({ job, bytes, resolve, reject });
    pump();
  });
}

function pump() {
  while (jobQueue.length) {
    let slot = pool.find((s) => !s.task);
    if (!slot) {
      if (pool.length >= POOL_SIZE) return;
      slot = spawnWorker();
    }
    const task = jobQueue.shift();
    slot.task = task;
    slot.w.ref();
    slot.w.postMessage({ job: task.job, bytes: task.bytes });
  }
}

function spawnWorker() {
  const w = new Worker(WORKER_URL, { workerData: { peekaboomRewriter: true } });
  const slot = { w, task: null };
  w.unref();
  w.on('message', (m) => {
    const t = slot.task;
    slot.task = null;
    w.unref();
    if (t) {
      if (m.error) t.reject(new Error(m.error));
      else t.resolve(m.out);
    }
    pump();
  });
  let dead = false;
  const fail = () => {
    if (dead) return;
    dead = true;
    workerFailures++;
    pool.splice(pool.indexOf(slot), 1);
    // Whatever killed the worker, the job still gets done.
    const t = slot.task;
    slot.task = null;
    if (t) {
      try { t.resolve(rewriteAssetSync(t.job, t.bytes)); } catch (e) { t.reject(e); }
    }
    pump();
  };
  w.on('error', fail);
  w.on('exit', fail);
  pool.push(slot);
  return slot;
}

// ---------------------------------------------------------------- HTML streaming

const HTML_CHARSET = /<meta[^>]+charset=["']?([\w-]+)/i;

// Rewrites an HTML response body as it arrives. The charset is settled from
// the first 4 KB like decodeText() does; a page with no declared charset is
// read whole, since telling UTF-8 from windows-1252 needs every byte.
function htmlStream(contentType, upstream) {
  const rewrite = htmlRewriter(upstream);
  let head = [];
  let headLength = 0;
  let decoder = null;
  let whole = null; // chunks, when the page must be read whole
  const start = (bytes) => {
    try {
      const charset = sniffCharset(bytes, contentType, HTML_CHARSET);
      if (charset) decoder = new TextDecoder(charset);
    } catch {}
    head = null;
    if (!decoder) { whole = [bytes]; return ''; }
    return rewrite(decoder.decode(bytes, { stream: true }), false);
  };
  return new Transform({
    transform(chunk, _, cb) {
      let s = '';
      try {
        if (whole) whole.push(chunk);
        else if (decoder) s = rewrite(decoder.decode(chunk, { stream: true }), false);
        else {
          head.push(chunk);
          headLength += chunk.length;
          if (headLength >= 4096) s = start(Buffer.concat(head));
        }
      } catch (e) { return cb(e); }
      cb(null, s ? Buffer.from(s) : undefined);
    },
    flush(cb) {
      let s = '';
      try {
        if (head) s = start(Buffer.concat(head));
        s += whole
          ? rewrite(decodeText(Buffer.concat(whole), contentType, HTML_CHARSET), true)
          : rewrite(decoder.decode(), true);
      } catch (e) { return cb(e); }
      cb(null, s ? Buffer.from(s) : undefined);
    },
  });
}

// Inline scripts repeat across a site's pages too; same idea, kept as strings.
const INLINE_CACHE_BYTES = 32 * 1024 * 1024;
const rewriteCache = new Map(); // key -> string
let rewriteCacheSize = 0;

function cached(kind, base, input, fn) {
  if (input.length < 2048) return fn(input);
  const key = crypto.createHash('sha1').update(`${kind}\0${base}\0`).update(input).digest('base64');
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

function acceptsEncoding(header, enc) {
  for (const part of (header || '').toLowerCase().split(',')) {
    const [name, ...params] = part.trim().split(';');
    if (name.trim() !== enc && name.trim() !== '*') continue;
    const q = params.map((p) => /^\s*q\s*=\s*([\d.]+)/.exec(p)).find(Boolean);
    return !q || Number(q[1]) > 0;
  }
  return false;
}

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

// ---------------------------------------------------------------- HTML

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
        if (/^on/i.test(a.name)) t.set(a.name, rewriteJs(a.value));
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

// Node can tell us whether rewritten code still compiles (modules excepted).
function vmCheck(code) {
  try { new vm.Script(code); return true; } catch { return false; }
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

// ---------------------------------------------------------------- pages

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

// ---------------------------------------------------------------- HTML tokenizer

// Small HTML rewriter. It walks the document once, hands every
// start tag to `tag(t)` so attributes can be read and changed, and hands the
// contents of raw-text elements (<script>, <style>, ...) to `rawText(t, text)`.
// Everything it doesn't touch is copied through byte for byte.

const RAW_TEXT = new Set(['script', 'style', 'textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes', 'noscript']);
const SPACE = new Set([' ', '\t', '\n', '\r', '\f']);

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
      if (!/[a-zA-Z]/.test(c)) { out.push('<'); i = lt + 1; continue; }

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
      if (RAW_TEXT.has(t.name)) raw = { t, close: new RegExp(`</${t.name}[\\s/>]`, 'ig'), scan: i };
    }
    rest = i < n ? html.slice(i) : '';
    return out.join('');
  };
}

function parseTag(s, start) {
  const n = s.length;
  let i = start + 1;
  while (i < n && !SPACE.has(s[i]) && s[i] !== '/' && s[i] !== '>') i++;
  const rawName = s.slice(start + 1, i);
  const attrs = [];
  while (i < n) {
    while (i < n && (SPACE.has(s[i]) || s[i] === '/')) i++;
    if (i >= n) return null;
    if (s[i] === '>') {
      return new Tag(rawName, attrs, s[i - 1] === '/', s.slice(start, i + 1), i + 1);
    }
    const nameStart = i;
    i++; // the first character always belongs to the name (even "=")
    while (i < n && !SPACE.has(s[i]) && !'/>='.includes(s[i])) i++;
    const name = s.slice(nameStart, i);
    let value = null;
    let p = i;
    while (p < n && SPACE.has(s[p])) p++;
    if (s[p] === '=') {
      p++;
      while (p < n && SPACE.has(s[p])) p++;
      const q = s[p];
      if (q === '"' || q === "'") {
        const e = s.indexOf(q, p + 1);
        if (e === -1) return null;
        value = s.slice(p + 1, e);
        i = e + 1;
      } else {
        let e = p;
        while (e < n && !SPACE.has(s[e]) && s[e] !== '>') e++;
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

  get(name) {
    const a = this.attrs.find((x) => x.name === name);
    return a ? a.value ?? '' : null;
  }

  set(name, value) {
    const a = this.attrs.find((x) => x.name === name);
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

// ---------------------------------------------------------------- JavaScript rewriting

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
    const DECL = /\b(?:var|let|const|function|class)\s+(location|top|parent)\b|(?<=[(,]|(?<!\$)\{)\s*(location|top|parent)\s*(?=[,)}]|=(?!=))|\b(location|top|parent)\s*=>|\.\.\.\s*(location|top|parent)\b/g;
    for (let m, found = 0; found < 3 && (m = DECL.exec(src));) {
      const name = m[1] || m[2] || m[3] || m[4];
      if (!skip[name]) { skip[name] = true; found++; }
    }
    const fake = (n) => (n === 'location' ? '(globalThis.__px$L||location)' : `(globalThis.__px$${n}||${n})`);
    const P = (t, v) => t && t.t === 'p' && t.v === v;
    const isDot = (t) => t && t.t === 'p' && (t.v === '.' || t.v === '?.');
    const isAssign = (t) => t && t.t === 'p' && /^(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)?=$/.test(t.v);
    const WIN = new Set(['window', 'self', 'globalThis', 'document', 'top', 'parent']);

    const stack = []; // open brackets: { cls, ev: [edit indexes] | null }
    let pendingClass = false;
    const inClass = () => stack.length > 0 && stack[stack.length - 1].cls;
    // A bare name in a class body right after `{ } ;`, a value or a modifier is a member name.
    const classMember = (p) => inClass() && (!p || p.t !== 'p' || ['{', '}', ';', ')', ']', '*'].includes(p.v));
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
            if (/^https?:$/.test(abs.protocol)) edits.push([nx.s, nx.e, JSON.stringify('/__px/' + abs.href)]);
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
      PUNCT.lastIndex = i;
      m = PUNCT.exec(src);
      const v = m ? m[0] : ch;
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

// ---------------------------------------------------------------- service worker

// Served at /__px_sw.js and registered by the page runtime. It catches the
// requests the runtime's patches miss (CSS fonts, innerHTML images, worker
// imports, ...): cross-origin ones go through /__px/, unprefixed same-origin
// ones are mapped to the site of the page that made them, and scripts the
// server did not rewrite (no x-px-js header) are run through rewriteJs.
function serviceWorker(PREFIX, rewriteJs) {
  const ME = self.location.origin;
  const origins = new Map(); // clientId -> upstream origin of an outermost frame

  self.addEventListener('install', () => self.skipWaiting());
  self.addEventListener('activate', (e) => e.waitUntil(Promise.all([
    self.clients.claim(),
    // Drop caches made by an older rewriter.
    cacheName.then((name) => caches.keys().then((keys) => Promise.all(
      keys.filter((k) => k.startsWith('__px-js-') && k !== name).map((k) => caches.delete(k))))),
  ])));
  self.addEventListener('message', (e) => {
    const d = e.data;
    if (d && d.__px === 'origin' && e.source && e.source.id) origins.set(e.source.id, d.origin);
  });
  self.addEventListener('fetch', (e) => {
    const req = e.request;
    if (req.mode === 'navigate' || !/^https?:/.test(req.url)) return;
    const url = new URL(req.url);
    if (url.origin === ME) {
      if (url.pathname === '/__px_sw.js' || (url.pathname === '/' && url.searchParams.has('url'))) return;
      if (url.pathname.startsWith(PREFIX)) {
        if (isScript(req)) {
          const tagged = new Request(req, { mode: 'same-origin', headers: withDest(req) });
          e.respondWith(fetch(tagged).then((r) => rewriteResponse(r, url.href.slice(ME.length + PREFIX.length))));
        }
        return;
      }
      e.respondWith(siteOf(e.clientId).then((origin) =>
        origin ? forward(req, origin + url.pathname + url.search) : fetch(req)));
      return;
    }
    e.respondWith(forward(req, url.href));
  });

  function isScript(req) {
    return ['script', 'worker', 'sharedworker', 'serviceworker'].includes(req.destination);
  }
  // Re-fetched requests lose their destination, which tells the server to
  // treat the response as a script (and add the worker runtime).
  function withDest(req) {
    const h = new Headers(req.headers);
    if (req.destination) h.set('x-px-dest', req.destination);
    return h;
  }

  async function siteOf(clientId) {
    if (!clientId) return null;
    if (origins.has(clientId)) return origins.get(clientId);
    const c = await self.clients.get(clientId);
    if (!c || !c.url.startsWith(ME + PREFIX)) return null;
    try { return new URL(c.url.slice(ME.length + PREFIX.length)).origin; } catch (err) { return null; }
  }

  async function forward(req, upstream) {
    const init = {
      method: req.method,
      headers: withDest(req),
      credentials: 'include',
      cache: req.cache === 'only-if-cached' ? 'default' : req.cache,
      redirect: 'follow',
      signal: req.signal,
    };
    if (!['GET', 'HEAD'].includes(req.method)) init.body = await req.arrayBuffer();
    let r;
    try {
      r = await fetch(ME + PREFIX + upstream, init);
    } catch (err) {
      return Response.error();
    }
    return isScript(req) ? rewriteResponse(r, upstream) : r;
  }

  async function rewriteResponse(r, upstream) {
    const type = (r.headers.get('content-type') || '').toLowerCase();
    if (!r.ok || r.headers.has('x-px-js') || !/javascript|ecmascript|text\/plain/.test(type)) return r;
    const src = await r.text();
    const code = await cachedRewrite(src, upstream);
    const headers = new Headers(r.headers);
    headers.delete('content-length');
    headers.set('x-px-js', '1');
    return new Response(code, { status: r.status, statusText: r.statusText, headers });
  }

  // Rewritten scripts are cached by a hash of their URL and source, so a
  // script is rewritten once per version no matter how its HTTP caching is set
  // up. The cache name carries a hash of the rewriter, so changing it starts
  // a fresh cache. Small scripts aren't worth the cache I/O.
  const CACHE_MIN = 8 * 1024;
  const CACHE_MAX_ENTRIES = 300;
  const cacheName = sha256(String(rewriteJs)).then((h) => '__px-js-' + h.slice(0, 16));
  let pruning = null;

  async function cachedRewrite(src, upstream) {
    const check = (c) => { try { new Function(c); return true; } catch (err) { return false; } };
    if (src.length < CACHE_MIN) return rewriteJs(src, upstream, check);
    let cache, key;
    try {
      cache = await caches.open(await cacheName);
      key = ME + '/__px_cache/' + (await sha256(upstream + '\n' + src));
      const hit = await cache.match(key);
      if (hit) return hit.headers.has('x-px-same') ? src : hit.text();
    } catch (err) {
      cache = null; // Cache API unavailable (e.g. private mode): just rewrite.
    }
    const code = rewriteJs(src, upstream, check);
    if (cache) {
      // Unchanged scripts store an empty marker instead of a second copy.
      const entry = code === src
        ? new Response('', { headers: { 'x-px-same': '1' } })
        : new Response(code, { headers: { 'content-type': 'application/javascript' } });
      cache.put(key, entry).then(() => prune(cache)).catch(() => {});
    }
    return code;
  }

  // Keep the cache bounded; keys() lists oldest entries first.
  function prune(cache) {
    if (pruning) return pruning;
    pruning = cache.keys().then((keys) => Promise.all(
      keys.slice(0, Math.max(0, keys.length - CACHE_MAX_ENTRIES)).map((k) => cache.delete(k)),
    )).catch(() => {}).then(() => { pruning = null; });
    return pruning;
  }

  async function sha256(s) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  }
}

const SW_SCRIPT = `(function(__name){(${serviceWorker})(${JSON.stringify(PREFIX)}, ${rewriteJs});})(function(f){return f;});`;

function serviceWorkerResponse() {
  return new Response(SW_SCRIPT, {
    headers: {
      'content-type': 'application/javascript; charset=utf-8',
      'cache-control': 'no-cache',
      'service-worker-allowed': '/',
    },
  });
}

// ---------------------------------------------------------------- injected worker script

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

// ---------------------------------------------------------------- injected page script

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
  // The UI (and only the UI's origin) can also run bookmarklets: { __px: 'run' }.
  let hostOpens = false;
  let uiOrigin = '';
  try { uiOrigin = new URL(C.uiOrigin || location.protocol + '//' + location.hostname + ':' + C.uiPort).origin; } catch (e) {}
  if (!nested && window.parent !== window) {
    addEventListener('message', (e) => {
      if (e.source !== window.parent || !e.data) return;
      if (e.data.__px === 'host') {
        hostOpens = true;
        e.stopImmediatePropagation();
      } else if (e.data.__px === 'run' && uiOrigin && e.origin === uiOrigin && typeof e.data.code === 'string') {
        e.stopImmediatePropagation();
        try { (0, eval)(js(e.data.code)); } catch (err) { console.error(err); }
      } else if (e.data.__px === 'mute' && uiOrigin && e.origin === uiOrigin) {
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
      sw.register('/__px_sw.js', { scope: '/' }).catch(() => {});
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
          url = nested ? prox(s) : s.slice(UP.origin.length) || '/';
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
        if (real.origin === UP.origin) _replaceState.call(history, history.state, '', real.pathname + real.search + real.hash);
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

function runtimeScript(upstream, prefix, swReload) {
  const json = JSON.stringify({
    upstream: upstream.href, prefix, swReload, cookieSite: cookieSite(upstream.hostname),
    uiPort: UI_PORT, uiOrigin: UI_ORIGIN,
  }).replace(/</g, '\\u003c');
  return RUNTIME_HEAD + json + RUNTIME_TAIL;
}

// ---------------------------------------------------------------- HTTP server

function toRequest(req, withBody) {
  const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
  const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) v.forEach((x) => headers.append(k, x));
    else if (v != null) headers.set(k, v);
  }
  const request = new Request(`${proto}://${host}${req.url}`, { method: req.method, headers });
  // The body stays a Node stream and is piped straight upstream.
  if (withBody) request.nodeBody = req;
  return request;
}

// Text the proxy decoded or rewrote is compressed again for the browser.
// Flushing after every chunk keeps streamed responses streaming.
const COMPRESSIBLE = /^(?:text\/(?!event-stream)|application\/(?:(?:x-)?javascript|ecmascript|json|xml|xhtml\+xml|wasm|[\w.-]+\+(?:json|xml))|image\/svg\+xml)/;

function compressor(req, resp, body) {
  if (!body || resp.headers.has('content-encoding') || resp.headers.has('content-range') || resp.status === 206) return null;
  if (!COMPRESSIBLE.test(resp.headers.get('content-type') || '')) return null;
  const length = body instanceof Uint8Array ? body.length : resp.headers.get('content-length');
  if (length != null && Number(length) < 1024) return null;
  const accept = req.headers['accept-encoding'];
  if (acceptsEncoding(accept, 'br')) {
    return ['br', zlib.createBrotliCompress({
      flush: zlib.constants.BROTLI_OPERATION_FLUSH,
      params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 4 },
    })];
  }
  if (acceptsEncoding(accept, 'gzip')) return ['gzip', zlib.createGzip({ flush: zlib.constants.Z_SYNC_FLUSH, level: 6 })];
  return null;
}

// Proxied responses carry their body as `nodeBody` (a Node stream or a
// Buffer); the proxy's own pages are small web Responses.
async function send(req, res, resp) {
  const headers = {};
  for (const [k, v] of resp.headers) if (k !== 'set-cookie') headers[k] = v;
  const cookies = resp.headers.getSetCookie();
  if (cookies.length) headers['set-cookie'] = cookies;
  let body = resp.nodeBody || (resp.body ? Buffer.from(await resp.arrayBuffer()) : null);
  const z = compressor(req, resp, body);
  if (z) {
    headers['content-encoding'] = z[0];
    headers.vary = headers.vary ? `${headers.vary}, accept-encoding` : 'accept-encoding';
    delete headers['content-length'];
  } else if (body instanceof Uint8Array) {
    headers['content-length'] = body.length;
  }
  res.writeHead(resp.status, resp.statusText || undefined, headers);
  if (!body) return res.end();
  if (body instanceof Uint8Array) {
    if (!z) return res.end(body);
    z[1].end(body);
  } else {
    body.on('error', () => res.destroy());
    res.on('close', () => body.destroy());
    if (z) body.pipe(z[1]);
  }
  if (z) {
    body = z[1];
    body.on('error', () => res.destroy());
    res.on('close', () => body.destroy());
  }
  body.pipe(res);
}

const server = http.createServer({ maxHeaderSize: 256 * 1024 }, async (req, res) => {
  try {
    const request = toRequest(req, !['GET', 'HEAD'].includes(req.method));
    await send(req, res, await handle(request));
  } catch (err) {
    if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain' });
    res.end(String((err && err.message) || err));
  }
});

// WebSockets: resolve the target like any request, then splice the raw
// sockets together after sending the upgrade request upstream.
const WS_TIMEOUT = 30_000;

function upstreamSocket(target, port, secure, ca) {
  return new Promise((resolve, reject) => {
    const s = secure
      ? tls.connect({ host: target.hostname, port, servername: target.hostname, ALPNProtocols: ['http/1.1'], lookup: safeLookup, ...(ca && { ca }) })
      : net.connect({ host: target.hostname, port, lookup: safeLookup });
    s.setTimeout(WS_TIMEOUT, () => s.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    s.once(secure ? 'secureConnect' : 'connect', () => { s.setTimeout(0); s.removeListener('error', reject); s.on('error', () => {}); resolve(s); });
    s.once('error', reject);
  });
}

server.on('upgrade', async (req, socket, head) => {
  socket.on('error', () => {});
  try {
    const request = toRequest(req, false);
    const r = await resolveTarget(request);
    if (r.response) {
      socket.end(`HTTP/1.1 ${r.response.status} ${r.response.statusText || 'Error'}\r\nConnection: close\r\n\r\n`);
      return;
    }
    const { self, target } = r;
    const secure = target.protocol === 'https:';
    const port = Number(target.port) || (secure ? 443 : 80);
    let closed = false;
    socket.once('close', () => { closed = true; });
    const key = `${target.hostname}:${port}`;
    let ca = secure && hostAgents.has(key) ? (await chainAgent(target.hostname, port))?.options.ca : undefined;
    let up;
    try {
      up = await upstreamSocket(target, port, secure, ca);
    } catch (err) {
      // Same incomplete-chain fallback as nodeFetch().
      if (!secure || ca || !CHAIN_ERRORS.has(err.code)) throw err;
      ca = (await chainAgent(target.hostname, port))?.options.ca;
      if (!ca) throw err;
      up = await upstreamSocket(target, port, secure, ca);
    }
    if (closed) { up.destroy(); return; }

    const lines = [`GET ${target.pathname}${target.search} HTTP/1.1`, `Host: ${target.host}`,
      'Connection: Upgrade', 'Upgrade: websocket'];
    for (const [k, v] of upstreamHeaders(request, self, target)) lines.push(`${k}: ${v}`);

    // Keep the timeout until the upstream answers the handshake.
    up.setTimeout(WS_TIMEOUT, () => up.destroy());
    up.once('data', () => up.setTimeout(0));
    up.write(lines.join('\r\n') + '\r\n\r\n');
    if (head && head.length) up.write(head);
    up.pipe(socket);
    socket.pipe(up);
    up.on('error', () => socket.destroy());
    up.on('close', () => socket.destroy());
    socket.on('close', () => up.destroy());
  } catch {
    // Upstream unreachable (or bad TLS): answer like the HTTP path does.
    if (socket.writable) socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
    else socket.destroy();
  }
});

// The browser UI: one page, plus search suggestions (DuckDuckGo's autocomplete,
// fetched here because the page can't call it cross-origin).
const uiServer = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://ui');
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { allow: 'GET, HEAD' }).end();
    return;
  }
  if (url.pathname === '/') {
    const config = JSON.stringify({ origin: PROXY_ORIGIN, port: PORT }).replace(/</g, '\\u003c');
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    });
    res.end(req.method === 'HEAD' ? undefined : UI_HTML.replace('__PROXY_CONFIG__', () => config));
    return;
  }
  if (url.pathname === '/suggest') {
    const q = (url.searchParams.get('q') || '').slice(0, 200);
    let list = [];
    if (q.trim()) {
      try {
        const r = await fetch('https://duckduckgo.com/ac/?type=list&q=' + encodeURIComponent(q), {
          signal: AbortSignal.timeout(4000),
        });
        const data = await r.json();
        if (Array.isArray(data) && Array.isArray(data[1])) list = data[1].filter(x => typeof x === 'string').slice(0, 8);
      } catch {}
    }
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(list));
    return;
  }
  res.writeHead(404, { 'content-type': 'text/plain' }).end('Not found');
});

// Imported (e.g. by index.test.js) it only provides the exports below. Run
// directly, or piped in (`curl … | node`, where there is no script path), it serves.
if (isMainThread && (!process.argv[1] || import.meta.url === pathToFileURL(process.argv[1]).href)) {
  let listening = 0;
  const ready = () => { if (++listening === 2) console.log(banner()); };
  server.listen(PORT, HOST, () => {
    ready();
    // Start the rewriting workers now rather than on the first big script.
    if (WORKER_URL) while (pool.length < POOL_SIZE) spawnWorker();
  });
  uiServer.listen(UI_PORT, HOST, ready);
}

// A rewriting worker (see runInWorker): CSS / JS in, UTF-8 bytes out.
if (!isMainThread && workerData && workerData.peekaboomRewriter) {
  parentPort.on('message', ({ job, bytes }) => {
    try {
      const out = rewriteAssetSync(job, bytes);
      parentPort.postMessage({ out }, [out.buffer]);
    } catch (err) {
      parentPort.postMessage({ error: String((err && err.stack) || err) });
    }
  });
}

// Startup message. Plain text when piped or when NO_COLOR is set.
function banner() {
  const color = process.stdout.isTTY && !process.env.NO_COLOR;
  const rgb = (r, g, b) => s => color ? `\x1b[38;2;${r};${g};${b}m${s}\x1b[0m` : s;
  const bold = s => color ? `\x1b[1m${s}\x1b[22m` : s;
  const dim = s => color ? `\x1b[2m${s}\x1b[22m` : s;
  const logo = [
    '█▄▀ █▄ █ █▀█ █ █▀█ █▀▀ █▄ █',
    '█ █ █ ▀█ █▄█ █ █▀▄ ██▄ █ ▀█',
  ];
  // Violet to cyan, one shade per column.
  const shade = (line) => [...line].map((ch, i, all) => {
    const t = i / (all.length - 1);
    return rgb(Math.round(167 - 133 * t), Math.round(139 + 72 * t), Math.round(250 - 12 * t))(ch);
  }).join('');
  const uiUrl = UI_ORIGIN || `http://localhost:${UI_PORT}`;
  const proxyUrl = PROXY_ORIGIN || `http://localhost:${PORT}`;
  const row = (dot, label, url) => `  ${dot} ${label.padEnd(8)}${bold(url)}`;
  return [
    '',
    ...logo.map(l => '  ' + shade(l)),
    dim('  proxy browser'),
    '',
    row(rgb(74, 222, 128)('●'), 'Open', uiUrl),
    row(rgb(96, 165, 250)('●'), 'Proxy', proxyUrl),
    '',
    dim('  Ctrl+C to stop'),
    '',
  ].join('\n');
}

export {
  server, uiServer, rewriteHtml, rewriteCss, rewriteJs, mapSrcset, proxUrl, rewriteCookie, siteCookies, cookieSite,
  decodeText, runtimeScript, withWorkerRuntime,
};

// The Knoiren Browser page served by uiServer. __PROXY_CONFIG__ is filled in per request.
const UI_HTML = `<!DOCTYPE html>
<html lang="en"> 

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="no-referrer">
    <title>New tab</title>
    <link rel="icon" type="image/png" sizes="any" media="(prefers-color-scheme: light)"
        href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAMAAAD04JH5AAAAZlBMVEUAAABAQEA4QEg4QEA6QEU6QEA8QEQ8QEA9QEM+QEM6QEI7QEQ7QEI8QEQ8QEI8QEQ8QEI9QEQ9QEI8QEM8QEI7QEM7QEM8QEM8QEM8QEQ8QEM9QEM9QEI7QEM7QEI8QEM8QEI8QEOBp9B1AAAAIXRSTlMAECAgMDBAQFBfYHBwf3+AgI+PkJCfoK+/z8/f39/f7+84OiXtAAAB70lEQVR42u3azU7jMBRA4SSeJmmHGX5MwEBLct//JTldWLIMsVNgYVf3W1WQKmdx1dhuG6WUusQAixfMEAFmOFgM0IDrCzjgDbLRCXtoQP0BHRzkm07ooAF1BuwxQ35oxggNqCtghPyyPTSgnoA3yC+b0UED6gi4gaxYcIsR5kItNKCOgDMHiVi0aH5AA8oOmOBf95DAXzSBFjsM+CpqSNCAMgP8DcMLniG4Q3jjB8yQwITwYWMhKwZoQHkBjxCc4IfK4BXhZjW1WPHv9aELBDELDSgvwEEQD90O/vUTJOMe/vpbCGKv0IDyAsKBmdEifvhIRvzeEWvXaEB5ARKZ8OlhtZEfXANZoQHlB8QLhz+QjQZoQH0BCyTi0CBaYGS1SA3uDA0oL+AFuUNmC8mYkFvAOGhAeQGP2LLZOEJWvMMgd+htoQHlBfTYstkwiIdrQXyI+Q+yYoAGlBXgpQbsBvFGpccO/sZeh9SgNtCAMgMOkIT/aJLyBxl7aEC5AWcOknDChAEGZx3CQ63cAGpA2QEGC+QCWxYhCww0oPyAS3/INGHLB9mIBhpQR4CPWCDIbURSX2gt8DfXgLoCzgyO2LK4eIBEHHygBtQZ4B1wxNriokP8vzBOA+oP8HpYOIwIDyMcLHr4v2vA9QUopa7SBwy1hh79c1UmAAAAAElFTkSuQmCC">

    <link rel="icon" type="image/png" sizes="any" media="(prefers-color-scheme: dark)"
        href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAMAAAD04JH5AAAAZlBMVEUAAAC/v7/Hv7/Hv7fFv7/Fv7rDv7/Dv7vCv7zBv7zFv73Ev73Ev7vDv73Dv7vDv73Dv7vCv73Cv7vDv73Dv7zEv7zEv7zDv7zDv7zDv7zDv7vEv73Ev7zCv73Cv7zDv73Dv7zDv7xno0nKAAAAIXRSTlMAECAgMDBAQFBfYHBwf3+AgI+PkJCfoK+/z8/f39/f7+84OiXtAAAB70lEQVR42u3azU7jMBRA4cTpJGmZGf4cMNCS3Pd/SU4XlixD7BRY2NX9VhWkyllcNbbbRimlLtHD4hULRIAFDhY9NOD6Ag54h2x0xB4aUH9ABwf5piM6aECdAXsskB9aMEID6goYIb9sDw2oJ+Ad8ssWdNCAOgJuICtm3GGEuVALDagj4MxBIhYtmh/QgLIDJvjXAyTwF02gxQ49vorqEzSgzAB/w/CCZwhuEd74HgskMCF82FjIih4aUF7AIwRH+KEyeEG4WU0tVvx7fegMQcxCA8oLcBDEQ7eDf/0EyXiAv/4OgtgLNKC8gHBgFrSIHz6SEb93xNo1GlBegEQmfHpYbeQH10BWaED5AfHC4Q9kox4aUF/ADIk4NIgWGFktUoO7QAPKC3hF7pDZQjIm5BYwDhpQXsAjtmw2TpAVbzDIHXpbaEB5AQO2bDYM4uGaER9i/oes6KEBZQV4qQG7QbxRGbCDv7HXITWoDTSgzIADJOEfmqT8QcYeGlBuwJmDJBwxoYfBWYfwUCs3gBpQdoDBDLnAlkXIDAMNKD/g0h8yTdjyQTaigQbUEeAjZghyG5HUF1oz/M01oK6AM4MTtiwu7iERBx+oAXUGeAecsLa46BD/L4zTgPoDvAEWDiPCwwgHiwH+7xpwfQFKqav0AXlzhL6TK7MLAAAAAElFTkSuQmCC">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Outfit:wght@700&display=swap">
    <style>
        :root {
            --bg: #282828;
            --fg: #3c3c3c;
            --text: #e8e8e8;
            --muted: #9aa0a6;
            --trash-icon: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>');
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        html,
        body {
            height: 100%;
            overflow: hidden;
            /* clip, unlike hidden, can't be scrolled by scripts: a page's
               scrollIntoView() would otherwise shift the whole UI sideways. */
            overflow: clip;
            font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            user-select: none;
        }

        #app {
            display: flex;
            flex-direction: column;
            height: 100%;
            position: relative;
        }

        #tabbar {
            display: flex;
            align-items: flex-end;
            height: 40px;
            background: var(--bg);
            padding: 0 6px 0 40px;
            gap: 0;
            flex: 0 0 auto;
            overflow: hidden;
            max-height: 40px;
            transition: max-height 0.25s ease;
        }

        #app.chrome-hidden #tabbar {
            max-height: 0;
        }


        .icon-btn {
            background: transparent;
            border: none;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            transition: background 0.15s ease, transform 0.25s ease;
            flex: 0 0 auto;
        }

        .icon-btn:hover {
            background: rgba(255, 255, 255, 0.10);
        }

        .icon-btn img {
            pointer-events: none;
            -webkit-user-drag: none;
        }

        #collapse-btn {
            position: absolute;
            top: 5px;
            left: 6px;
            width: 30px;
            height: 30px;
            z-index: 100;
            transform: translateY(3px);
        }

        #collapse-btn img {
            width: 18px;
            height: 18px;
            transition: transform 0.25s ease;
            filter: invert(1);
        }

        #collapse-btn.collapsed img {
            transform: rotate(180deg);
        }

        #app.chrome-hidden #collapse-btn {
            background: rgba(40, 40, 40, 0.85);
        }

        #app.chrome-hidden #collapse-btn:hover {
            background: rgba(60, 60, 60, 0.95);
        }

        #tabs {
            display: flex;
            align-items: flex-end;
            flex: 0 1 auto;
            overflow-x: auto;
            overflow-y: hidden;
            scrollbar-width: none;
            padding: 0 8px;
            isolation: isolate;
        }

        #tabs::-webkit-scrollbar {
            display: none;
        }

        .tab {
            display: flex;
            align-items: center;
            gap: 8px;
            min-width: 100px;
            width: 232px;
            height: 32px;
            padding: 0 10px;
            background: var(--bg);
            color: var(--muted);
            cursor: default;
            position: relative;
            border-radius: 10px 10px 0 0;
            flex: 0 1 232px;
            font-size: 13px;
            transition: background 0.12s ease;
        }

        .tab:not(.active):hover {
            isolation: isolate;
        }

        .tab .favicon,
        .tab .tab-title,
        .tab .tab-close {
            transition: transform 0.2s ease;
        }

        .tab:not(.active) .favicon,
        .tab:not(.active) .tab-title,
        .tab:not(.active) .tab-close {
            transform: translateY(-3px);
        }

        .tab:not(.active):hover::before {
            content: '';
            position: absolute;
            left: 2px;
            right: 2px;
            top: 0;
            bottom: 6px;
            background: #474747;
            border-radius: 8px;
            pointer-events: none;
            z-index: -1;
        }

        .tab.dragging {
            z-index: 5;
            cursor: grabbing;
            box-shadow: 0 4px 14px rgba(0, 0, 0, 0.45);
            transition: none;
        }

        .tab.pinned {
            width: 36px;
            min-width: 36px;
            flex: 0 0 36px;
        }

        .tab.label-anim .tab-title {
            text-overflow: clip;
        }

        .tab.active {
            background: var(--fg);
            color: var(--text);
            z-index: 1;
        }

        .tab.active::before,
        .tab.active::after {
            content: '';
            position: absolute;
            bottom: 0;
            width: 8px;
            height: 8px;
            pointer-events: none;
        }

        .tab.active::before {
            left: -8px;
            background: radial-gradient(circle at top left, transparent 8px, var(--fg) 8px);
        }

        .tab.active::after {
            right: -8px;
            background: radial-gradient(circle at top right, transparent 8px, var(--fg) 8px);
        }

        .tab .favicon {
            width: 16px;
            height: 16px;
            flex: 0 0 16px;
            border-radius: 3px;
            object-fit: contain;
            -webkit-user-drag: none;
        }

        .tab.closing .favicon {
            flex: 0 1 16px;
            min-width: 0;
        }

        .tab .tab-title {
            flex: 1 1 auto;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .tab .tab-close {
            flex: 0 0 18px;
            width: 18px;
            height: 18px;
            line-height: 16px;
            text-align: center;
            border-radius: 50%;
            font-size: 16px;
            color: var(--muted);
            opacity: 1;
            transition: background 0.12s ease, transform 0.2s ease;
        }

        .tab .tab-audio {
            display: none;
            flex: 0 0 20px;
            width: 20px;
            height: 20px;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            color: var(--muted);
            transition: background 0.12s ease, transform 0.2s ease;
        }

        .tab.has-audio .tab-audio {
            display: flex;
        }

        .tab .tab-audio[data-sound="muted"] {
            color: #f28b82;
        }

        .tab .tab-audio:hover {
            background: rgba(255, 255, 255, 0.18);
            color: #fff;
        }

        .tab:not(.active) .tab-audio {
            transform: translateY(-3px);
        }

        .tab .tab-close:hover {
            background: rgba(255, 255, 255, 0.18);
            color: #fff;
        }

        .tab-sep {
            width: 1px;
            height: 18px;
            background: var(--fg);
            flex: 0 0 1px;
            align-self: center;
            margin: 0 2px;
        }

        .tab-sep.hidden {
            background: transparent;
        }

        #newtab-btn {
            width: 28px;
            height: 28px;
            margin: 0 4px 4px -4px;
            font-size: 20px;
            color: var(--text);
            line-height: 1;
        }

        #toolbar {
            background: var(--fg);
            flex: 0 0 auto;
            overflow: hidden;
            transition: height 0.25s ease;
        }

        #navbar {
            display: flex;
            align-items: center;
            gap: 4px;
            height: 48px;
            padding: 0 10px;
        }

        .nav-btn {
            width: 40px;
            height: 40px;
        }

        .nav-btn img {
            width: 22px;
            height: 22px;
            filter: invert(0);
            -webkit-user-drag: none;
        }

        .nav-btn.disabled {
            opacity: 0.3;
            pointer-events: none;
        }

        #btn-back img {
            transform: rotate(180deg);
        }

        #urlbar {
            flex: 1 1 auto;
            display: flex;
            align-items: center;
            height: 32px;
            background: var(--bg);
            border-radius: 16px;
            padding: 0 6px;
            margin: 0 6px;
            border: 1px solid transparent;
            transition: border-color 0.15s ease;
        }

        #urlbar:focus-within {
            border-color: rgba(120, 170, 255, 0.6);
        }

        #url-input {
            flex: 1 1 auto;
            background: transparent;
            border: none;
            outline: none;
            color: var(--text);
            font-size: 14px;
            user-select: text;
        }

        #url-input::placeholder {
            color: var(--muted);
        }

        #url-suggest {
            position: fixed;
            z-index: 50;
            background: var(--bg);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 14px;
            padding: 6px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            display: none;
        }

        #url-suggest.open {
            display: block;
        }

        #url-suggest .suggest-item {
            padding: 8px 12px;
            border-radius: 10px;
            font-size: 14px;
            color: var(--text);
            cursor: pointer;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        #url-suggest .suggest-item.active {
            background: rgba(255, 255, 255, 0.10);
        }

        #url-suggest .suggest-item.open-link {
            color: #cfe0ff;
            background: rgba(80, 130, 255, 0.18);
        }

        #url-suggest .suggest-item.open-link.active {
            background: rgba(80, 130, 255, 0.32);
        }

        #site-btn {
            flex: 0 0 auto;
            width: 24px;
            height: 24px;
            padding: 0;
            margin-left: -3px;
            margin-right: 6px;
            border-radius: 50%;
            background: #3c3c3c;
        }

        #site-btn:hover,
        #site-btn.active {
            background: #555554;
        }

        #site-btn img {
            width: 20px;
            height: 20px;
            -webkit-user-drag: none;
        }

        #site-panel {
            position: fixed;
            z-index: 50;
            min-width: 250px;
            background: var(--fg);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 12px;
            padding: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            color: var(--text);
            display: none;
        }

        #site-panel.open {
            display: block;
        }

        #site-panel .site-panel-head {
            font-size: 13px;
            font-weight: 600;
            word-break: break-all;
            margin-bottom: 10px;
        }

        #site-panel .site-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            font-size: 13px;
            padding: 4px 0;
        }

        #site-panel .site-status {
            color: var(--muted);
        }

        #site-panel .site-reset {
            margin-top: 12px;
            width: 100%;
            padding: 8px;
            border: none;
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.10);
            color: var(--text);
            font-size: 13px;
            cursor: pointer;
        }

        #site-panel .site-reset:hover:not(:disabled) {
            background: rgba(255, 255, 255, 0.18);
        }

        #site-panel .site-reset:disabled {
            opacity: 0.45;
            cursor: default;
        }

        #star-btn {
            width: 24px;
            height: 24px;
            flex: 0 0 24px;
        }

        #star-btn img {
            width: 18px;
            height: 18px;
            -webkit-user-drag: none;
        }

        #games-btn,
        #settings-btn {
            margin-left: 2px;
        }

        #games-btn img,
        #settings-btn img {
            width: 22px;
            height: 22px;
            filter: none;
            -webkit-user-drag: none;
        }

        #games-btn.active,
        #settings-btn.active {
            background: rgba(120, 170, 255, 0.18);
        }

        .sidebar {
            position: absolute;
            top: 0;
            right: 0;
            bottom: 0;
            width: 300px;
            max-width: 80%;
            background: var(--fg);
            border-left: 1px solid rgba(255, 255, 255, 0.1);
            border-top: 1px solid rgba(255, 255, 255, 0.06);
            box-shadow: -18px 0 16px -16px rgba(0, 0, 0, 0.45);
            z-index: 20;
            display: flex;
            flex-direction: column;
            transform: translateX(100%);
            visibility: hidden;
            transition: transform 0.22s ease, visibility 0s linear 0.22s;
        }

        .sidebar.open {
            transform: translateX(0);
            visibility: visible;
            transition: transform 0.22s ease;
        }

        .sidebar-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px 10px 14px 18px;
            font-size: 1rem;
            font-weight: 700;
            color: var(--text);
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            flex: 0 0 auto;
        }

        .sidebar-close {
            width: 30px;
            height: 30px;
            font-size: 20px;
            color: var(--text);
            line-height: 1;
        }

        .sidebar-body {
            display: flex;
            flex-direction: column;
            gap: 8px;
            padding: 12px;
            overflow-y: auto;
        }

        #games-sidebar-list .gs-link {
            padding: 12px 16px;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.08);
            color: var(--text);
            font-size: 0.92rem;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.15s ease, transform 0.15s ease;
        }

        #games-sidebar-list .gs-link:hover {
            background: #45a29e;
            color: #0b0c10;
            transform: translateX(-2px);
        }

        .settingspage {
            position: absolute;
            inset: 0;
            overflow-y: auto;
            background: linear-gradient(135deg, #0b0c10 0%, #1f2833 100%);
            color: var(--text);
            padding: 40px 20px 60px;
        }

        .settingspage .set-inner {
            width: 100%;
            max-width: 640px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .settingspage .set-title {
            font-size: 1.9rem;
            font-weight: 800;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }

        .set-group {
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 1.2px;
            text-transform: uppercase;
            color: var(--muted);
            margin: 18px 4px 2px;
        }

        .set-option {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 12px 14px;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.08);
            color: var(--text);
            cursor: pointer;
            transition: background 0.15s ease, border-color 0.15s ease;
        }

        .set-option:hover {
            background: rgba(255, 255, 255, 0.11);
        }

        .set-option.selected {
            border-color: #45a29e;
            background: rgba(69, 162, 158, 0.16);
        }

        .set-radio {
            flex: 0 0 14px;
            width: 14px;
            height: 14px;
            margin-top: 3px;
            border-radius: 50%;
            border: 2px solid var(--muted);
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }

        .set-option.selected .set-radio {
            border-color: #66fcf1;
            box-shadow: inset 0 0 0 3px #66fcf1;
        }

        .set-option .set-name {
            font-size: 0.92rem;
            font-weight: 600;
        }

        .set-option .set-desc {
            font-size: 0.76rem;
            line-height: 1.45;
            color: var(--muted);
            margin-top: 3px;
        }

        .set-status {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 0 6px;
            font-size: 0.76rem;
            color: var(--muted);
        }

        .set-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--muted);
            flex: 0 0 8px;
        }

        .set-dot.ready {
            background: #66fcf1;
        }

        .set-dot.failed {
            background: #e06c6c;
        }

        .set-note {
            padding: 0 6px;
            font-size: 0.72rem;
            line-height: 1.5;
            color: var(--muted);
        }

        .set-site {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 10px 10px 14px;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.08);
            color: var(--text);
            font-size: 0.88rem;
        }

        .set-site .set-site-name {
            flex: 1 1 auto;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .set-site .set-del {
            flex: 0 0 auto;
            width: 30px;
            height: 30px;
            display: grid;
            place-items: center;
            border-radius: 8px;
            border: none;
            background: transparent;
            padding: 0;
            cursor: pointer;
            transition: background 0.15s ease;
        }

        /* Masked so the glyph takes its colour from the button state. */
        .set-site .set-del::before {
            content: '';
            width: 17px;
            height: 17px;
            background: var(--muted);
            transition: background 0.15s ease;
            -webkit-mask: var(--trash-icon) center / contain no-repeat;
            mask: var(--trash-icon) center / contain no-repeat;
        }

        .set-site .set-del:hover {
            background: rgba(224, 108, 108, 0.18);
        }

        .set-site .set-del:hover::before {
            background: #ffb4b4;
        }

        .set-empty {
            padding: 14px;
            border-radius: 10px;
            border: 1px dashed rgba(255, 255, 255, 0.14);
            font-size: 0.82rem;
            color: var(--muted);
            text-align: center;
        }

        #bookmarksbar {
            display: flex;
            align-items: center;
            gap: 2px;
            height: 34px;
            padding: 0 8px;
            background: var(--fg);
            border-top: 1px solid rgba(255, 255, 255, 0.06);
            overflow-x: auto;
            overflow-y: hidden;
            scrollbar-width: none;
            white-space: nowrap;
        }

        #bookmarksbar::-webkit-scrollbar {
            display: none;
        }

        .bm {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            height: 26px;
            padding: 0 8px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            color: var(--text);
            max-width: 180px;
            flex: 0 0 auto;
            transition: background 0.12s ease;
        }

        .bm:hover {
            background: rgba(255, 255, 255, 0.10);
        }

        .bm img {
            width: 16px;
            height: 16px;
            flex: 0 0 16px;
            object-fit: contain;
            -webkit-user-drag: none;
        }

        .bm .bm-label {
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        #bookmarksbar.empty {
            display: none;
        }

        #content {
            flex: 1 1 auto;
            position: relative;
            background: var(--bg);
            overflow: hidden;
            overflow: clip;
        }

        .panel {
            position: absolute;
            inset: 0;
            display: none;
        }

        .panel.active {
            display: block;
        }

        .panel iframe.webframe {
            width: 100%;
            height: 100%;
            border: none;
            display: block;
            background: #fff;
        }

        .newtab {
            position: absolute;
            inset: 0;
            overflow-y: auto;
            background: #232428;
            color: #fff;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 40px 20px 100px;
            /* Search-bar height; everything on the page is sized from it so the
               layout scales with the window (32px on small screens, up to 64px). */
            --nt: clamp(32px, min(2.5vw, 4.6vh), 64px);
        }

        .newtab .nt-title {
            font-family: 'Outfit', 'Inter', system-ui, sans-serif;
            font-size: calc(var(--nt) * 1.06);
            font-weight: 700;
            letter-spacing: 0.5px;
            line-height: 1.1;
            margin-bottom: calc(var(--nt) * 0.55);
            text-align: center;
        }

        .newtab .nt-search {
            position: relative;
            width: 100%;
            max-width: calc(var(--nt) * 13);
        }

        .newtab .nt-input-group {
            display: flex;
            align-items: center;
            width: 100%;
            height: var(--nt);
            background: #373942;
            border: 1px solid #4a4c55;
            border-radius: 999px;
            transition: border-color 0.15s ease;
        }

        .newtab .nt-input-group:focus-within {
            border-color: #6b6e7a;
        }

        .newtab .nt-input {
            flex: 1 1 auto;
            min-width: 0;
            height: 100%;
            padding: 0 4px 0 calc(var(--nt) * 0.45);
            border: none;
            background: transparent;
            color: #fff;
            font: inherit;
            font-size: max(13px, calc(var(--nt) * 0.3));
            outline: none;
            user-select: text;
        }

        .newtab .nt-input::placeholder {
            color: rgba(255, 255, 255, 0.4);
        }

        .newtab .nt-go {
            flex: 0 0 auto;
            display: grid;
            place-items: center;
            width: var(--nt);
            height: calc(var(--nt) - 2px);
            margin-right: calc(var(--nt) * 0.06);
            border: none;
            border-radius: 999px;
            background: transparent;
            color: #e8e8e8;
            cursor: pointer;
        }

        .newtab .nt-go:hover {
            color: #fff;
        }

        .newtab .nt-go svg {
            width: calc(var(--nt) * 0.48);
            height: calc(var(--nt) * 0.48);
        }

        .newtab .nt-suggest {
            position: absolute;
            top: calc(100% + var(--nt) * 0.15);
            left: 0;
            right: 0;
            background: #2e3036;
            border: 1px solid #4a4c55;
            border-radius: calc(var(--nt) * 0.4);
            box-shadow: 0 8px 28px rgba(0, 0, 0, 0.35);
            padding: 6px;
            z-index: 5;
            display: none;
        }

        .newtab .nt-suggest.open {
            display: block;
        }

        .newtab .nt-suggest .suggest-item {
            padding: calc(var(--nt) * 0.16) calc(var(--nt) * 0.3);
            border-radius: calc(var(--nt) * 0.25);
            color: #e8e8e8;
            font-size: max(12px, calc(var(--nt) * 0.27));
            cursor: pointer;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .newtab .nt-suggest .suggest-item.active {
            background: #3d4049;
            color: #fff;
        }

        .newtab .nt-github {
            position: absolute;
            right: calc(var(--nt) * 0.3);
            bottom: calc(var(--nt) * 0.2);
            color: #fff;
            font-size: max(12px, calc(var(--nt) * 0.22));
            text-decoration: none;
        }

        .newtab .nt-github:hover {
            text-decoration: underline;
        }

        #ctx-menu {
            position: fixed;
            min-width: 200px;
            background: #2b2b2b;
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 8px;
            padding: 6px 0;
            box-shadow: 0 8px 28px rgba(0, 0, 0, 0.5);
            z-index: 10000;
            display: none;
            font-size: 13px;
        }

        #ctx-menu .ctx-item {
            padding: 8px 16px;
            cursor: pointer;
            color: var(--text);
            white-space: nowrap;
        }

        #ctx-menu .ctx-item:hover {
            background: rgba(255, 255, 255, 0.10);
        }

        #ctx-menu .ctx-item.disabled {
            color: var(--muted);
            pointer-events: none;
        }

        #ctx-menu .ctx-sep {
            height: 1px;
            background: rgba(255, 255, 255, 0.12);
            margin: 6px 0;
        }

        .bm-dropdown {
            position: fixed;
            min-width: 200px;
            background: #2b2b2b;
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 8px;
            padding: 6px 0;
            box-shadow: 0 8px 28px rgba(0, 0, 0, 0.5);
            z-index: 9000;
            font-size: 13px;
        }

        .bm-dropdown .dd-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 7px 14px;
            cursor: pointer;
            color: var(--text);
            max-width: 280px;
        }

        .bm-dropdown .dd-item:hover {
            background: rgba(255, 255, 255, 0.10);
        }

        .bm-dropdown .dd-item img {
            width: 16px;
            height: 16px;
            flex: 0 0 16px;
            object-fit: contain;
        }

        .bm-dropdown .dd-item .dd-label {
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .bm-dropdown .dd-empty {
            padding: 7px 14px;
            color: var(--muted);
        }

        #modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.5);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 11000;
        }

        #modal-overlay.show {
            display: flex;
        }

        .modal {
            background: #2b2b2b;
            border-radius: 12px;
            padding: 22px;
            width: 380px;
            max-width: 90vw;
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.6);
        }

        .modal h3 {
            margin-bottom: 16px;
            font-size: 16px;
            font-weight: 600;
        }

        .modal label {
            display: block;
            font-size: 12px;
            color: var(--muted);
            margin: 10px 0 4px;
        }

        .modal input {
            width: 100%;
            padding: 9px 12px;
            background: var(--bg);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 6px;
            color: var(--text);
            font-size: 14px;
            outline: none;
            user-select: text;
        }

        .modal input:focus {
            border-color: rgba(120, 170, 255, 0.6);
        }

        .modal .modal-msg {
            font-size: 14px;
            line-height: 1.5;
            color: var(--text);
            word-break: break-all;
            white-space: pre-line;
        }

        .modal-actions {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 20px;
        }

        .modal-actions button {
            padding: 8px 18px;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
        }

        .btn-cancel {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text);
        }

        .btn-cancel:hover {
            background: rgba(255, 255, 255, 0.18);
        }

        .btn-ok {
            background: #4a90d9;
            color: #fff;
        }

        .btn-ok:hover {
            background: #5a9fe8;
        }
    </style>
</head>

<body>
    <div id="app">
        <button id="collapse-btn" class="icon-btn" title="Hide toolbar"></button>

        <div id="tabbar">
            <div id="tabs"></div>
            <button id="newtab-btn" class="icon-btn" title="New tab">+</button>
        </div>

        <div id="toolbar">
            <div id="navbar">
                <button id="btn-back" class="icon-btn nav-btn" title="Back"></button>
                <button id="btn-forward" class="icon-btn nav-btn" title="Forward"></button>
                <button id="btn-reload" class="icon-btn nav-btn" title="Reload"></button>
                <div id="urlbar">
                    <button id="site-btn" class="icon-btn" title="Site settings"></button>
                    <input id="url-input" type="text" spellcheck="false" autocomplete="off"
                        placeholder="Search DuckDuckGo or enter a URL">
                    <button id="star-btn" class="icon-btn" title="Bookmark this page"></button>
                </div>
                <button id="games-btn" class="icon-btn nav-btn" title="Games"></button>
                <button id="settings-btn" class="icon-btn nav-btn" title="Settings"></button>
            </div>
            <div id="bookmarksbar"></div>
        </div>

        <div id="content">
            <aside id="games-sidebar" class="sidebar">
                <div class="sidebar-head">
                    <span>Games</span>
                    <button id="games-sidebar-close" class="icon-btn sidebar-close" title="Close">×</button>
                </div>
                <div id="games-sidebar-list" class="sidebar-body"></div>
            </aside>
        </div>

        <div id="url-suggest"></div>
        <div id="site-panel"></div>
    </div>

    <div id="ctx-menu"></div>

    <div id="modal-overlay">
        <div class="modal" id="modal-box"></div>
    </div>

    <script type="module">
        // Filled in by index.js: the proxy's origin, or just its port on this host.
        const PROXY_CONFIG = __PROXY_CONFIG__;
        const PROXY_ORIGIN = PROXY_CONFIG.origin || \`\${location.protocol}//\${location.hostname}:\${PROXY_CONFIG.port}\`;
        const PX_PREFIX = '/__px/';

        const NO_ICON = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4HsAAAACVBMVEWVmqCRl5yYnqR1edwxAAAAA3RSTlMHiviNM9i0AAAA9ElEQVR42u2XMQ4DIQwEPfz/0alC47PHREJpbssTO7KBW5l41QjWFhy7VxKndkGY3RFud4T7zwl5fSaO/VTYkZ+uLffT97XM7/va7j/hAOZ+GJ6mtK9NIH4tYYPFbzudPk5L8AaypAAHYAXEmpcgN1ABCEB7oD9aB1SXa8t60KD4PwABeN4+J61UCEUJhAG2KAJzKWArnWpECECS5xiwJgDGwVFcfbwEiZ/fADEEEKEBigE0QBXgCe6A8wDtV/oPy1ePC9HMoE8GzwxkiFAC4s9ygA1JAsDHtA7Aqv1OwBLiaNS9Omw7gYsPDkdw89Hlz75XtT46qA3Em0wn6wAAAABJRU5ErkJggg==';
        const NEWTAB_ICON = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAMAAAD04JH5AAAAZlBMVEUAAAC/v7/Hv7/Hv7fFv7/Fv7rDv7/Dv7vCv7zBv7zFv73Ev73Ev7vDv73Dv7vDv73Dv7vCv73Cv7vDv73Dv7zEv7zEv7zDv7zDv7zDv7zDv7vEv73Ev7zCv73Cv7zDv73Dv7zDv7xno0nKAAAAIXRSTlMAECAgMDBAQFBfYHBwf3+AgI+PkJCfoK+/z8/f39/f7+84OiXtAAAB70lEQVR42u3azU7jMBRA4cTpJGmZGf4cMNCS3Pd/SU4XlixD7BRY2NX9VhWkyllcNbbbRimlLtHD4hULRIAFDhY9NOD6Ag54h2x0xB4aUH9ABwf5piM6aECdAXsskB9aMEID6goYIb9sDw2oJ+Ad8ssWdNCAOgJuICtm3GGEuVALDagj4MxBIhYtmh/QgLIDJvjXAyTwF02gxQ49vorqEzSgzAB/w/CCZwhuEd74HgskMCF82FjIih4aUF7AIwRH+KEyeEG4WU0tVvx7fegMQcxCA8oLcBDEQ7eDf/0EyXiAv/4OgtgLNKC8gHBgFrSIHz6SEb93xNo1GlBegEQmfHpYbeQH10BWaED5AfHC4Q9kox4aUF/ADIk4NIgWGFktUoO7QAPKC3hF7pDZQjIm5BYwDhpQXsAjtmw2TpAVbzDIHXpbaEB5AQO2bDYM4uGaER9i/oes6KEBZQV4qQG7QbxRGbCDv7HXITWoDTSgzIADJOEfmqT8QcYeGlBuwJmDJBwxoYfBWYfwUCs3gBpQdoDBDLnAlkXIDAMNKD/g0h8yTdjyQTaigQbUEeAjZghyG5HUF1oz/M01oK6AM4MTtiwu7iERBx+oAXUGeAecsLa46BD/L4zTgPoDvAEWDiPCwwgHiwH+7xpwfQFKqav0AXlzhL6TK7MLAAAAAElFTkSuQmCC';
        const FOLDER_ICON = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAABAklEQVR4AexUyQ3CQAyc5UUJFARF8IIHh5QOoADoIBLHI7woAgqiBF4sniUJWRPIIUACZRVnY8easSfxtvDh1RAUCvxdiXbrsBttwok2xgtLfZKQdhBtw4VtmQOMWWljvC5JSgCYPoATrJ16BruUOEjCInR32teFZAjQJtBwHKw9GwVzc7E9vgPMTHen/aQQxCtLEIcet8EkODoS3V2eTxVuajigUgTMJInXme409pkr5tSQHaUJmFzHGoJC1f5LojP71ZNZ1SeGmMOSPfub2r0EOnoyK/tAB3BYAoc7wTA5EvKms0KME08shy437yOXndZXE00MwU0vjyCNvvHh9wmuAAAA//96iR2uAAAABklEQVQDAMGKAUD79gyKAAAAAElFTkSuQmCC';
        const STAR_OFF = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAMAAADXqc3KAAAAD1BMVEVdZGlfY2hfY2hfY2hfY2iYMCtaAAAABXRSTlMGNoPD+sanbjoAAAB7SURBVHjanZA5DgNBDMNkkf9/c4Ake8xiiiCsDAsspPxCmy2jsxd0r6juhXarYLJRppJgJwcF30wyvoEmQQXaTxVAJUmQLCDnMTkZ5FZtbv2bLMnmn3AFPNt9eQRyzI7r4s2gTOqsA6Ktsg6JyiSDSi7UHq7mgpte8h8vMyUB8jQkgkoAAAAASUVORK5CYII=';
        const STAR_ON = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAMAAADXqc3KAAAAD1BMVEUZcesac+gac+kac+gac+jfewgqAAAABXRSTlMDOX29+cHLqgQAAABbSURBVHjarc1JDgIxDETRGv79z8yCoUlwJCR4iyhWqWz9xNas1Qw0CuRQmCsGsDa2C1D7ysKHHJIcOlkOXyyNibUoD9WKF+mrVQHI/d2DWnL3oM852/W8f//tBqD4AlV8pJ2+AAAAAElFTkSuQmCC';
        const ICON_FWD = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAkElEQVR4AeyQUQrAIAxDt93/zpsPVigd1kbwawrBCmme5DoWnw0YFvyziu73DHtxhqmK4LiMdJQAZzuWVoVIAMIb4+RGFYgMIFiBdAH8LhMgEz6b490FROPsuwughkweiM+//dwFeFOcfSVZOHsyQAmXAWq4DGABjWrBY5IqIhjZcuWWAJXA6NmA2MjnvbyiBwAA//+OcqznAAAABklEQVQDAKZPSDHM2iJ9AAAAAElFTkSuQmCC';
        const ICON_RELOAD = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAA6ElEQVR4AezTUQqDQAwE0LYXELyB9z+UNxA8QctbjMjiZv3xqxamyWaSmZDSz+vmz2PQPfCfnGie5++yLDu8wX1EnPwM3RMZHoZhn13X9eUNxHeikaQGIUB0HMc3TNNUohoTaGiXctOAuGFCREv39oXb0m5oGhA3XYur4UDeQ9PAoO3FGk5Vo+6Jd2pwZUvnghCsY2pQN5+9e0s0DeI82XYZF8s0DeLHteGZkBrOItEbosfYNNDkhyRAyB+OqAhqejJxfGqggQATeYjK1Swgz9A1MMyE2BFquB4uGfREMv4xyK5TuNtP9AMAAP//Bkw8dgAAAAZJREFUAwDUanox3hqaEAAAAABJRU5ErkJggg==';
        const ICON_COLLAPSE = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAABCUlEQVR4AexRSw6CMBCdoh5BTyEoJrpzod7ZnRcQMUAMegONFzARQ53XAKmkgIkaN5BOO515n2aw6Mdfa9A44HZE3xuR67r90XiyRSBvVM4Ab/0DCKZkbUiIKQI5aplG7dFoACEIsopNgg4qiGzU0ON67ao1gACEWMGmlE7ykawQyFFDDxjOK1elgeM4AwgwU4nfu7SMouiKSBJroZsAyzjjMhqAILq9DTMK8aPvn/muVhx7F90EWHBUs7QZDUSntyZJQ7wSL9fFc/6LCWMVJ29qp9GApLiRlF6VeM4vTBirOHlDO40GYbCbh8F+Znq5xlUpTIAFRxVKm9GghPno2ho0jq8d0f9H9AQAAP//N0iYjwAAAAZJREFUAwAnwXoxn+SR2AAAAABJRU5ErkJggg==';
        const GAMES_ICON = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAMwAAADACAYAAABI4IyJAAAL7ElEQVR4AeycC5LkNg5Eq33/O7cnp60YmUOJxIckQGaHMdWiQHwekOXdsHf/+fCHBEigmwAF042KjiTw+VAw3AISEBCgYASw6EoCFAx3gAQEBG6CEdyiKwkcSoCCOXTwbFtHgILRceOtQwlQMIcOnm3rCFAwOm68dSiBumAOhcG2SaBFgIJpEeJ7ErgRoGBuMPgrCbQIUDAtQnxPAjcCFMwNBn8lgRaBpmBaAfieBE4iQMGcNG32aiZAwZgRMsBJBCiYk6bNXs0EKBgzQgY4iYBEMCdxYa8kUCVAwVSx8JAE6gQomDoXnpJAlQAFU8XCQxKoE6Bg6lx4SgJVAkrBVGPxkAS2J0DBbD9iNuhJgILxpMlY2xOgYLYfMRv0JEDBeNJkrO0J2AUTDNE3f0IRCLYe5nJSC6a2GWYiDOBKYLcZpRPMfQCuk2WwaQQyzzCNYC7I06bKRFMIZJtreMFkAzplyzZMkmXOroLxnGMWgJ49M9bnE33u4QQTHRiXeg6BqHsQRjBRAc1ZD2Z5IhBtL0IIBlCegPGcBEAgyo4sFQwgwACERgItAtgVWMtv5PtRgnmtGU3DXp34kgQeCGB3YA+vhx5PF8yqRodSZPAlBFbs0lTBjG7wiz8hCYxU0+idKmufJphRjd03pGyOzzEIjJ7RqN2q0ZsiGO+GRg+gBopnPgSyz264YL6/v799UH8+F+wPf7Yg4DlP7y/lJ8DDBfOUWHoOuNI79M9BwGu2M0QzVDAeDQAmLMfoWaWWAGYM096/7nns3BWr9jlMMB6FewCsNc2zuAQ8Zu6xe0+EhgjGo2APcE9N8zw2AY/Ze+xgjZK7YF4LrVVQnAEWrDjm42EEsAMwS9vWXazldhWMtUAroFqDPMtNwLoT1p0s6bkKpgwuebaCkeSiby4CkXbDTTAWJUcCkmuVzqnWsiOW3SwJuwmmDNz7bAHRm4N+exCIsCsugtEoGCOMAAB10PIQ0O6MdkdLMi6CKYP2PGsb74lNn70JrNwds2C8lLv3iNndLgTMgtGAWPkNoamXd/783x/hCxK2molmhzzqXiKY1bCZv58AlgxW3sAZrDzf/dkkGA2wyjfDNMaot7RpyRMmAqtW2T0+rRja95pdstZrEoy0UU2D0hxP/k+gns6f4vD8bwIrGc7eKbVgVkL6e2TvJ61aW+/fo/NtNgKWeasFI4U0+5tAWp8FojQX/X0JzNytaYLxRdQfjULoZ0XPNgGVYKRL2P8N0C54pIe0r5G1MLaMgHTHtLNWCUbWCr1JYB8CFMw+s3TvpPdbu9fPvcAFAYcL5iSYC+a3PGWk+c6oRSwY7X/2Wz5ZFqAigCWElZdxBivPMz1rdlksmGlAmCgUAYjjbqGKm1gMBTMRNlPlJzBUMPhGyo+IHWQiMHrnhgomE2jWSgI9BFIKBv9lrdd6INx9RsW951jxe62vWXXUcuNsVn7PPCkEc284CugoddzZ1H5HnbCnd7Vzz7On3Mjx9g7vI5pIMKsbXJ2/HGC0ejT1jeyhJ3aPT9mX57M0v0gwnoUyVhwC0qWJU/n8StIIhkOdvxyWjJJ5SXwtNXncTSMYj2ZHxMg07BH9nxYzm2BOmw/7DUYgjWBG/wMp7Vyi1qXtx+uehIvE16s+bZw0gtE2yHttApkWtt3NWI9Ugok22Gj1lKuyur6e/D0+ZV8rn1MJBqCiAI5SB5i8GeqE1XxwDqu98zp7i//2ziu/d5x0ggEAgP766vsT/hLri/r1JYkZwfer8jOrrkrq30ez8nvmSSkYTwCMRQISAhSMhBZ9jydAwRy/AgQgIUDBSGjR93gCewjm+DGOA4B/9efNxmWOGZmCiTmXEFVBKK1CenxaMTK9p2AyTYu1LidAwSwfQf4CTvq7DAVz21f807TbI38lgb8IbCeYvzrkAQk4EtheML1/1+j1c2TPUAkJbC8YzKQlhtZ7xKCRAAgcIRg0+iSKp3PcofUROInhMYLB6DHY0nBOqxMAq/qbc093Fsy5U3Xs/E00eAdzTBc+FAUTfkTrC4Qoara+svkVUDDzmTNjYgIUTOLhsfT5BCiY+cyZMTGBQwSTeEIsPRQBCmbhOPAvLUptYblM/YsABfMLwqy/SnFo8pYx8KyJwzs6AhSMjlv3LSz0Zd2XhI5XfHwKr9JdSICCEQLrccfiXtbj7+lz5cWnZ1zG+iFwnmB++h7yJ5YUNiS4IihqgSmu8soDAQrmAYzkGEsJk9yZ6YvaYDNz7pqLgjFMFksIM4SYehW1wqYm3SwZBaMcaObFy1y7clxu1ygYBcodFm6HHhSjM185WjAaejst2k69aGapuUPBCKjtuGA79iQYqdiVgulENmuxyv/dSWd5JrdZvZmKDHKZgukYxIiFKoVxPZflXOflZ+lnfR7Ro7WmiPcpmMZUPBfpvvSNtM3XnrGuZJ69XjF3+6RgfiZa/dNrga7lriZxOPSM79WzQ1shQ1AwlbFgaWCVV+IjLLP4kvKCVy70DlOWsfU1CqYYr9eiYHlhRfjhj8gJ80jkxcKjligxKBjnSWBZYc5hxeFQA0x8kRdeCVAwNzzWb9SIC2qtycrkhneLXymY/8b4ZzH+OxB+WBdTmE7kbq3NykZUbHBnCubXgKwLYV3IXyUM/8tao5XR8AYnJTheMNZFsC7ipDn/TmOt1crqdxHJ/zhaMNYFsC7git2x1mxltqJnz5zHCsY6eOvieQ5RGstau5WdtN5I/kcKpnvgkSYVrJZTGR4nGI9BW7+hI+y+Rw8eLCOwkNRwlGCsA8aSwSSAI/uiF5ilRitTS+4Vd48RjHWw1sVaMdzenNberGx764zgd4RgrAO1LlSEQbdqsPZoZdyqL8r77QVjHeS1SFEGNrIOa69W1iN784q9tWCsA7QukNeQZsax9mxlPrNXTa6tBaMBct2xLs4VJ+Pnyb235rWtYHb/pmsNduX7ndmLBJPhmwfDglkWJkOflv567loZYAawnlwrfaR9igSzsrGe3B4D6gDYU8oWPh4sPGYSCeZQwcyE5ZHLY0EiDdejFg8mHrPp7WV0rqGC6W3S6ucByWMxrH1Eve/BxmNGEfgMF8xoUB7xPRYiwjBH1uDByGNWbz2Ojo/cYsF4gEPiKLZbPyO5RmalEYumH7FgNAPRNNOTxxpXA+z/dZ33ZGVmndlq4lMEgya9QVnjWQePnk41Kzvr7ErumnjaHlSC0SbTNFbCwbM1jrZ+5Kb9ELAytM7wp4rPxyvOFa/1qRJMK+jbezQIe/N5eod7sKf3PefWQffkOMXHyhKzhGl44R5Mc9dSt1owlqRoUtIsfGG4ZzFrzZbcu971YIrZwnoZSXx7Y/b6qQWDBFZYaLzHkMtq1lqb+Q928GLbswvwsaC21moSjKXwmXetkGbWmjXXKYzNgokOKnp9WQVSqzs6a4/6zIIBOI9CEMfbotbl3WekeFGZe9XlIhgMzKsgxPKwaPV49JQlRjT2nvW4CQbD9CwM8bS2ug5t3TvdizID7zpcBYOBexeImBJbnV9S6+6+q2cxIr+7YLAEIwpF3Jatytuq6+T3q2YyKu8QwWBBUDAMv4825IGNzsP4OgKYDUx3W3YLeWCyW/3ewwRzlYDiYdez5yfiwjxjMtY4ApgVbEQGxIWNiH2POVwwVzI0A7ueLZ+IA7PEmHSXaSoEMDtY5ZX4CHFg4ovKC9MEc9WH5i67zno+rzv47PGnT3wCmOVlkmqvO/iU3PPwnS6Ye9FouNfu9/j7fgR69wB+K7tfKpiVjTM3CWgIUDAaarxzLAEKZtromWgHAhTMDlNkD9MIUDDTUDPRDgQomB2myB6mEaBgpqFmoh0IUDArpsicaQlQMGlHx8JXEKBgVlBnzrQEKJi0o2PhKwhQMCuoM2daAhTM4tExfS4CFEyuebHaxQQomMUDYPpcBCiYXPNitYsJUDCLB8D0uQhQMHHmxUoSEKBgEgyJJcYhQMHEmQUrSUCAgkkwJJYYhwAFE2cWrCQBAQom5JBYVFQCFEzUybCukAQomJBjYVFRCVAwUSfDukISoGBCjoVFRSVAwUSdzFUXP0MRoGBCjYPFRCfwLwAAAP//ciaOTAAAAAZJREFUAwD9eKHbPpEaCAAAAABJRU5ErkJggg==';
        const SITE_ICON = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAmQAAAJkAQMAAACF36//AAAABlBMVEUAAADi4uTELgoOAAAAAXRSTlMAQObYZgAABoRJREFUeNrsl0GOqzAQRLG88JIjcBQfzRyNo3AEpL9hgai/QeqANe6xu8eZifotE/wS4+oiGQzDMAzDMAzDMAzDMAzDMAzDMAzDMAyjQFoGAQ7DKx6bxBawDi+MOCW2iH14YQJmgQ047nLJVgPuW0tkb2ACcP+qkq2m+2oHAGurzAPAcrMJtjqSjexozsdjZwFtW6WNYXva9tZ8kI12DrTnA9gzW9vk47I99Nga8/FIRKRX6qB9nZntbL9twG00mo8hZmtx0TKq+VpcLBo2J7DR2uyVtd1Ga73Alq8NuNgEtk1uo7U0WqOqbdKwHZltb7fRWMbfZwMNvaYNGqeAWc9Gg+pUbV7HtqratlxfjVe2PeI16tgOGlNp99JoJcifCxRfyG202inY6FCDgo2OIYpsA4h/uDHLbPhsW+pkGz7MFvvYTrOVmPrYjk+zjX1s+6fZgtnM1tP2F6de13bq2lS7F++3xU6/3xZV26r6u3cT/PtQGVQPKA5DABTjO+JrZHGTBy4BioFDgVXVtkkCIg9cQIFDMyA4VW2QdKU8cBFgAxcgDy8Fjo+xXyhuTOBGPnjxpHZjAgc+eMBK4S0GbmKCd1kovKWIOC54l2Vn4wasV4T40GLmAgIc7jvBm667AhaycaFdAr7JwtgIuS2hjrWjDZVs/Wzuvba9n82jkqOfLbzXdrbY6B3Wxj+T568fsPW2vRCe+if8zLxXZTsoPWIbtU6qtcXSgrG2fGMpoL7WloqlU1u+qfjpUcFWSCNTl+W5DgJb3oeuzuaYG5Oqytcx8YxiW6EUmLr0TIEFgS2/2lXZAndmVeUbuKwnoW3hWqGqyAsXsDZuI6HGNnFH5gW2POpOYsuHWmLLyzAJbHntR5Ftzq6Q2IYftY0VkzWx14YK28j2jf/f3hnkOA4CUdSIBUuOwEVG8tHw0XwUH8FLL6L0bDJCcjR+/J5SSHrqLyN4ElRhA1XlYIumjM/pYEqbLlrgrOxI2wXahruBTXgvrLiLWoU34HJB490g08qFu9GsgNnhLDMzTTifZhxHEs71CceRhNuVgLSoXGBWWjZBuaqdkaZcSmdsrFyYJ422KNGYjWZ2AlWFdpNujVdocBAtK7SNaEmhLUQLZLIiXeXXftpdu7yHiT2YlvtpO9NSP21lWoB5SVoEpJ8mxFCMaOV6GUZwEJGmxciyKS310o4u2nXzoNGiKS300vYBNGiu0aYxtO2/oQ2wAg2lOs1pTnOa05wGtJe9s+ob0z7iXQ+0A0ncPHwE7Sbsos1pN6yvZEU+Zz30eloCmnauz3AS11JpSzdts6BJ7jvT7YrkcJVoTYrzMo3NEPHGTDFDRppihoI3jYoZKtOa2AhIE8wQ+fZYMENmmmCGwrfughlmpglmEKIVbIYo0NgMWYjysBkK0ZKSQ185OiaYQYjcsRmiQGMzJCHiyZu4IsR22aizTLuBSYUoNriIEGFnWhCi/+xwEWlBo3HWBDiRkq+RFBqOIys0bFsEWralcQaRQuPsJpXGmVc6jbPCmIYZa7bZdMMz/TgLcXyGpH325gEOMijrlTNy9fzeFbKFX5PJzFnWozLA9ez08ZnznNVvX3GgV0MUoImVGgOqSMwqXOyrb+wrg+yrluwrqqJM+9S6tneuB5zG0nbT+tP9Y2tj5SpgE9p9mjtopXv2Y3tYAu2IOMJH057LvAWt8fBNqmF/OHjueBDlrvr6L3yYPCgYIAsP/w49yzPhneqfme1aUL84HrB1f4GBlb963Hi1/XLF0K9qJHA3TRHcTVMAmihwXlEV3E3TbEor4G52Djf6i0YRHGTIl6DY4fbhX9CaTWkFnpVWDrcMo7H7TsNp8RNp9+/QgtOcNpDW9NNo8UW05YfR0otoq9MulF9E25z2rd3g/qNpd6AJe/KVMiP16kwLWus9G9H2No9I45PRCrm1Gm2BvF+NxhnOOm2yod0NaM+dG96CNpvQDkNaW+TFlJaB1rcZ3Axp7fWZ3o7WNljRxAqN/3a01hfWqUirOu2ibzV4kre+s0676FsM3s57oxnskRot67SLvsng9LG2XwzOp+vFf5gKehpXRJOyUdsPoeF1padZaitNV3jqDCsBhnqe89qsoiufaXMbua54Hlg50TXVJ1pbGrrKybsy+AcPdbv4Z2tRJxNG3T8u/vI7gH/wcjiZZfoXnRyiwEBB8za5XC6Xy+VyuVwul8vlcrlcLpfL5XK5XC6Xy/V3/QYJyJa4mNbwPQAAAABJRU5ErkJggg==';

        // Internal page, shown in the URL bar and accepted as a typed address.
        const SETTINGS_URL = 'knoiren://settings';
        const SETTINGS_RE = /^knoiren:\\/\\/settings\\/?$/i;

        const SETTINGS_ICON = 'data:image/svg+xml,' + encodeURIComponent(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#e8e8e8" ' +
            'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' +
            '<circle cx="12" cy="12" r="3.1"/>' +
            '<path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 ' +
            '1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 ' +
            '1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 ' +
            '4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 ' +
            '0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 ' +
            '2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>' +
            '</svg>'
        );

        const GAMES = [
            ['3kh0 (Echo) Games', 'https://lite.3kh0.net/'],
            ['RETRO GAMES', 'https://theooofficial.github.io/myRETROGAMES/'],
            ['Bin Bash Games', 'https://bidoofery.github.io/gfiles/list.html'],
            ['Native Games', 'https://bidoofery.github.io/nativegames/'],
            ['GAMEBOY Advance Games', 'https://bidoofery.github.io/gam3b0y/'],
            ['GBA Online Games', 'https://gba.js.org/'],
            ['OutRed Games', 'https://outred.org/games.html'],
            ['GBA Emulator Games', 'https://theclashman2.github.io/GBA-Emulator/'],
            ['Unblocked Games World', 'https://sites.google.com/site/thegamecompilation/home?authuser=0'],
            ['Now.gg Games', 'https://now.gg/'],
            ['Dancing Bunny Games', 'https://ltorl.github.io/dancing-bunny/v2.html'],
        ];

        function esc(s) {
            return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
        }

        function strHash(s) {
            let h = 2166136261;
            for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
            return h >>> 0;
        }

        const BRANDS = {
            'duckduckgo.com': ['#de5833', 'D'],
            'wikipedia.org': ['#eaecf0', 'W', '#202122'],
            'github.com': ['#24292f', 'G'],
            'reddit.com': ['#ff4500', 'r'],
            'youtube.com': ['#ff0000', '▶'],
            'example.com': ['#38488f', 'E'],
            'news.ycombinator.com': ['#ff6600', 'Y'],
        };

        function brandFor(host) {
            host = (host || '').replace(/^www\\./, '');
            for (const k in BRANDS) {
                if (host === k || host.endsWith('.' + k)) return BRANDS[k];
            }
            const hue = strHash(host) % 360;
            return [\`hsl(\${hue} 62% 46%)\`, (host.split('.')[0][0] || '?').toUpperCase()];
        }

        // Letter icon for default bookmarks, so they render before any site is visited.
        function letterIcon(host) {
            const [bg, letter, fg] = brandFor(host);
            return 'data:image/svg+xml,' + encodeURIComponent(
                \`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="\${bg}"/>\` +
                \`<text x="16" y="22.5" font-family="Arial,Helvetica,sans-serif" font-weight="700" font-size="18" text-anchor="middle" fill="\${fg || '#fff'}">\${esc(letter)}</text></svg>\`
            );
        }

        // ---- Frames -------------------------------------------------------------
        // Each tab is an iframe on the proxy's origin. Being cross-origin, it talks
        // to us only through the runtime's messages: { __px: 'nav', url, title, icon }
        // on every navigation and { __px: 'open', url, user } for new windows.

        function createFrame() {
            const frame = document.createElement('iframe');
            frame.setAttribute('allow', 'fullscreen; autoplay; clipboard-read; clipboard-write; encrypted-media; picture-in-picture; gamepad');
            const listeners = { urlchange: [], open: [] };
            return {
                frame,
                addEventListener(type, fn) {
                    (listeners[type] = listeners[type] || []).push(fn);
                },
                emit(type, ev) {
                    (listeners[type] || []).forEach(fn => { try { fn(ev); } catch (e) { console.error(e); } });
                },
                go(url) { frame.src = engine.encodeUrl(url); },
            };
        }

        window.addEventListener('message', (e) => {
            if (e.origin !== PROXY_ORIGIN || !e.data || typeof e.data.__px !== 'string') return;
            // A page talking to us is proof the proxy works, whatever the probe said.
            if (!engineReady) markProxyReady();
            const tab = tabs.find(t => t.sframe && t.sframe.frame.contentWindow === e.source);
            if (!tab) return;
            const d = e.data;
            if (d.__px === 'nav') {
                // Tell the page we handle its new windows as tabs.
                e.source.postMessage({ __px: 'host' }, PROXY_ORIGIN);
                // A new document starts unmuted, so a muted tab says it again.
                if (tab.muted) e.source.postMessage({ __px: 'mute', muted: true }, PROXY_ORIGIN);
                setTabAudible(tab, !!d.audible);
                tab.sframe.emit('urlchange', { url: String(d.url || ''), title: String(d.title || ''), icon: String(d.icon || '') });
            } else if (d.__px === 'hello') {
                if (tab.muted) e.source.postMessage({ __px: 'mute', muted: true }, PROXY_ORIGIN);
            } else if (d.__px === 'audio') {
                setTabAudible(tab, !!d.audible);
            } else if (d.__px === 'open') {
                tab.sframe.emit('open', { url: String(d.url || ''), user: !!d.user });
            }
        });


        // Peekaboom, the proxy in index.js, runs on its own port so proxied sites
        // never share an origin with this page.
        const engine = {
            prefix: PROXY_ORIGIN + PX_PREFIX,
            encodeUrl: (u) => PROXY_ORIGIN + PX_PREFIX + u,
            decodeUrl: (u) => u.slice(u.indexOf(PX_PREFIX) + PX_PREFIX.length),
            createFrame,
        };
        let engineReady = false;
        let engineFailed = false;

        // Only checks that the proxy answers; tabs load either way. Runs at startup
        // and again whenever settings is shown while the proxy isn't known to work.
        async function initProxy() {
            try {
                await fetch(PROXY_ORIGIN + '/', { mode: 'no-cors', cache: 'no-store' });
                markProxyReady();
                return;
            } catch (err) {
                if (engineReady) return;
                engineFailed = true;
                console.error('Proxy unreachable at ' + PROXY_ORIGIN, err);
            }
            renderAllSettings();
        }
        function markProxyReady() {
            engineReady = true;
            engineFailed = false;
            renderAllSettings();
        }

        // Closing or reloading the whole page throws away every tab, so the browser
        // is asked to confirm first.
        window.addEventListener('beforeunload', (e) => {
            e.preventDefault();
            // Older browsers need one of these; the text itself is always ignored.
            e.returnValue = '';
            return '';
        });

        function decodeRealUrl(u) {
            try {
                if (typeof u !== 'string') u = String(u);
                if (u.includes(engine.prefix)) return engine.decodeUrl(u);
                return u;
            } catch (e) {
                return u;
            }
        }

        function proxyUrl(u) {
            try {
                if (!u) return null;
                if (typeof u !== 'string') u = String(u);
                if (u.startsWith('data:') || u.startsWith('blob:')) return u;
                if (u.includes(engine.prefix)) return u;
                return engine.encodeUrl(u);
            } catch (e) {
                return null;
            }
        }

        function normalizeUrl(query) {
            query = (query || '').trim();
            if (!query) return null;
            const isUrl = query.includes('.') && !query.includes(' ');
            if (!isUrl) return \`https://duckduckgo.com/?q=\${encodeURIComponent(query)}\`;
            if (!/^https?:\\/\\//i.test(query)) return 'https://' + query;
            return query;
        }

        async function fetchSuggestions(query) {
            query = (query || '').trim();
            if (!query) return [];
            try {
                const res = await fetch('/suggest?q=' + encodeURIComponent(query));
                return res.ok ? await res.json() : [];
            } catch (e) {
                return [];
            }
        }

        function attachSuggestions(input, box, onPick, positionBox, urlMode) {
            let items = [];
            let kbSel = -1;
            let seq = 0;
            let timer = null;

            function hide() { box.classList.remove('open'); box.innerHTML = ''; items = []; kbSel = -1; }

            function highlight(i) {
                [...box.children].forEach((c, idx) => c.classList.toggle('active', idx === i));
            }

            function choose(i) {
                const it = items[i];
                if (!it) return;
                hide();
                onPick(it.query);
            }

            function render(list) {
                items = list;
                kbSel = -1;
                box.innerHTML = '';
                if (!list.length || document.activeElement !== input) { hide(); return; }
                list.forEach((it, i) => {
                    const el = document.createElement('div');
                    el.className = 'suggest-item' + (it.cls ? ' ' + it.cls : '');
                    el.textContent = it.label;
                    el.addEventListener('mousedown', (e) => { e.preventDefault(); choose(i); });
                    el.addEventListener('mouseenter', () => highlight(i));
                    box.appendChild(el);
                });
                if (positionBox) positionBox();
                box.classList.add('open');
            }

            const looksLikeUrl = (q) => q.includes('.') && !q.includes(' ');

            function urlItems(q) {
                return [
                    { label: q, query: q, cls: 'open-link' },
                    { label: q + ' - DuckDuckGo Search', query: \`https://duckduckgo.com/?q=\${encodeURIComponent(q)}\` },
                ];
            }

            input.addEventListener('input', () => {
                const q = input.value.trim();
                clearTimeout(timer);
                if (!q) { hide(); return; }
                if (urlMode && looksLikeUrl(q)) { render(urlItems(q)); return; }
                const my = ++seq;
                timer = setTimeout(async () => {
                    const list = await fetchSuggestions(q);
                    if (my === seq) render(list.map(s => ({ label: s, query: s })));
                }, 120);
            });

            input.addEventListener('keydown', (e) => {
                const open = box.classList.contains('open');
                if (e.key === 'ArrowDown' && open) { e.preventDefault(); kbSel = Math.min(kbSel + 1, items.length - 1); highlight(kbSel); }
                else if (e.key === 'ArrowUp' && open) { e.preventDefault(); kbSel = Math.max(kbSel - 1, 0); highlight(kbSel); }
                else if (e.key === 'Escape') { hide(); }
                else if (e.key === 'Enter') {
                    e.preventDefault();
                    if (open && kbSel >= 0) choose(kbSel);
                    else { hide(); onPick(input.value); }
                }
            });

            box.addEventListener('mouseleave', () => highlight(kbSel));
            input.addEventListener('blur', () => setTimeout(hide, 120));
        }

        const tabsEl = document.getElementById('tabs');
        const contentEl = document.getElementById('content');
        const urlInput = document.getElementById('url-input');

        let tabs = [];
        let activeId = null;
        let tabSeq = 0;

        function activeTab() {
            return tabs.find(t => t.id === activeId) || null;
        }

        function tabsMinWidth(extra = 0) {
            let w = extra * 100;
            for (const t of tabs) w += t.pinned ? 36 : 100;
            const seps = tabs.length + extra - 1;
            if (seps > 0) w += seps * 5;
            return w;
        }

        function tabStripHasRoom() {
            if (tabs.length === 0) return true;
            const bar = document.getElementById('tabbar');
            const btn = document.getElementById('newtab-btn');
            if (!bar || !bar.clientWidth) return true;
            const cs = getComputedStyle(bar);
            const padX = parseFloat(cs.paddingLeft) + parseFloat(cs.paddingRight);
            const btnW = btn ? btn.offsetWidth + 8 : 0;
            const avail = bar.clientWidth - padX - btnW;
            return tabsMinWidth(1) <= avail;
        }

        function createTab(opts = {}) {
            if (!tabStripHasRoom()) {
                const cur = tabs.find(t => t.id === activeId);
                if (opts.url && cur) {
                    navigateTab(cur, opts.url);
                    return cur;
                }
                return null;
            }

            const id = ++tabSeq;
            const panel = document.createElement('div');
            panel.className = 'panel';
            contentEl.appendChild(panel);

            const tab = {
                id,
                type: 'newtab',
                title: 'New tab',
                url: '',
                favicon: NEWTAB_ICON,
                panel,
                sframe: null,
                newtabEl: null,
                settingsEl: null,
                hist: [],
                histPtr: -1,
                suppress: false,
            };
            tabs.push(tab);
            const animateOpen = tabs.length > 1;
            buildNewtab(tab);
            activateTab(id);
            renderTabs();
            if (animateOpen) animateTabOpen(tab);

            if (opts.url) navigateTab(tab, opts.url);
            return tab;
        }

        function closeTab(id, opts = {}) {
            const animate = opts.animate !== false;
            const idx = tabs.findIndex(t => t.id === id);
            if (idx === -1) return;
            const tab = tabs[idx];
            if (tab._closing) return;
            const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

            if (!animate || reduce || !tab.el || tabs.length === 1) {
                removeTab(tab);
                return;
            }

            if (activeId === id) {
                const next = tabs[idx + 1] || tabs[idx - 1];
                if (next) activateTab(next.id);
            }

            const el = tab.el;
            const ANIM = 260;
            const startW = el.getBoundingClientRect().width;
            tab._closing = true;
            tab._animatingLabel = true;
            el.style.pointerEvents = 'none';
            el.classList.add('label-anim', 'closing');
            el.style.overflow = 'hidden';
            el.style.zIndex = '-1';
            el.style.minWidth = '0px';
            el.style.transition = 'none';
            el.style.width = startW + 'px';
            el.style.flex = '0 0 ' + startW + 'px';
            el.style.padding = '0 10px';

            const sep = idx > 0
                ? sepEls.get(tab.id)
                : (tabs[idx + 1] ? sepEls.get(tabs[idx + 1].id) : null);
            if (sep) {
                sep.style.transition = 'none';
                sep.style.flex = '0 0 1px';
                sep.style.width = '1px';
                sep.style.margin = '0 2px';
                sep.style.opacity = '1';
            }

            requestAnimationFrame(() => {
                el.style.transition = \`width \${ANIM}ms ease, flex-basis \${ANIM}ms ease, padding \${ANIM}ms ease\`;
                el.style.width = '0px';
                el.style.flex = '0 0 0px';
                el.style.padding = '0';
                if (sep) {
                    sep.style.transition = \`width \${ANIM}ms ease, flex-basis \${ANIM}ms ease, margin \${ANIM}ms ease, opacity \${ANIM}ms ease\`;
                    sep.style.width = '0px';
                    sep.style.flex = '0 0 0px';
                    sep.style.margin = '0';
                    sep.style.opacity = '0';
                }
            });
            labelTypewriter(tab, 0, startW, ANIM);
            setTimeout(() => removeTab(tab), ANIM + 40);
        }

        function removeTab(tab) {
            const idx = tabs.findIndex(t => t.id === tab.id);
            if (idx === -1) return;
            if (tab.sframe && tab.sframe.dispose) tab.sframe.dispose();
            if (tab.panel) tab.panel.remove();
            tabs.splice(idx, 1);
            if (tabs.length === 0) {
                createTab();
                return;
            }
            if (activeId === tab.id) {
                const next = tabs[Math.min(idx, tabs.length - 1)];
                activateTab(next.id);
            }
            renderTabs();
        }

        function activateTab(id) {
            activeId = id;
            tabs.forEach(t => t.panel.classList.toggle('active', t.id === id));
            renderTabs();
            syncToolbar();
        }

        function buildTabEl(tab) {
            const el = document.createElement('div');
            el.className = 'tab';

            const fav = document.createElement('img');
            fav.className = 'favicon';
            fav.addEventListener('error', () => { if (fav.getAttribute('src') !== NO_ICON) fav.src = NO_ICON; });

            const title = document.createElement('span');
            title.className = 'tab-title';

            const audio = document.createElement('span');
            audio.className = 'tab-audio';
            audio.addEventListener('click', (e) => { e.stopPropagation(); setTabMuted(tab, !tab.muted); });

            const close = document.createElement('span');
            close.className = 'tab-close';
            close.textContent = '×';
            close.addEventListener('click', (e) => { e.stopPropagation(); closeTab(tab.id); });

            el.append(fav, title, audio, close);
            fav.draggable = false;
            el.addEventListener('click', () => {
                if (suppressTabClick) { suppressTabClick = false; return; }
                activateTab(tab.id);
            });
            el.addEventListener('pointerdown', (e) => onTabPointerDown(tab, e));
            el.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                e.stopPropagation();
                openTabMenu(e.clientX, e.clientY, tab);
            });

            tab.el = el;
            tab.favEl = fav;
            tab.titleEl = title;
            tab.audioEl = audio;
            tab.closeEl = close;
            return el;
        }

        let dragState = null;
        let suppressTabClick = false;
        const DRAG_THRESHOLD = 5;

        function onTabPointerDown(tab, e) {
            if (e.button !== 0) return;
            if (e.target.closest && e.target.closest('.tab-close, .tab-audio')) return;
            suppressTabClick = false;
            const rect = tab.el.getBoundingClientRect();
            dragState = {
                tab,
                pointerId: e.pointerId,
                startX: e.clientX,
                grabOffset: e.clientX - rect.left,
                started: false,
            };
        }

        function onDragMove(e) {
            if (!dragState || e.pointerId !== dragState.pointerId) return;

            if (!dragState.started) {
                if (Math.abs(e.clientX - dragState.startX) < DRAG_THRESHOLD) return;
                dragState.started = true;
                suppressTabClick = true;
                dragState.tab.el.classList.add('dragging');
                try { dragState.tab.el.setPointerCapture(dragState.pointerId); } catch (_) { }
            }

            e.preventDefault();
            reorderByPointer(e.clientX);
            positionDragged(e.clientX);
        }

        function reorderByPointer(pointerX) {
            const dragId = dragState.tab.id;
            const siblings = tabs.filter(t => t.id !== dragId);
            let newIndex = siblings.length;
            for (let i = 0; i < siblings.length; i++) {
                const r = siblings[i].el.getBoundingClientRect();
                if (pointerX < r.left + r.width / 2) { newIndex = i; break; }
            }
            const order = siblings.slice();
            order.splice(newIndex, 0, dragState.tab);
            const changed = order.some((t, i) => t.id !== tabs[i].id);
            if (!changed) return;

            const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

            const first = new Map();
            if (!reduce) {
                siblings.forEach(t => {
                    t.el.style.transition = 'none';
                    t.el.style.transform = '';
                    first.set(t.id, t.el.getBoundingClientRect().left);
                });
            }

            tabs = order;
            renderTabs();
            try { dragState.tab.el.setPointerCapture(dragState.pointerId); } catch (_) { }

            if (reduce) return;
            siblings.forEach(t => {
                const prev = first.get(t.id);
                if (prev == null) return;
                const dx = prev - t.el.getBoundingClientRect().left;
                if (Math.abs(dx) < 0.5) return;
                const el = t.el;
                el.style.transition = 'none';
                el.style.transform = \`translateX(\${dx}px)\`;
                requestAnimationFrame(() => {
                    el.style.transition = 'transform 160ms ease';
                    el.style.transform = '';
                });
            });
        }

        function positionDragged(pointerX) {
            const el = dragState.tab.el;
            const containerRect = tabsEl.getBoundingClientRect();
            el.style.transform = '';
            const naturalLeft = el.getBoundingClientRect().left;
            let desiredLeft = pointerX - dragState.grabOffset;
            desiredLeft = Math.max(containerRect.left, Math.min(desiredLeft, containerRect.right - el.offsetWidth));
            el.style.transform = \`translateX(\${desiredLeft - naturalLeft}px)\`;
        }

        function onDragEnd(e) {
            if (!dragState || (e && e.pointerId !== dragState.pointerId)) return;
            const el = dragState.tab.el;
            if (dragState.started) {
                el.classList.remove('dragging');
                tabs.forEach(t => { t.el.style.transition = ''; t.el.style.transform = ''; });
                try { el.releasePointerCapture(dragState.pointerId); } catch (_) { }
                renderTabs();
            }
            dragState = null;
        }

        window.addEventListener('pointermove', onDragMove);
        window.addEventListener('pointerup', onDragEnd);
        window.addEventListener('pointercancel', onDragEnd);

        function updateTabEl(tab) {
            if (!tab.el) buildTabEl(tab);
            const t = tab.title || 'New tab';
            if (tab.el.title !== t) tab.el.title = t;
            const icon = tab.favicon || NO_ICON;
            if (tab.favEl.getAttribute('src') !== icon) tab.favEl.src = icon;
            tab.el.classList.toggle('active', tab.id === activeId);
            tab.el.classList.toggle('pinned', !!tab.pinned);
            const sound = tab.pinned ? '' : tab.muted ? 'muted' : tab.audible ? 'on' : '';
            if (tab.audioEl.dataset.sound !== sound) {
                tab.audioEl.dataset.sound = sound;
                tab.audioEl.innerHTML = sound ? (sound === 'muted' ? SPEAKER_MUTED_SVG : SPEAKER_SVG) : '';
                tab.audioEl.title = sound === 'muted' ? 'Unmute tab' : sound ? 'Mute tab' : '';
            }
            tab.el.classList.toggle('has-audio', !!sound);
            if (!tab._animatingLabel) {
                const wantTitle = tab.pinned ? '' : t;
                if (tab.titleEl.textContent !== wantTitle) tab.titleEl.textContent = wantTitle;
                tab.closeEl.style.display = tab.pinned ? 'none' : '';
            }
        }

        const SPEAKER_SVG = '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 6h2.5l3.5-3v10l-3.5-3h-2.5z" fill="currentColor"/><path d="M11 5.5a3.5 3.5 0 0 1 0 5M12.8 3.5a6.2 6.2 0 0 1 0 9"/></svg>';
        const SPEAKER_MUTED_SVG = '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 6h2.5l3.5-3v10l-3.5-3h-2.5z" fill="currentColor"/><path d="M11 6l4 4M15 6l-4 4"/></svg>';

        // Muting is kept per tab and sent to the page again after every navigation.
        function setTabMuted(tab, muted) {
            tab.muted = !!muted;
            const w = tab.sframe && tab.sframe.frame.contentWindow;
            if (w) { try { w.postMessage({ __px: 'mute', muted: tab.muted }, PROXY_ORIGIN); } catch (e) { } }
            updateTabEl(tab);
        }

        function setTabAudible(tab, audible) {
            if (tab.audible === audible) return;
            tab.audible = audible;
            updateTabEl(tab);
        }

        const sepEls = new Map();

        function renderTabs() {
            tabs.forEach(updateTabEl);
            const seq = [];
            const seen = new Set();
            tabs.forEach((tab, i) => {
                if (i > 0) {
                    let sep = sepEls.get(tab.id);
                    if (!sep) { sep = document.createElement('div'); sepEls.set(tab.id, sep); }
                    sep.className = 'tab-sep';
                    if (tab.id === activeId || tabs[i - 1].id === activeId) sep.classList.add('hidden');
                    seen.add(tab.id);
                    seq.push(sep);
                }
                seq.push(tab.el);
            });
            for (const id of sepEls.keys()) { if (!seen.has(id)) sepEls.delete(id); }

            const desired = new Set(seq);
            Array.from(tabsEl.childNodes).forEach(n => { if (!desired.has(n)) tabsEl.removeChild(n); });
            let ref = tabsEl.firstChild;
            for (const node of seq) {
                if (ref === node) { ref = ref.nextSibling; }
                else { tabsEl.insertBefore(node, ref); }
            }
        }

        function buildNewtab(tab) {
            const nt = document.createElement('div');
            nt.className = 'newtab';

            const title = document.createElement('h1');
            title.className = 'nt-title';
            title.textContent = 'Knoiren Browser';

            const group = document.createElement('div');
            group.className = 'nt-input-group';
            const input = document.createElement('input');
            input.className = 'nt-input';
            input.setAttribute('aria-label', 'Search with DuckDuckGo or enter URL');
            input.spellcheck = false;
            const go = document.createElement('button');
            go.className = 'nt-go';
            go.title = 'Search';
            go.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><circle cx="10" cy="10" r="7"/><path d="M15.2 15.2 21 21"/></svg>';
            group.append(input, go);

            const go2 = () => { if (input.value.trim()) navigateTab(tab, input.value); };
            go.addEventListener('click', go2);

            const search = document.createElement('div');
            search.className = 'nt-search';
            const suggest = document.createElement('div');
            suggest.className = 'nt-suggest';
            search.append(group, suggest);
            attachSuggestions(input, suggest, (val) => navigateTab(tab, val));

            const github = document.createElement('a');
            github.className = 'nt-github';
            github.href = 'https://github.com/ltorl/knoiren-browser/tree/main';
            github.textContent = 'Github';
            // Opens as a Knoiren tab, not a tab of the real browser.
            const openGithub = (e) => {
                if (e.button > 1) return;
                e.preventDefault();
                createTab({ url: github.href });
            };
            github.addEventListener('click', openGithub);
            github.addEventListener('auxclick', openGithub);

            nt.append(title, search, github);
            tab.panel.appendChild(nt);
            tab.newtabEl = nt;
        }

        function showNewtab(tab) {
            if (tab.newtabEl) tab.newtabEl.style.display = '';
            if (tab.settingsEl) tab.settingsEl.style.display = 'none';
            if (tab.sframe) tab.sframe.frame.style.display = 'none';
        }

        function showFrame(tab) {
            if (tab.newtabEl) tab.newtabEl.style.display = 'none';
            if (tab.settingsEl) tab.settingsEl.style.display = 'none';
            if (tab.sframe) tab.sframe.frame.style.display = '';
        }

        // --- Settings page (knoiren://settings) ---------------------------------

        function settingsSection(title) {
            const h = document.createElement('div');
            h.className = 'set-group';
            h.textContent = title;
            return h;
        }

        function buildProxySection(inner) {
            inner.appendChild(settingsSection('Proxy'));

            const status = document.createElement('div');
            status.className = 'set-status';
            const dot = document.createElement('span');
            dot.className = 'set-dot ' + (engineReady ? 'ready' : engineFailed ? 'failed' : '');
            status.appendChild(dot);
            status.appendChild(document.createTextNode(
                engineReady ? 'Peekaboom ready'
                    : engineFailed ? 'Peekaboom is not reachable'
                        : 'Connecting to Peekaboom…'
            ));
            inner.appendChild(status);

            const note = document.createElement('div');
            note.className = 'set-note';
            note.textContent = 'Sites load through ' + PROXY_ORIGIN + ', a separate origin from this page.';
            inner.appendChild(note);
        }

        function buildWindowSection(inner) {
            inner.appendChild(settingsSection('Sites that can open new windows'));

            const allowed = Object.keys(winDecisions).filter(o => winDecisions[o] === 'allow').sort();

            if (!allowed.length) {
                const empty = document.createElement('div');
                empty.className = 'set-empty';
                empty.textContent = 'No sites yet. When a site asks to open a new window and you allow it, it is remembered here.';
                inner.appendChild(empty);
                return;
            }

            allowed.forEach(origin => {
                const row = document.createElement('div');
                row.className = 'set-site';

                const name = document.createElement('span');
                name.className = 'set-site-name';
                name.textContent = origin.replace(/^https?:\\/\\//, '');
                name.title = origin;

                const del = document.createElement('button');
                del.className = 'set-del';
                del.title = 'Remove ' + origin;
                del.setAttribute('aria-label', 'Remove ' + origin);
                del.addEventListener('click', () => {
                    delete winDecisions[origin];
                    saveWinDecisions();
                    renderAllSettings();
                });

                row.append(name, del);
                inner.appendChild(row);
            });

            const note = document.createElement('div');
            note.className = 'set-note';
            note.textContent = 'Removing a site makes Knoiren ask again the next time it tries to open a window.';
            inner.appendChild(note);
        }

        function renderSettings(tab) {
            if (!tab.settingsEl) return;
            const inner = tab.settingsEl.querySelector('.set-inner');
            inner.innerHTML = '';

            const title = document.createElement('h1');
            title.className = 'set-title';
            title.textContent = 'Settings';
            inner.appendChild(title);

            buildProxySection(inner);
            buildWindowSection(inner);
        }

        // Settings state is global, so every open settings tab has to be redrawn.
        function renderAllSettings() {
            tabs.forEach(t => { if (t.settingsEl) renderSettings(t); });
        }

        function showSettings(tab) {
            if (!tab) return;
            if (!tab.settingsEl) {
                const page = document.createElement('div');
                page.className = 'settingspage';
                const inner = document.createElement('div');
                inner.className = 'set-inner';
                page.appendChild(inner);
                tab.panel.appendChild(page);
                tab.settingsEl = page;
            }
            renderSettings(tab);
            if (!engineReady) initProxy();

            tab.type = 'settings';
            tab.url = SETTINGS_URL;
            tab.title = 'Settings';
            tab.favicon = SETTINGS_ICON;
            if (tab.newtabEl) tab.newtabEl.style.display = 'none';
            if (tab.sframe) tab.sframe.frame.style.display = 'none';
            tab.settingsEl.style.display = '';

            renderTabs();
            if (tab.id === activeId) syncToolbar();
        }

        function openSettings() {
            const existing = tabs.find(t => t.type === 'settings');
            if (existing) {
                activateTab(existing.id);
                renderSettings(existing);
                return;
            }
            const cur = activeTab();
            // Reuse an untouched new tab; otherwise open a fresh one.
            const tab = (cur && cur.type === 'newtab' && !cur.hist.length) ? cur : (createTab() || cur);
            showSettings(tab);
        }

        function ensureFrame(tab) {
            if (tab.sframe) return tab.sframe;
            const sframe = engine.createFrame();
            const f = sframe.frame;
            f.classList.add('webframe');
            tab.panel.appendChild(f);
            tab.sframe = sframe;

            sframe.addEventListener('urlchange', (e) => onUrlChange(tab, e));
            sframe.addEventListener('open', (e) => onWindowOpen(tab, e));
            return sframe;
        }

        async function navigateTab(tab, query) {
            if (SETTINGS_RE.test(String(query || '').trim())) return showSettings(tab);
            const url = normalizeUrl(query);
            if (!url) return;

            const sframe = ensureFrame(tab);
            tab.hist = tab.hist.slice(0, tab.histPtr + 1);
            if (tab.hist[tab.histPtr] !== url) {
                tab.hist.push(url);
                tab.histPtr = tab.hist.length - 1;
            }
            tab.type = 'web';
            tab.url = url;
            showFrame(tab);
            sframe.go(url);
            if (tab.id === activeId) syncToolbar();
            renderTabs();
        }

        function onUrlChange(tab, e) {
            const real = decodeRealUrl(e.url);
            if (tab.suppress) {
                tab.suppress = false;
            } else if (real && real !== tab.url && /^https?:/i.test(real)) {
                tab.hist = tab.hist.slice(0, tab.histPtr + 1);
                tab.hist.push(real);
                tab.histPtr = tab.hist.length - 1;
            }
            if (real && /^https?:/i.test(real)) tab.url = real;
            tab.meta = { title: e.title, icon: e.icon };
            updateMeta(tab);
        }

        // target=_blank links open a tab; scripted pop-ups need the site's permission.
        function onWindowOpen(tab, e) {
            const target = e.url;
            if (!/^https?:/i.test(target)) return;
            const origin = siteOrigin(tab);
            if (e.user || (origin && winDecisions[origin] === 'allow')) createTab({ url: target });
            else confirmWindowOpen(tab, target, origin);
        }

        function updateMeta(tab) {
            const meta = tab.meta || {};
            let host = '';
            try { host = new URL(tab.url).hostname.replace(/^www\\./, ''); } catch (e) { }
            tab.title = meta.title || host || tab.title;
            let icon = meta.icon && proxyUrl(meta.icon);
            if (!icon && tab.url) {
                try { icon = proxyUrl(new URL('/favicon.ico', tab.url).href); } catch (e) { }
            }
            tab.favicon = icon || NO_ICON;
            renderTabs();
            if (tab.id === activeId) syncToolbar();
        }

        function goBack(tab) {
            if (!tab) return;
            if (tab.histPtr > 0) {
                tab.histPtr--;
                tab.suppress = true;
                tab.url = tab.hist[tab.histPtr];
                showFrame(tab);
                tab.sframe.go(tab.url);
            } else if (tab.histPtr === 0) {
                tab.histPtr = -1;
                tab.url = '';
                tab.title = 'New tab';
                tab.favicon = NEWTAB_ICON;
                showNewtab(tab);
            }
            renderTabs();
            syncToolbar();
        }

        function goForward(tab) {
            if (!tab) return;
            if (tab.histPtr === -1 && tab.hist.length > 0) {
                tab.histPtr = 0;
                tab.url = tab.hist[0];
                showFrame(tab);
                updateMeta(tab);
            } else if (tab.histPtr < tab.hist.length - 1) {
                tab.histPtr++;
                tab.suppress = true;
                tab.url = tab.hist[tab.histPtr];
                showFrame(tab);
                tab.sframe.go(tab.url);
            }
            renderTabs();
            syncToolbar();
        }

        function reloadTab(tab) {
            if (!tab) return;
            if (tab.type === 'settings') { renderSettings(tab); return; }
            if (tab.histPtr >= 0 && tab.sframe) tab.sframe.go(tab.url);
        }

        function canGoBack(tab) {
            return tab && tab.histPtr >= 0 && tab.hist.length > 0;
        }
        function canGoForward(tab) {
            return tab && ((tab.histPtr === -1 && tab.hist.length > 0) || tab.histPtr < tab.hist.length - 1);
        }

        const btnBack = document.getElementById('btn-back');
        const btnForward = document.getElementById('btn-forward');
        const starBtn = document.getElementById('star-btn');

        function syncToolbar() {
            const tab = activeTab();
            urlInput.value = tab ? tab.url : '';
            btnBack.classList.toggle('disabled', !canGoBack(tab));
            btnForward.classList.toggle('disabled', !canGoForward(tab));
            updateStar();
        }

        function updateStar() {
            const tab = activeTab();
            const isBm = tab && tab.url && findBookmarkByUrl(tab.url);
            starBtn.querySelector('img').src = isBm ? STAR_ON : STAR_OFF;
            starBtn.title = isBm ? 'Edit bookmark' : 'Bookmark this page';
        }

        const bmBar = document.getElementById('bookmarksbar');
        let bookmarks = loadBookmarks();
        let bmClipboard = null;

        function loadBookmarks() {
            try {
                const raw = localStorage.getItem('knoiren_bookmarks');
                if (raw) return JSON.parse(raw);
            } catch (e) { }
            return [];
        }
        function saveBookmarks() {
            localStorage.setItem('knoiren_bookmarks', JSON.stringify(bookmarks));
        }
        function newId() {
            return 'b' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
        }

        function isBookmarklet(node) {
            return node && node.type === 'bookmark' && /^\\s*javascript:/i.test(node.url || '');
        }

        // Pages live on the proxy's origin, so the page runtime runs the code for us.
        function runBookmarklet(tab, rawUrl) {
            if (!tab || !tab.sframe || !/^https?:/i.test(tab.url || '')) return;
            let code = String(rawUrl).replace(/^\\s*javascript:/i, '');
            try { code = decodeURIComponent(code); } catch (e) { }
            tab.sframe.frame.contentWindow.postMessage({ __px: 'run', code }, PROXY_ORIGIN);
        }

        function findBookmarkByUrl(url, list = bookmarks) {
            for (const node of list) {
                if (node.type === 'bookmark' && node.url === url) return node;
                if (node.type === 'folder' && node.children) {
                    const f = findBookmarkByUrl(url, node.children);
                    if (f) return f;
                }
            }
            return null;
        }

        function locate(id, list = bookmarks, parent = bookmarks) {
            for (let i = 0; i < list.length; i++) {
                if (list[i].id === id) return { node: list[i], arr: list, index: i };
                if (list[i].type === 'folder' && list[i].children) {
                    const r = locate(id, list[i].children, list[i].children);
                    if (r) return r;
                }
            }
            return null;
        }

        function cloneNode(node) {
            return JSON.parse(JSON.stringify(node));
        }

        const bmEls = new Map();

        function renderBookmarks() {
            bmBar.classList.toggle('empty', bookmarks.length === 0);
            const seen = new Set();
            let prev = null;
            bookmarks.forEach(node => {
                seen.add(node.id);
                let el = bmEls.get(node.id);
                if (!el) { el = makeBmEl(node); bmEls.set(node.id, el); }
                else { updateBmEl(el, node); }
                const want = prev ? prev.nextSibling : bmBar.firstChild;
                if (want !== el) bmBar.insertBefore(el, want);
                prev = el;
            });
            for (const [id, el] of bmEls) {
                if (!seen.has(id)) { el.remove(); bmEls.delete(id); }
            }
            updateStar();
        }

        function makeBmEl(node) {
            const el = document.createElement('div');
            el.className = 'bm';
            el.dataset.id = node.id;
            const img = document.createElement('img');
            const label = document.createElement('span');
            label.className = 'bm-label';
            el.append(img, label);

            el.addEventListener('click', (e) => {
                const n = (locate(el.dataset.id) || {}).node;
                if (!n) return;
                if (n.type === 'folder') { e.stopPropagation(); openFolderDropdown(n, el); }
                else if (isBookmarklet(n)) { const t = activeTab(); if (t) runBookmarklet(t, n.url); }
                else { const t = activeTab(); if (t) navigateTab(t, n.url); }
            });
            el.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                e.stopPropagation();
                openCtxMenu(e.clientX, e.clientY, (locate(el.dataset.id) || {}).node || node);
            });

            updateBmEl(el, node);
            return el;
        }

        function updateBmEl(el, node) {
            const img = el.querySelector('img');
            const label = el.querySelector('.bm-label');
            const wantSrc = node.type === 'folder' ? FOLDER_ICON : (node.icon || NO_ICON);
            if (img.getAttribute('src') !== wantSrc) {
                img.onerror = () => { img.onerror = null; img.src = NO_ICON; };
                img.src = wantSrc;
            }
            const wantText = node.type === 'folder' ? (node.title || 'Folder') : (node.title || node.url);
            if (label.textContent !== wantText) label.textContent = wantText;
        }

        let openDropdowns = [];
        function closeDropdowns() {
            openDropdowns.forEach(d => d.remove());
            openDropdowns = [];
        }
        function openFolderDropdown(folder, anchorEl, x, y) {
            closeDropdowns();
            const dd = document.createElement('div');
            dd.className = 'bm-dropdown';
            const children = folder.children || [];
            if (children.length === 0) {
                const empty = document.createElement('div');
                empty.className = 'dd-empty';
                empty.textContent = '(empty)';
                dd.appendChild(empty);
            } else {
                children.forEach(child => {
                    const item = document.createElement('div');
                    item.className = 'dd-item';
                    const img = document.createElement('img');
                    const lbl = document.createElement('span');
                    lbl.className = 'dd-label';
                    if (child.type === 'folder') {
                        img.src = FOLDER_ICON;
                        lbl.textContent = child.title || 'Folder';
                        item.addEventListener('click', (e) => {
                            e.stopPropagation();
                            const r = item.getBoundingClientRect();
                            openFolderDropdown(child, item, r.right, r.top);
                        });
                    } else {
                        img.src = child.icon || NO_ICON;
                        img.onerror = () => { img.onerror = null; img.src = NO_ICON; };
                        lbl.textContent = child.title || child.url;
                        item.addEventListener('click', () => {
                            closeDropdowns();
                            const t = activeTab(); if (!t) return;
                            if (isBookmarklet(child)) runBookmarklet(t, child.url);
                            else navigateTab(t, child.url);
                        });
                    }
                    item.addEventListener('contextmenu', (e) => {
                        e.preventDefault(); e.stopPropagation();
                        openCtxMenu(e.clientX, e.clientY, child);
                    });
                    item.append(img, lbl);
                    dd.appendChild(item);
                });
            }
            document.body.appendChild(dd);
            if (x == null) {
                const r = anchorEl.getBoundingClientRect();
                x = r.left; y = r.bottom + 2;
            }
            dd.style.left = Math.min(x, window.innerWidth - dd.offsetWidth - 6) + 'px';
            dd.style.top = y + 'px';
            openDropdowns.push(dd);
        }

        const ctxMenu = document.getElementById('ctx-menu');
        let ctxTarget = null;

        function showCtxMenu(x, y, items) {
            ctxMenu.innerHTML = '';
            items.forEach(it => {
                if (it.sep) {
                    const s = document.createElement('div');
                    s.className = 'ctx-sep';
                    ctxMenu.appendChild(s);
                    return;
                }
                const el = document.createElement('div');
                el.className = 'ctx-item' + (it.disabled ? ' disabled' : '');
                el.textContent = it.label;
                if (!it.disabled) el.addEventListener('click', () => { closeCtxMenu(); it.action(); });
                ctxMenu.appendChild(el);
            });
            ctxMenu.style.display = 'block';
            const w = ctxMenu.offsetWidth, h = ctxMenu.offsetHeight;
            ctxMenu.style.left = Math.min(x, window.innerWidth - w - 6) + 'px';
            ctxMenu.style.top = Math.min(y, window.innerHeight - h - 6) + 'px';
        }

        function openCtxMenu(x, y, node) {
            ctxTarget = node || null;
            const items = [
                { label: 'New blank bookmark', action: ctxNewBookmark },
                { label: 'New folder', action: ctxNewFolder },
                { label: 'Bookmark this page', action: ctxBookmarkPage },
                { sep: true },
                { label: 'Cut', action: ctxCut, disabled: !ctxTarget },
                { label: 'Copy', action: ctxCopy, disabled: !ctxTarget },
                { label: 'Paste', action: ctxPaste },
            ];
            if (ctxTarget) {
                items.push({ sep: true });
                items.push({ label: 'Edit…', action: ctxEdit });
                items.push({ label: 'Delete', action: ctxDelete });
            }
            showCtxMenu(x, y, items);
        }

        function closeCtxMenu() {
            ctxMenu.style.display = 'none';
        }

        function openTabMenu(x, y, tab) {
            const idx = tabs.indexOf(tab);
            const others = tabs.filter(t => t !== tab && !t.pinned);
            const toRight = tabs.slice(idx + 1).filter(t => !t.pinned);
            const toLeft = tabs.slice(0, idx).filter(t => !t.pinned);
            showCtxMenu(x, y, [
                { label: 'Duplicate', action: () => duplicateTab(tab) },
                { label: 'Reload', action: () => reloadTab(tab), disabled: tab.histPtr < 0 },
                { label: tab.pinned ? 'Unpin' : 'Pin', action: () => togglePin(tab) },
                { label: tab.muted ? 'Unmute tab' : 'Mute tab', action: () => setTabMuted(tab, !tab.muted) },
                { sep: true },
                { label: 'Close', action: () => closeTab(tab.id) },
                { label: 'Close other tabs', action: () => closeMany(others), disabled: others.length === 0 },
                { label: 'Close Tabs to the right', action: () => closeMany(toRight), disabled: toRight.length === 0 },
                { label: 'Close Tabs to the left', action: () => closeMany(toLeft), disabled: toLeft.length === 0 },
            ]);
        }

        function duplicateTab(tab) {
            const idx = tabs.indexOf(tab);
            const dup = createTab(tab.url ? { url: tab.url } : {});
            const from = tabs.indexOf(dup);
            if (!dup || from !== tabs.length - 1) return;
            tabs.splice(from, 1);
            tabs.splice(idx + 1, 0, dup);
            reorderPinned();
            renderTabs();
        }

        function labelTypewriter(tab, lowW, highW, durationMs) {
            const range = Math.max(1, highW - lowW);
            const start = performance.now();
            function tick(now) {
                // Read the title live: a tab can be renamed mid-animation (e.g. a new
                // tab immediately becoming the settings page).
                const fullTitle = tab.title || 'New tab';
                const totalUnits = fullTitle.length + 1;
                const w = tab.el.getBoundingClientRect().width;
                const p = Math.max(0, Math.min(1, (w - lowW) / range));
                const vis = Math.round(totalUnits * p);
                const txt = fullTitle.slice(0, Math.min(vis, fullTitle.length));
                if (tab.titleEl.textContent !== txt) tab.titleEl.textContent = txt;
                tab.closeEl.style.display = vis > fullTitle.length ? '' : 'none';
                if (now - start < durationMs + 40) requestAnimationFrame(tick);
            }
            requestAnimationFrame(tick);
        }

        function animateTabOpen(tab) {
            const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            const el = tab.el;
            if (reduce || !el) return;
            const ANIM = 260;
            const targetW = el.getBoundingClientRect().width;
            const startW = Math.min(36, targetW);
            if (targetW - startW < 1) return;

            tab._animatingLabel = true;
            el.classList.add('label-anim');
            el.style.transition = 'none';
            el.style.minWidth = '0px';
            el.style.width = startW + 'px';
            el.style.flex = '0 0 ' + startW + 'px';
            el.style.zIndex = '-1';

            requestAnimationFrame(() => {
                el.style.transition = \`width \${ANIM}ms ease, flex-basis \${ANIM}ms ease\`;
                el.style.width = targetW + 'px';
                el.style.flex = '0 0 ' + targetW + 'px';
            });

            labelTypewriter(tab, startW, targetW, ANIM);

            setTimeout(() => {
                el.style.transition = '';
                el.style.width = '';
                el.style.flex = '';
                el.style.minWidth = '';
                el.style.zIndex = '';
                el.classList.remove('label-anim');
                tab._animatingLabel = false;
                updateTabEl(tab);
            }, ANIM + 40);
        }

        function togglePin(tab) {
            const ANIM = 260;
            const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

            const first = new Map();
            tabs.forEach(t => first.set(t.id, t.el.getBoundingClientRect()));

            tab._animatingLabel = !reduce;
            tab.pinned = !tab.pinned;
            reorderPinned();
            renderTabs();

            if (reduce) return;

            const tFirstW = (first.get(tab.id) || tab.el.getBoundingClientRect()).width;
            const tLastW = tab.el.getBoundingClientRect().width;
            const fullW = Math.max(tFirstW, tLastW);
            const pinnedW = Math.min(tFirstW, tLastW);
            tab.el.classList.add('label-anim');

            const animating = [];
            tabs.forEach(t => {
                const f = first.get(t.id);
                if (!f) return;
                const l = t.el.getBoundingClientRect();
                const dx = f.left - l.left;
                const dw = f.width - l.width;
                if (Math.abs(dx) < 0.5 && Math.abs(dw) < 0.5) return;
                const el = t.el;
                el.style.transition = 'none';
                el.style.transform = \`translateX(\${dx}px)\`;
                if (Math.abs(dw) > 0.5) {
                    el.style.width = f.width + 'px';
                    el.style.flex = '0 0 ' + f.width + 'px';
                    el.dataset.targetW = l.width;
                }
                animating.push(el);
            });
            tab.el.style.zIndex = '-1';

            requestAnimationFrame(() => {
                animating.forEach(el => {
                    el.style.transition = \`transform \${ANIM}ms ease, width \${ANIM}ms ease, flex-basis \${ANIM}ms ease\`;
                    el.style.transform = 'translateX(0)';
                    if (el.dataset.targetW != null) {
                        el.style.width = el.dataset.targetW + 'px';
                        el.style.flex = '0 0 ' + el.dataset.targetW + 'px';
                    }
                });
            });

            labelTypewriter(tab, pinnedW, fullW, ANIM);

            setTimeout(() => {
                animating.forEach(el => {
                    el.style.transition = '';
                    el.style.transform = '';
                    el.style.width = '';
                    el.style.flex = '';
                    delete el.dataset.targetW;
                });
                tab.el.style.zIndex = '';
                tab.el.classList.remove('label-anim');
                tab._animatingLabel = false;
                updateTabEl(tab);
            }, ANIM + 40);
        }

        function reorderPinned() {
            tabs = [...tabs.filter(t => t.pinned), ...tabs.filter(t => !t.pinned)];
        }

        function closeMany(list) {
            list.slice().forEach(t => closeTab(t.id, { animate: false }));
        }

        function insertNode(node) {
            if (ctxTarget) {
                const loc = locate(ctxTarget.id);
                if (loc) { loc.arr.splice(loc.index + 1, 0, node); saveBookmarks(); renderBookmarks(); return; }
            }
            bookmarks.push(node);
            saveBookmarks();
            renderBookmarks();
        }

        async function ctxNewBookmark() {
            const res = await showModal({
                title: 'New bookmark',
                fields: [{ key: 'title', label: 'Name', value: '' }, { key: 'url', label: 'URL', value: 'https://' }]
            });
            if (!res) return;
            insertNode({ id: newId(), type: 'bookmark', title: res.title || res.url, url: res.url, icon: NO_ICON });
        }

        async function ctxNewFolder() {
            const res = await showModal({
                title: 'New folder',
                fields: [{ key: 'title', label: 'Name', value: '' }]
            });
            if (!res) return;
            insertNode({ id: newId(), type: 'folder', title: res.title || 'New folder', children: [] });
        }

        function ctxBookmarkPage() {
            const tab = activeTab();
            if (!tab || !tab.url) return;
            insertNode({ id: newId(), type: 'bookmark', title: tab.title || tab.url, url: tab.url, icon: tab.favicon || NO_ICON });
        }

        function ctxCut() {
            if (!ctxTarget) return;
            const loc = locate(ctxTarget.id);
            if (!loc) return;
            bmClipboard = { node: cloneNode(loc.node) };
            loc.arr.splice(loc.index, 1);
            saveBookmarks();
            renderBookmarks();
        }

        function ctxCopy() {
            if (!ctxTarget) return;
            bmClipboard = { node: cloneNode(ctxTarget) };
        }

        async function ctxPaste() {
            if (bmClipboard) {
                const node = cloneNode(bmClipboard.node);
                reassignIds(node);
                insertNode(node);
                return;
            }
            let text = '';
            try { text = await navigator.clipboard.readText(); } catch (e) { }
            text = (text || '').trim();
            if (!text) return;
            const url = /^https?:\\/\\//i.test(text) ? text : (text.includes('.') ? 'https://' + text : null);
            if (!url) return;
            const tab = activeTab();
            let title, icon;
            if (tab && tab.url === url) { title = tab.title; icon = tab.favicon; }
            else { try { title = new URL(url).hostname.replace(/^www\\./, ''); } catch (e) { title = url; } icon = NO_ICON; }
            insertNode({ id: newId(), type: 'bookmark', title: title || url, url, icon: icon || NO_ICON });
        }

        function reassignIds(node) {
            node.id = newId();
            if (node.children) node.children.forEach(reassignIds);
        }

        async function ctxEdit() {
            if (!ctxTarget) return;
            const node = ctxTarget;
            if (node.type === 'folder') {
                const res = await showModal({ title: 'Edit folder', fields: [{ key: 'title', label: 'Name', value: node.title || '' }] });
                if (!res) return;
                node.title = res.title || node.title;
            } else {
                const res = await showModal({
                    title: 'Edit bookmark',
                    fields: [{ key: 'title', label: 'Name', value: node.title || '' }, { key: 'url', label: 'URL', value: node.url || '' }]
                });
                if (!res) return;
                node.title = res.title || node.title;
                node.url = res.url || node.url;
            }
            saveBookmarks();
            renderBookmarks();
        }

        function ctxDelete() {
            if (!ctxTarget) return;
            const loc = locate(ctxTarget.id);
            if (!loc) return;
            loc.arr.splice(loc.index, 1);
            saveBookmarks();
            renderBookmarks();
        }

        bmBar.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            openCtxMenu(e.clientX, e.clientY, null);
        });

        document.addEventListener('click', (e) => {
            if (!ctxMenu.contains(e.target)) closeCtxMenu();
            if (!e.target.closest('.bm-dropdown') && !e.target.closest('.bm')) closeDropdowns();
        });
        window.addEventListener('blur', () => { closeCtxMenu(); closeDropdowns(); });

        starBtn.addEventListener('click', () => {
            const tab = activeTab();
            if (!tab || !tab.url) { ctxNewBookmark(); return; }
            const existing = findBookmarkByUrl(tab.url);
            if (existing) {
                const loc = locate(existing.id);
                if (loc) { loc.arr.splice(loc.index, 1); saveBookmarks(); renderBookmarks(); }
            } else {
                bookmarks.push({ id: newId(), type: 'bookmark', title: tab.title || tab.url, url: tab.url, icon: tab.favicon || NO_ICON });
                saveBookmarks();
                renderBookmarks();
            }
        });

        const modalOverlay = document.getElementById('modal-overlay');
        const modalBox = document.getElementById('modal-box');

        function showModal({ title, fields }) {
            return new Promise(resolve => {
                modalBox.innerHTML = '';
                const h = document.createElement('h3');
                h.textContent = title;
                modalBox.appendChild(h);
                const inputs = {};
                fields.forEach(f => {
                    const lbl = document.createElement('label');
                    lbl.textContent = f.label;
                    const inp = document.createElement('input');
                    inp.value = f.value || '';
                    inputs[f.key] = inp;
                    modalBox.append(lbl, inp);
                });
                const actions = document.createElement('div');
                actions.className = 'modal-actions';
                const cancel = document.createElement('button');
                cancel.className = 'btn-cancel'; cancel.textContent = 'Cancel';
                const ok = document.createElement('button');
                ok.className = 'btn-ok'; ok.textContent = 'Save';
                actions.append(cancel, ok);
                modalBox.appendChild(actions);

                function done(val) {
                    modalOverlay.classList.remove('show');
                    resolve(val);
                }
                cancel.addEventListener('click', () => done(null));
                ok.addEventListener('click', () => {
                    const out = {};
                    Object.keys(inputs).forEach(k => out[k] = inputs[k].value.trim());
                    done(out);
                });
                modalBox.addEventListener('keydown', function onKey(e) {
                    if (e.key === 'Enter') { e.preventDefault(); ok.click(); }
                    if (e.key === 'Escape') { e.preventDefault(); cancel.click(); }
                });
                modalOverlay.classList.add('show');
                const first = fields[0] && inputs[fields[0].key];
                if (first) { first.focus(); first.select(); }
            });
        }

        let winDecisions = {};
        try { winDecisions = JSON.parse(localStorage.getItem('knoiren-win-decisions') || '{}') || {}; } catch (e) { winDecisions = {}; }
        function saveWinDecisions() {
            try { localStorage.setItem('knoiren-win-decisions', JSON.stringify(winDecisions)); } catch (e) { }
        }
        function siteOrigin(tab) {
            if (!tab || !/^https?:/i.test(tab.url || '')) return '';
            try { return new URL(tab.url).origin; } catch (e) { return tab.url || ''; }
        }

        function showConfirm(title, msg, okLabel = 'Continue') {
            return new Promise(resolve => {
                modalBox.innerHTML = '';
                const h = document.createElement('h3');
                h.textContent = title;
                const p = document.createElement('div');
                p.className = 'modal-msg';
                p.textContent = msg;

                const actions = document.createElement('div');
                actions.className = 'modal-actions';
                const cancel = document.createElement('button');
                cancel.className = 'btn-cancel'; cancel.textContent = 'Cancel';
                const ok = document.createElement('button');
                ok.className = 'btn-ok'; ok.textContent = okLabel;
                actions.append(cancel, ok);
                modalBox.append(h, p, actions);

                function done(v) { modalOverlay.classList.remove('show'); resolve(v); }
                cancel.addEventListener('click', () => done(false));
                ok.addEventListener('click', () => done(true));
                modalBox.addEventListener('keydown', function (e) {
                    if (e.key === 'Enter') { e.preventDefault(); ok.click(); }
                    if (e.key === 'Escape') { e.preventDefault(); cancel.click(); }
                });
                modalOverlay.classList.add('show');
                ok.focus();
            });
        }

        function showWindowWarning(url) {
            return new Promise(resolve => {
                modalBox.innerHTML = '';
                const h = document.createElement('h3');
                h.textContent = 'Allow new windows?';
                const p = document.createElement('div');
                p.className = 'modal-msg';
                p.textContent = 'This site wants to open a new window:\\n\\n' + url;

                const actions = document.createElement('div');
                actions.className = 'modal-actions';
                const block = document.createElement('button');
                block.className = 'btn-cancel'; block.textContent = 'Block';
                const allow = document.createElement('button');
                allow.className = 'btn-ok'; allow.textContent = 'Allow';
                actions.append(block, allow);
                modalBox.append(h, p, actions);

                function done(action) { modalOverlay.classList.remove('show'); resolve(action); }
                block.addEventListener('click', () => done('block'));
                allow.addEventListener('click', () => done('allow'));
                modalBox.addEventListener('keydown', function (e) {
                    if (e.key === 'Enter') { e.preventDefault(); allow.click(); }
                    if (e.key === 'Escape') { e.preventDefault(); block.click(); }
                });
                modalOverlay.classList.add('show');
                allow.focus();
            });
        }

        async function confirmWindowOpen(tab, url, origin) {
            const action = await showWindowWarning(url);
            if (action !== 'allow') return;
            if (origin) {
                winDecisions[origin] = 'allow';
                saveWinDecisions();
                renderAllSettings();
            }
            createTab({ url });
        }

        document.getElementById('btn-back').addEventListener('click', () => goBack(activeTab()));
        document.getElementById('btn-forward').addEventListener('click', () => goForward(activeTab()));
        document.getElementById('btn-reload').addEventListener('click', () => reloadTab(activeTab()));
        document.getElementById('newtab-btn').addEventListener('click', () => createTab());

        const urlSuggest = document.getElementById('url-suggest');
        attachSuggestions(urlInput, urlSuggest, (val) => {
            const tab = activeTab();
            if (tab) navigateTab(tab, val);
            urlInput.blur();
        }, () => {
            const r = document.getElementById('urlbar').getBoundingClientRect();
            urlSuggest.style.left = r.left + 'px';
            urlSuggest.style.top = (r.bottom + 4) + 'px';
            urlSuggest.style.width = r.width + 'px';
        }, true);

        const appEl = document.getElementById('app');
        const collapseBtn = document.getElementById('collapse-btn');
        const toolbarEl = document.getElementById('toolbar');
        collapseBtn.addEventListener('click', () => {
            const hidden = appEl.classList.toggle('chrome-hidden');
            collapseBtn.classList.toggle('collapsed', hidden);
            collapseBtn.title = hidden ? 'Show toolbar' : 'Hide toolbar';

            if (hidden) {
                toolbarEl.style.height = toolbarEl.scrollHeight + 'px';
                toolbarEl.getBoundingClientRect();
                toolbarEl.style.height = '0px';
            } else {
                toolbarEl.style.height = '0px';
                toolbarEl.getBoundingClientRect();
                const target = toolbarEl.scrollHeight;
                toolbarEl.style.height = target + 'px';
                const onEnd = (e) => {
                    if (e.propertyName !== 'height') return;
                    toolbarEl.style.height = '';
                    toolbarEl.removeEventListener('transitionend', onEnd);
                };
                toolbarEl.addEventListener('transitionend', onEnd);
            }
        });

        function imgEl(src) { const i = document.createElement('img'); i.src = src; return i; }
        collapseBtn.appendChild(imgEl(ICON_COLLAPSE));
        btnBack.appendChild(imgEl(ICON_FWD));
        btnForward.appendChild(imgEl(ICON_FWD));
        document.getElementById('btn-reload').appendChild(imgEl(ICON_RELOAD));
        starBtn.appendChild(imgEl(STAR_OFF));

        const gamesBtn = document.getElementById('games-btn');
        const gamesSidebar = document.getElementById('games-sidebar');
        const gamesList = document.getElementById('games-sidebar-list');
        gamesBtn.appendChild(imgEl(GAMES_ICON));

        // Browsers without overflow: clip still let a page inside a tab scroll this
        // document (and #content) sideways; snap them back.
        for (const el of [document.documentElement, document.body, document.getElementById('content')]) {
            const target = el === document.documentElement ? window : el;
            target.addEventListener('scroll', () => {
                if (el.scrollLeft || el.scrollTop) { el.scrollLeft = 0; el.scrollTop = 0; }
            });
        }

        function setGamesSidebar(open) {
            gamesSidebar.classList.toggle('open', open);
            gamesBtn.classList.toggle('active', open);
        }

        GAMES.forEach(([label, url]) => {
            const link = document.createElement('div');
            link.className = 'gs-link';
            link.textContent = label;
            link.addEventListener('click', () => {
                const tab = tabs.find(t => t.id === activeId);
                if (tab) navigateTab(tab, url);
                setGamesSidebar(false);
            });
            gamesList.appendChild(link);
        });

        gamesBtn.addEventListener('click', () => setGamesSidebar(!gamesSidebar.classList.contains('open')));
        document.getElementById('games-sidebar-close').addEventListener('click', () => setGamesSidebar(false));

        const settingsBtn = document.getElementById('settings-btn');
        settingsBtn.appendChild(imgEl(SETTINGS_ICON));
        settingsBtn.addEventListener('click', () => openSettings());

        const siteBtn = document.getElementById('site-btn');
        const sitePanel = document.getElementById('site-panel');
        siteBtn.appendChild(imgEl(SITE_ICON));

        function renderSitePanel() {
            const tab = activeTab();
            const origin = tab ? siteOrigin(tab) : '';
            sitePanel.innerHTML = '';

            const head = document.createElement('div');
            head.className = 'site-panel-head';
            head.textContent = origin ? origin.replace(/^https?:\\/\\//, '') : 'No site loaded';
            sitePanel.appendChild(head);

            const row = document.createElement('div');
            row.className = 'site-row';
            const label = document.createElement('span');
            label.textContent = 'Pop-up windows';
            const status = document.createElement('span');
            status.className = 'site-status';
            status.textContent = !origin ? '—' : (winDecisions[origin] === 'allow' ? 'Allowed' : 'Ask');
            row.append(label, status);
            sitePanel.appendChild(row);

            const reset = document.createElement('button');
            reset.className = 'site-reset';
            reset.textContent = 'Reset permission';
            reset.disabled = !(origin && winDecisions[origin]);
            reset.addEventListener('click', () => {
                if (origin && winDecisions[origin]) { delete winDecisions[origin]; saveWinDecisions(); renderAllSettings(); }
                renderSitePanel();
            });
            sitePanel.appendChild(reset);
        }

        function setSitePanel(open) {
            if (open) {
                renderSitePanel();
                const r = siteBtn.getBoundingClientRect();
                sitePanel.style.left = r.left + 'px';
                sitePanel.style.top = (r.bottom + 6) + 'px';
            }
            sitePanel.classList.toggle('open', open);
            siteBtn.classList.toggle('active', open);
        }

        siteBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            setSitePanel(!sitePanel.classList.contains('open'));
        });
        document.addEventListener('click', (e) => {
            if (sitePanel.classList.contains('open') && !sitePanel.contains(e.target) && !siteBtn.contains(e.target)) {
                setSitePanel(false);
            }
        });

        renderBookmarks();
        initProxy();
        createTab();
    </script>
</body>

</html>
`;
