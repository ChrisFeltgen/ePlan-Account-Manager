// Staff-only HTTP server for the bulk-add-account tool: lets Development
// Services staff add a new or existing ProjectDox account to many projects
// at once, as either "Applicant" or "View Only Public".
//
// Route-allowlisted like permit-status-server.js (never a generic static-
// file/path resolver) - this server can see project security data and must
// 404 everything it doesn't explicitly define.
//
// AUTH MODEL (changed 2026-09-29): staff still POST their own ProjectDox
// email/password once to /api/login, and login still requires that account
// to hold System Administrator or Project Administrator rights (see
// hasRequiredRole in bulk-add-account.js) - that login is exchanged for a
// SessionID via User/Login and the password is immediately forgotten, only
// the SessionID (plus display info) is kept, in memory, keyed by an opaque
// cookie token this server generates. That's still true, but it's now ONLY
// used to establish IDENTITY and pass the role check at login - confirmed
// live that a real Project Administrator account, despite passing that
// check, gets refused by other calls this tool needs (Chris confirmed this
// in real staff use: a PA could log in but the tool then failed to actually
// do anything). So every actual data operation now runs through a separate,
// shared System Administrator session (pdx.withSaSession(), backed by
// PROJECTDOX_ADMIN_EMAIL/PASSWORD) instead of the logged-in staff member's
// own session - the same env-var-backed service-account pattern collector.js
// /permit-status.js already use, not something unique to this tool anymore.
// Per-staff audit trail is unaffected (every write is still logged against
// session.email/session.userId, captured from the staff member's own login),
// but the ProjectDox-side credential this process now holds is SA-level,
// which changes this tool's own blast-radius-if-compromised story - it can
// no longer be described as "at most whatever the logged-in staff member's
// own account could do".
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const pdx = require('./bulk-add-account');

// PORT first, not BULK_ADD_PORT: cPanel's Node.js Selector (Passenger) sets
// PORT itself and the app must bind to whatever it picks - same convention
// permit-status-server.js already uses. BULK_ADD_PORT is only a fallback for
// running two of these tools locally side by side without an env clash.
const PORT = parseInt(process.env.PORT || process.env.BULK_ADD_PORT || '5759', 10);
const PAGE_PATH = path.join(__dirname, 'index.html');
const LOGO_PATH = path.join(__dirname, 'copb-logo.png');

const LOG_DIR = path.join(__dirname, 'data', 'bulk-add-account-log');
fs.mkdirSync(LOG_DIR, { recursive: true });

const COOKIE_NAME = 'bulk_add_session';
const SESSION_TTL_MS = parseInt(process.env.BULK_ADD_SESSION_TTL_MS || String(30 * 60 * 1000), 10); // 30 min idle timeout
const MAX_PROJECTS_PER_REQUEST = 500; // bounds request duration + blast radius of one Apply click
const PREVIEW_CONCURRENCY = 10; // resolve/preview are read-only ProjectDox calls - safe to run several in flight at once

// token -> { pdxSessionId, userId, email, fullName, createdAt, lastActivity }
const sessions = new Map();

setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [token, s] of sessions) {
    if (s.lastActivity < cutoff) sessions.delete(token);
  }
}, 60 * 1000).unref();

// --- login rate limiting (per IP, separate from general API use) -----------
// This endpoint proxies real credential attempts to ProjectDox, so it gets
// its own tighter limit than a generic API abuse guard would.
const LOGIN_RATE_LIMIT_MAX = parseInt(process.env.BULK_ADD_LOGIN_RATE_LIMIT_MAX || '10', 10);
const LOGIN_RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const loginHits = new Map(); // ip -> timestamps[]

function clientIp(req) {
  // Same caveat as permit-status-server.js: only trustworthy behind a
  // reverse proxy that itself sets/overwrites this header.
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function loginRateLimited(ip) {
  const now = Date.now();
  const cutoff = now - LOGIN_RATE_LIMIT_WINDOW_MS;
  const times = (loginHits.get(ip) || []).filter((t) => t > cutoff);
  times.push(now);
  loginHits.set(ip, times);
  return times.length > LOGIN_RATE_LIMIT_MAX;
}

function isSecureRequest(req) {
  return req.socket.encrypted === true || req.headers['x-forwarded-proto'] === 'https';
}

function setSessionCookie(req, res, token) {
  const parts = [
    `${COOKIE_NAME}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
  ];
  if (isSecureRequest(req)) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(req, res) {
  const parts = [`${COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0'];
  if (isSecureRequest(req)) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return null;
}

function getSession(req) {
  const token = readCookie(req, COOKIE_NAME);
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() - s.lastActivity > SESSION_TTL_MS) { sessions.delete(token); return null; }
  s.lastActivity = Date.now();
  return { token, ...s };
}

function auditLog(entry) {
  const day = new Date().toISOString().slice(0, 10);
  const line = JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n';
  fs.appendFile(path.join(LOG_DIR, `${day}.jsonl`), line, () => {}); // best-effort; never blocks/fails the request
}

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

// Every day that has ever logged anything, newest first - lets the audit
// viewer offer a dropdown of days that actually have data instead of a
// blind date picker that silently loads empty on most days.
function listAuditLogDates() {
  let files;
  try { files = fs.readdirSync(LOG_DIR); } catch (e) { return []; }
  return files
    .filter((f) => f.endsWith('.jsonl') && DATE_RE.test(f.slice(0, -6)))
    .map((f) => f.slice(0, -6))
    .sort()
    .reverse();
}

// Parses one day's JSONL log file, newest entry first. Never throws - a
// missing file (no activity that day) or a torn/mid-write last line just
// yields fewer entries, since this reads whatever's on disk right now
// rather than waiting for a write in progress.
const AUDIT_LOG_MAX_ENTRIES = 5000;
function readAuditLog(date) {
  let text;
  try { text = fs.readFileSync(path.join(LOG_DIR, `${date}.jsonl`), 'utf8'); } catch (e) { return []; }
  const entries = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try { entries.push(JSON.parse(line)); } catch (e) { /* skip a torn/partial line */ }
  }
  entries.reverse();
  return entries.slice(0, AUDIT_LOG_MAX_ENTRIES);
}

function sendJson(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(JSON.stringify(body));
}

function sendFile(res, filePath, contentType) {
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, {
      'Content-Type': contentType,
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    });
    res.end(data);
  });
}

function readJsonBody(req, maxBytes = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > maxBytes) { reject(Object.assign(new Error('Body too large'), { tooLarge: true })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) { resolve({}); return; }
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(Object.assign(new Error('Invalid JSON body'), { badJson: true })); }
    });
    req.on('error', reject);
  });
}

// Runs async fn(item) over items with at most `limit` in flight at once,
// preserving input order in the results. resolve-projects and preview both
// make 1-4 live, read-only ProjectDox calls PER project - running that
// sequentially made a bulk action of a few hundred projects slow enough to
// trip a reverse-proxy timeout (surfacing as a generic "failed, try again"
// in the UI) well before the request itself was rejected for being too
// large. Any error a worker throws (e.g. SessionExpiredError) rejects the
// overall Promise.all the same way a plain sequential await-in-a-loop
// would, so callers don't need special handling here.
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

// Minimal CSRF defense for an internal tool with no CORS headers exposed:
// every mutating call must be same-origin JSON carrying this custom header,
// which a cross-site <form> post can't attach and a cross-site fetch can't
// attach without triggering a CORS preflight this server doesn't allow.
function hasCsrfHeader(req) {
  return req.headers['x-bulk-tool'] === '1';
}

// Wraps a handler that needs a valid session; converts pdx.js's typed
// errors into clean HTTP responses instead of leaking stack traces.
function withSession(handler) {
  return async (req, res, url) => {
    const session = getSession(req);
    if (!session) { sendJson(res, 401, { ok: false, reason: 'not_logged_in' }); return; }
    try {
      await handler(req, res, url, session);
    } catch (e) {
      if (e.sessionExpired || e.serviceUnavailable) {
        // Every handler below does its actual work through pdx.withSaSession
        // (the shared SA service account), which already retries once on a
        // stale cached SA session - if SessionExpiredError still reaches
        // here, that retry ALSO failed, or PROJECTDOX_ADMIN_EMAIL/PASSWORD
        // aren't configured at all (.serviceUnavailable) - either way it
        // means the SA credentials themselves are the problem, not the
        // staff member's own login. So this deliberately does NOT clear
        // their cookie/log them out the way it used to when this really did
        // mean "your own session expired" - that would just send them back
        // to a login screen that re-passes the role check and hits the same
        // error again.
        console.error(`bulk-add-account-server: SA service account unavailable (staff=${session.email}): ${e.message}`);
        sendJson(res, 200, { ok: false, reason: 'service_unavailable' });
        return;
      }
      if (e.forbidden) { sendJson(res, 403, { ok: false, reason: 'forbidden' }); return; }
      if (e.badGroup) { sendJson(res, 400, { ok: false, reason: 'bad_group' }); return; }
      console.error(`bulk-add-account-server: ${req.method} ${url.pathname} failed: ${e.stack || e.message}`);
      sendJson(res, 200, { ok: false, reason: 'error', message: e.message });
    }
  };
}

// requireUserId=true for the remove flow, which always acts on an existing
// account (Group/RemoveProjectGroupsUser needs a real userID, not an email).
function validAccountPayload(account, requireUserId) {
  if (!account || typeof account !== 'object') return null;
  const email = String(account.email || '').trim();
  const firstName = String(account.firstName || '').trim();
  const lastName = String(account.lastName || '').trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return null;
  if (!firstName || !lastName) return null;
  if (email.length > 200 || firstName.length > 100 || lastName.length > 100) return null;
  const out = { email, firstName, lastName };
  if (requireUserId) {
    const userId = parseInt(account.userId, 10);
    if (!userId) return null;
    out.userId = userId;
  }
  return out;
}

// Checked separately from (and before) validProjectsPayload so a caller who
// selected too many projects gets a specific, actionable reason back instead
// of the same generic "invalid_request" as a malformed payload - this is
// what a staff member hit as a confusing "Preview failed, try again" before
// this was split out.
function tooManyProjects(res, rawProjects) {
  if (Array.isArray(rawProjects) && rawProjects.length > MAX_PROJECTS_PER_REQUEST) {
    sendJson(res, 400, { ok: false, reason: 'too_many_projects', max: MAX_PROJECTS_PER_REQUEST });
    return true;
  }
  return false;
}

function validProjectsPayload(projects) {
  if (!Array.isArray(projects) || !projects.length || projects.length > MAX_PROJECTS_PER_REQUEST) return null;
  const out = [];
  for (const p of projects) {
    const projectId = parseInt(p && p.projectId, 10);
    const projectName = String((p && p.projectName) || '').trim();
    if (!projectId || !projectName) return null;
    const row = { projectId, projectName };
    // Only meaningful for the remove flow's apply call: the specific
    // group(s) a prior /api/preview (action:'remove') already confirmed this
    // account actually belongs to on this project.
    if (Array.isArray(p.groups)) row.groups = p.groups.filter((g) => typeof g === 'string').slice(0, pdx.ALLOWED_GROUPS.length);
    out.push(row);
  }
  return out;
}

// Whether a reverse proxy in front of this process (e.g. cPanel's Node.js
// Selector/Passenger, mounting this app at a subpath like
// "/ePlan-Account-Manager") strips that prefix from req.url before this
// code ever sees it, or leaves it in, isn't knowable ahead of a real
// deployment - so every route matches the request path's SUFFIX rather than
// requiring an exact match, which is correct either way: a prefix-preserving
// proxy hands us "/ePlan-Account-Manager/api/login", a prefix-stripping one
// hands us "/api/login" - both end with "/api/login". index.html's own
// fetch() calls cooperate by using relative paths ("api/login", never
// "/api/login"), so the browser always computes the right full URL for
// whatever subpath the page itself loaded from.
function routeIs(pathname, route) {
  return pathname === route || pathname.endsWith(route);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');

  (async () => {
    if (req.method === 'GET' && routeIs(url.pathname, '/copb-logo.png')) { sendFile(res, LOGO_PATH, 'image/png'); return; }

    if (req.method === 'GET' && !url.pathname.includes('/api/')) {
      if (url.pathname === '/' || url.pathname.endsWith('/')) { sendFile(res, PAGE_PATH, 'text/html; charset=utf-8'); return; }
      // Confirmed live 2026-09-28 (scrapcraft.dev/ePlan-Account-Manager, no
      // trailing slash, 404d): the proxy in front of this app preserves the
      // FULL external path rather than stripping the mount prefix, so this
      // app's own root arrives as e.g. "/ePlan-Account-Manager" with no
      // trailing slash - which matched neither "/" nor routeIs() suffixes
      // and fell through to the generic 404 below. Redirect to add the
      // trailing slash (how a normal directory request behaves) instead of
      // 404ing the app's own root; the browser re-requests and hits the
      // branch above. This app has no other pages, so any GET that isn't an
      // /api/* call or the logo gets this same treatment.
      res.writeHead(301, { Location: url.pathname + '/' + url.search, 'Cache-Control': 'no-store' });
      res.end();
      return;
    }

    if (req.method === 'GET' && routeIs(url.pathname, '/api/session')) {
      const session = getSession(req);
      if (!session) { sendJson(res, 200, { ok: false }); return; }
      sendJson(res, 200, { ok: true, email: session.email, fullName: session.fullName, isSystemAdmin: !!session.isSystemAdmin });
      return;
    }

    if (req.method === 'POST' && routeIs(url.pathname, '/api/login')) {
      const ip = clientIp(req);
      if (loginRateLimited(ip)) { sendJson(res, 429, { ok: false, reason: 'rate_limited' }); return; }
      let body;
      try { body = await readJsonBody(req); } catch (e) { sendJson(res, 400, { ok: false, reason: 'bad_request' }); return; }
      const email = String(body.email || '').trim();
      const password = String(body.password || '');
      if (!email || !password) { sendJson(res, 400, { ok: false, reason: 'missing_credentials' }); return; }
      try {
        const { sessionId, userId } = await pdx.login(email, password);

        // Account authority is checked HERE, before any session cookie is
        // issued - not deferred to the first privileged call a staff member
        // happens to make. A valid ProjectDox login alone isn't enough; the
        // account must hold the role this tool's own API calls require.
        let authorized;
        try {
          authorized = await pdx.hasRequiredRole(sessionId);
        } catch (e2) {
          pdx.logout(sessionId);
          // Also to console (not just the audit log file) so this is visible
          // wherever this process's stdout/stderr ends up (e.g. cPanel's
          // Node app log viewer) without having to open the JSONL log file.
          console.error(`bulk-add-account-server: role check failed for ${email}: ${e2.status ? 'HTTP ' + e2.status + ' ' : ''}${e2.message}`);
          auditLog({ event: 'login_check_error', attemptedEmail: email, ip, error: e2.message, status: e2.status });
          sendJson(res, 200, { ok: false, reason: 'unavailable' });
          return;
        }
        if (!authorized) {
          pdx.logout(sessionId);
          auditLog({ event: 'login_denied_insufficient_role', attemptedEmail: email, ip });
          sendJson(res, 200, { ok: false, reason: 'not_authorized' });
          return;
        }

        // Separate from the SA-or-PA check above: the Activity Log is
        // SA-only, so this determines specifically whether THIS account is
        // SA (not just "authorized to use the tool at all"). Best-effort -
        // an inconclusive result (network hiccup, unexpected error) just
        // hides the log rather than blocking login over a secondary,
        // lower-stakes permission check.
        const isSystemAdmin = await pdx.isSystemAdministrator(sessionId, email).catch(() => false);

        const profile = await pdx.getUser(sessionId, userId).catch(() => ({ fullName: email }));
        const token = crypto.randomBytes(32).toString('hex');
        sessions.set(token, {
          pdxSessionId: sessionId,
          userId,
          email: profile.email || email,
          fullName: profile.fullName || email,
          isSystemAdmin,
          createdAt: Date.now(),
          lastActivity: Date.now()
        });
        setSessionCookie(req, res, token);
        auditLog({ event: 'login', staffEmail: profile.email || email, ip, isSystemAdmin });
        sendJson(res, 200, { ok: true, email: profile.email || email, fullName: profile.fullName || email, isSystemAdmin });
      } catch (e) {
        auditLog({ event: 'login_failed', attemptedEmail: email, ip });
        sendJson(res, 200, { ok: false, reason: 'invalid_credentials' });
      }
      return;
    }

    if (req.method === 'POST' && routeIs(url.pathname, '/api/logout')) {
      const session = getSession(req);
      if (session) { sessions.delete(session.token); pdx.logout(session.pdxSessionId); }
      clearSessionCookie(req, res);
      sendJson(res, 200, { ok: true });
      return;
    }

    // Read-only audit trail of who's used this tool and what they did with
    // it - reads the same data/bulk-add-account-log/*.jsonl files auditLog()
    // already writes for every login attempt and every add/remove outcome.
    // SA-only (not the general SA-or-PA gate everything else here uses) -
    // enforced HERE, not just by hiding the tab client-side, since the tab
    // being hidden is only a UI convenience and a PA account could otherwise
    // hit these routes directly.
    if (req.method === 'GET' && routeIs(url.pathname, '/api/audit-log-dates')) {
      await withSession(async (req, res, url, session) => {
        if (!session.isSystemAdmin) { sendJson(res, 403, { ok: false, reason: 'forbidden' }); return; }
        sendJson(res, 200, { ok: true, dates: listAuditLogDates() });
      })(req, res, url);
      return;
    }

    if (req.method === 'GET' && routeIs(url.pathname, '/api/audit-log')) {
      await withSession(async (req, res, url, session) => {
        if (!session.isSystemAdmin) { sendJson(res, 403, { ok: false, reason: 'forbidden' }); return; }
        const requested = url.searchParams.get('date') || '';
        const date = DATE_RE.test(requested) ? requested : new Date().toISOString().slice(0, 10);
        sendJson(res, 200, { ok: true, date, entries: readAuditLog(date) });
      })(req, res, url);
      return;
    }

    if (req.method === 'GET' && routeIs(url.pathname, '/api/search-users')) {
      await withSession(async (req, res, url, session) => {
        const keyword = (url.searchParams.get('keyword') || '').trim().slice(0, 100);
        if (keyword.length < 2) { sendJson(res, 200, { ok: true, users: [] }); return; }
        const users = await pdx.withSaSession((sa) => pdx.searchUsers(sa, keyword, 20));
        sendJson(res, 200, { ok: true, users });
      })(req, res, url);
      return;
    }

    if (req.method === 'GET' && routeIs(url.pathname, '/api/user-projects')) {
      await withSession(async (req, res, url, session) => {
        const userId = parseInt(url.searchParams.get('userID'), 10);
        if (!userId) { sendJson(res, 400, { ok: false, reason: 'missing_userID' }); return; }
        const { items, totalRowsCount, truncated } = await pdx.withSaSession((sa) => pdx.getUserProjectMemberships(sa, userId));

        // Group/GetUserGroupMembership itself doesn't return description/
        // location, so this enriches each row with one extra live call per
        // UNIQUE project (a project can appear twice if the account is in
        // two groups on it - fetched once, applied to both rows). Capped
        // independently of the 2000-row membership cap above so a very
        // large account still responds in bounded time - projects beyond
        // the cap just show without a description/location line, same as
        // any other project this tool doesn't have that detail for.
        const ENRICH_LIMIT = 300;
        const uniqueIds = Array.from(new Set(items.map((it) => it.projectId))).slice(0, ENRICH_LIMIT);
        const details = new Map();
        await mapLimit(uniqueIds, PREVIEW_CONCURRENCY, async (projectId) => {
          try {
            const d = await pdx.withSaSession((sa) => pdx.getProjectDetails(sa, projectId));
            if (d) details.set(projectId, d);
          } catch (e) {
            if (e.sessionExpired || e.forbidden || e.serviceUnavailable) throw e;
            // any other lookup failure just leaves this one project without a sub-line
          }
        });
        const enrichedItems = items.map((it) => {
          const d = details.get(it.projectId);
          return d ? { ...it, description: d.description, location: d.location } : it;
        });

        sendJson(res, 200, { ok: true, items: enrichedItems, totalRowsCount, truncated });
      })(req, res, url);
      return;
    }

    if (req.method === 'POST' && routeIs(url.pathname, '/api/resolve-projects')) {
      if (!hasCsrfHeader(req)) { sendJson(res, 403, { ok: false, reason: 'csrf' }); return; }
      await withSession(async (req, res, url, session) => {
        let body;
        try { body = await readJsonBody(req); } catch (e) { sendJson(res, 400, { ok: false, reason: 'bad_request' }); return; }
        if (tooManyProjects(res, body.inputs)) return;
        const inputs = Array.isArray(body.inputs) ? body.inputs : [];
        if (!inputs.length) { sendJson(res, 200, { ok: true, results: [] }); return; }
        const results = await mapLimit(inputs, PREVIEW_CONCURRENCY, (raw) =>
          pdx.withSaSession((sa) => pdx.resolveProject(sa, String(raw).slice(0, 64))));
        sendJson(res, 200, { ok: true, results });
      })(req, res, url);
      return;
    }

    if (req.method === 'POST' && routeIs(url.pathname, '/api/preview')) {
      if (!hasCsrfHeader(req)) { sendJson(res, 403, { ok: false, reason: 'csrf' }); return; }
      await withSession(async (req, res, url, session) => {
        let body;
        try { body = await readJsonBody(req); } catch (e) { sendJson(res, 400, { ok: false, reason: 'bad_request' }); return; }
        if (tooManyProjects(res, body.projects)) return;
        const action = body.action === 'remove' ? 'remove' : 'add';
        const account = validAccountPayload(body.account, action === 'remove');
        const projects = validProjectsPayload(body.projects);
        if (!account || !projects) { sendJson(res, 400, { ok: false, reason: 'invalid_request' }); return; }

        let rows;
        if (action === 'remove') {
          rows = await mapLimit(projects, PREVIEW_CONCURRENCY, (project) =>
            pdx.withSaSession((sa) => pdx.previewRemoveOne(sa, project, account.userId)));
        } else {
          const groupName = body.groupName;
          if (!pdx.ALLOWED_GROUPS.includes(groupName)) { sendJson(res, 400, { ok: false, reason: 'invalid_request' }); return; }
          rows = await mapLimit(projects, PREVIEW_CONCURRENCY, (project) =>
            pdx.withSaSession((sa) => pdx.previewAddOne(sa, project, groupName, account.email)));
        }
        sendJson(res, 200, { ok: true, rows });
      })(req, res, url);
      return;
    }

    if (req.method === 'POST' && routeIs(url.pathname, '/api/apply')) {
      if (!hasCsrfHeader(req)) { sendJson(res, 403, { ok: false, reason: 'csrf' }); return; }
      await withSession(async (req, res, url, session) => {
        let body;
        try { body = await readJsonBody(req); } catch (e) { sendJson(res, 400, { ok: false, reason: 'bad_request' }); return; }
        if (tooManyProjects(res, body.projects)) return;
        const action = body.action === 'remove' ? 'remove' : 'add';
        const account = validAccountPayload(body.account, action === 'remove');
        const projects = validProjectsPayload(body.projects);
        const accountMode = body.accountMode === 'existing' ? 'existing' : 'new';
        if (!account || !projects) { sendJson(res, 400, { ok: false, reason: 'invalid_request' }); return; }
        if (action === 'add' && !pdx.ALLOWED_GROUPS.includes(body.groupName)) {
          sendJson(res, 400, { ok: false, reason: 'invalid_request' });
          return;
        }

        // Unlike preview (read-only, parallelized above), apply performs
        // real writes - stays sequential on purpose to avoid hammering
        // ProjectDox with concurrent mutations and to keep the audit log
        // (and a mid-batch failure's blast radius) easy to reason about.
        const rows = [];
        for (const project of projects) {
          if (action === 'remove') {
            // Each project may carry more than one group to remove from (the
            // rare case of being added twice, once per group) - previewRemoveOne
            // already resolved exactly which allowed group(s) this account is
            // actually in, so apply just walks that list rather than guessing.
            const groupsToRemove = Array.isArray(project.groups) && project.groups.length
              ? project.groups.filter((g) => pdx.ALLOWED_GROUPS.includes(g))
              : [];
            if (!groupsToRemove.length) {
              rows.push({ projectId: project.projectId, projectName: project.projectName, outcome: 'error' });
              auditLog({
                event: 'apply', action: 'remove',
                staffEmail: session.email, staffUserId: session.userId,
                targetEmail: account.email, targetFirstName: account.firstName, targetLastName: account.lastName,
                targetUserId: account.userId,
                projectId: project.projectId, projectName: project.projectName, groupName: null, outcome: 'error',
                error: 'no_allowed_groups_in_preview_result'
              });
              continue;
            }
            for (const groupName of groupsToRemove) {
              let outcome;
              try {
                const removed = await pdx.withSaSession((sa) => pdx.removeAccountFromProjectGroup(sa, {
                  projectName: project.projectName,
                  groupName,
                  userId: account.userId
                }));
                outcome = removed ? 'removed' : 'not_removed';
              } catch (e) {
                if (e.sessionExpired || e.forbidden || e.serviceUnavailable) throw e;
                outcome = 'error';
              }
              rows.push({ projectId: project.projectId, projectName: project.projectName, groupName, outcome });
              auditLog({
                event: 'apply', action: 'remove',
                staffEmail: session.email, staffUserId: session.userId,
                targetEmail: account.email, targetFirstName: account.firstName, targetLastName: account.lastName,
                targetUserId: account.userId,
                projectId: project.projectId, projectName: project.projectName, groupName, outcome
              });
            }
          } else {
            let outcome;
            try {
              const added = await pdx.withSaSession((sa) => pdx.addAccountToProjectGroup(sa, {
                projectName: project.projectName,
                groupName: body.groupName,
                email: account.email,
                firstName: account.firstName,
                lastName: account.lastName
              }));
              outcome = added ? 'added' : 'not_added';
            } catch (e) {
              if (e.sessionExpired || e.forbidden || e.serviceUnavailable) throw e;
              outcome = 'error';
            }
            rows.push({ projectId: project.projectId, projectName: project.projectName, outcome });
            auditLog({
              event: 'apply', action: 'add',
              staffEmail: session.email, staffUserId: session.userId, accountMode,
              targetEmail: account.email, targetFirstName: account.firstName, targetLastName: account.lastName,
              projectId: project.projectId, projectName: project.projectName, groupName: body.groupName, outcome
            });
          }
        }
        sendJson(res, 200, { ok: true, rows });
      })(req, res, url);
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  })().catch((e) => {
    console.error(`bulk-add-account-server: unhandled error: ${e.stack || e.message}`);
    try { sendJson(res, 500, { ok: false, reason: 'unavailable' }); } catch (e2) { /* response likely already sent */ }
  });
});

server.listen(PORT, () => {
  console.log(`Bulk-add-account tool on http://localhost:${PORT}`);
  console.log('Staff log in with their own ProjectDox credentials (checked against the SA/PA role requirement),');
  console.log('but all actual ProjectDox calls run under the shared PROJECTDOX_ADMIN_EMAIL/PASSWORD service account.');
  if (!process.env.PROJECTDOX_ADMIN_EMAIL || !process.env.PROJECTDOX_ADMIN_PASSWORD) {
    console.warn('WARN: PROJECTDOX_ADMIN_EMAIL/PASSWORD are not set - staff will be able to log in, but every actual');
    console.warn('      action (search, resolve, preview, apply) will fail with "service_unavailable" until these are set.');
  }
});
