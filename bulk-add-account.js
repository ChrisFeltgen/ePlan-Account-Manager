// Staff bulk-add-account tool: core ProjectDox API wrapper.
//
// AUTH MODEL (changed 2026-09-29 - see the SA session section below for the
// full story): staff still log in with their OWN ProjectDox email/password,
// and login still requires that account to hold System Administrator or
// Project Administrator rights (hasRequiredRole). That staff login is used
// for IDENTITY and AUTHORIZATION only, and for nothing else - confirmed live
// that a real Project Administrator account, despite passing that same role
// check, gets refused by other calls this tool needs (ProjectDox's own "SA
// or PA" claims in its API docs don't hold up in practice on this instance).
// So every actual DATA operation (search, resolve, preview, apply) runs
// under a separate, shared System Administrator session instead - identity
// and audit trail are still per-staff-member via the server's own log
// (staffEmail/staffUserId, populated from the staff member's own login),
// but the ProjectDox calls themselves always have SA-level access no matter
// which staff member is driving the tool. This means the credential this
// process holds in memory (PROJECTDOX_ADMIN_EMAIL/PASSWORD) is now
// SA-level, same as collector.js/permit-status.js's admin fallback - a
// compromise of this process's environment is no longer scoped to "whatever
// one staff member's own account could do".
//
// Deliberately kept isolated from collector.js/permit-status.js (own tiny
// fetch helpers, no shared module) for the same reason permit-status.js
// gives for its own isolation: this file can make real write calls
// (Group/InviteProjectGroupsUser) against production project security, so a
// bug here must never be able to reach through to the read-only tools, or
// vice versa.
//
// Endpoints used (confirmed live against this ProjectDox instance on
// 2026-09-28 via its self-hosted /Help/Api pages before writing this file -
// see the ProjectDox API catalog memory):
//   - Project/GetProjectByName - resolve a pasted project number to a
//     ProjectID/Name/Status. 500s with DataItemNotFoundException for a
//     nonexistent project (not a clean 404) - same quirk permit-status.js
//     already works around.
//   - Group/GetProjectGroups?projectID= - list of a project's groups
//     (GroupID/Name/...), used only to confirm the target project actually
//     has an "Applicant"/"View Only Public" group before offering it.
//   - User/GetActiveUsers?fieldsToSearch[]=&keyword=&orderBy=&maxRecords= -
//     keyword search across chosen user fields. Docs say "Session user must
//     be a System Administrator or Project Administrator" - a staff account
//     without that role will get a 401/403 here, surfaced to the UI as a
//     permission error rather than a generic failure.
//   - Group/GetUserGroupMembership?userID=&PageIndex=&PageSize= - despite
//     its doc description ("active projects for the session user"), this
//     was confirmed LIVE to actually respect the passed userID (tested
//     against both a real applicant account and the calling admin's own
//     different UserID, which returned different, correct-looking results
//     for each) - so it's safe to use for "projects THIS arbitrary user has
//     access to", which is exactly what the "copy from another account"
//     flow in the UI needs. Paged; some accounts on this instance have
//     hundreds of thousands of rows, so callers must always cap pages.
//   - User/GetProjectUsersLite?projectID= - lite per-project member list,
//     used only to flag "already has this access" in the preview step.
//   - Group/InviteProjectGroupsUser?projectName=&groupName=&userEmail=&
//     userFirstName=&userLastName= - "Invite a user into a project group.
//     If the user does not exist, the user will be created." This one call
//     covers BOTH the new-account and existing-account cases identically,
//     which is why apply() below has only one code path for both.
//   - Group/RemoveProjectGroupsUser?projectName=&groupName=&userID= (a GET,
//     despite mutating - that's how ProjectDox's own API defines it) -
//     "Removes the user from the project group." Symmetric name-based
//     counterpart to InviteProjectGroupsUser, used for the bulk-remove flow.
//     Needs a real userID (not email), so remove only ever operates on an
//     existing account resolved via search.
//
// SECURITY: the two allowed group names are hardcoded below and enforced on
// every call in this file, never taken from a caller-supplied string as-is -
// this tool must never be usable to add someone to an internal review group
// (BUILDING DIVISION, Management, etc.), only Applicant/View Only Public.

const BASE_URL = 'https://pompanobeach-fl-us-projectdoxwebapi.avolvecloud.com';

const ALLOWED_GROUPS = Object.freeze(['Applicant', 'View Only Public']);

function assertAllowedGroup(groupName) {
  if (!ALLOWED_GROUPS.includes(groupName)) {
    const err = new Error(`Group "${groupName}" is not permitted through this tool.`);
    err.badGroup = true;
    throw err;
  }
}

class SessionExpiredError extends Error {
  constructor() { super('ProjectDox session expired or invalid.'); this.sessionExpired = true; }
}
class PermissionError extends Error {
  constructor(pathAndQuery) { super(`Not permitted: ${pathAndQuery}`); this.forbidden = true; }
}

// Low-level GET/POST against the ProjectDox REST API using an already-
// established SessionID. No auto-relogin (unlike collector.js/permit-
// status.js, which cache a single service-account password to relogin
// with) - this tool deliberately never retains a staff member's password
// past the single POST /User/Login call, so a 401 here always means "ask
// them to log in again", not "silently retry".
async function pdxRequest(sessionId, method, pathAndQuery, jsonBody) {
  const opts = { method, headers: { SessionID: sessionId } };
  if (jsonBody !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(jsonBody);
  }
  const res = await fetch(`${BASE_URL}/${pathAndQuery}`, opts);
  if (res.status === 401) throw new SessionExpiredError();
  if (res.status === 403) throw new PermissionError(pathAndQuery);
  if (!res.ok) {
    let body = '';
    try { body = await res.text(); } catch (e) { /* best-effort only */ }
    if (res.status === 500 && /DataItemNotFoundException/i.test(body)) {
      const notFound = new Error(`${pathAndQuery}: no matching record`);
      notFound.notFound = true;
      throw notFound;
    }
    // Confirmed live 2026-09-28 (via a real low-privilege test account
    // hitting User/GetActiveUsers): ProjectDox throws a plain, unhandled
    // System.Exception for "you're logged in fine but your role doesn't
    // allow this call" - surfaced as HTTP 500 ("Invalid access to Active
    // Users, you do not have rights"), not 401/403 like a normal API would.
    // Reclassified as the same PermissionError every caller already knows
    // how to handle (including the login-time role check in
    // hasRequiredRole), rather than every caller needing to know about this
    // specific ProjectDox quirk.
    if (res.status === 500 && /you do not have rights/i.test(body)) {
      throw new PermissionError(pathAndQuery);
    }
    const err = new Error(`${pathAndQuery} HTTP ${res.status}: ${body.slice(0, 300)}`);
    err.status = res.status;
    throw err;
  }
  const text = await res.text();
  if (!text) return null;
  return JSON.parse(text);
}
const pdxGet = (sessionId, pathAndQuery) => pdxRequest(sessionId, 'GET', pathAndQuery);
const pdxPost = (sessionId, pathAndQuery, body) => pdxRequest(sessionId, 'POST', pathAndQuery, body);

// --- auth ------------------------------------------------------------------

// Logs in with a STAFF member's own ProjectDox credentials. Throws on bad
// credentials (caller should show "invalid email or password", never
// distinguish which one was wrong).
async function login(email, password) {
  const res = await fetch(`${BASE_URL}/User/Login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ Email: email, Password: password })
  });
  if (!res.ok) {
    const err = new Error(`Login HTTP ${res.status}`);
    err.badCredentials = res.status === 400 || res.status === 401;
    throw err;
  }
  const data = await res.json();
  if (!data.SessionID || !data.UserID) {
    const err = new Error('Login response missing SessionID/UserID.');
    err.badCredentials = true;
    throw err;
  }
  return { sessionId: data.SessionID, userId: parseInt(data.UserID, 10) };
}

async function logout(sessionId) {
  try { await pdxPost(sessionId, 'User/Logout'); } catch (e) { /* best-effort only */ }
}

async function getUser(sessionId, userId) {
  const u = await pdxGet(sessionId, `User/GetUser?userID=${userId}`);
  return {
    userId,
    firstName: trimmed(u.FirstName) || '',
    lastName: trimmed(u.LastName) || '',
    fullName: trimmed(u.FullName) || `${trimmed(u.FirstName) || ''} ${trimmed(u.LastName) || ''}`.trim(),
    email: trimmed(u.Email) || ''
  };
}

// Confirms the just-logged-in account actually holds the ProjectDox role
// this whole tool depends on (User/GetActiveUsers and User/GetProjectUsersLite
// both require "System Administrator or Project Administrator" per their own
// docs). Without this check, ANY valid ProjectDox account - an Applicant, a
// contractor, anyone with a working password - could log into this staff
// tool and see the full UI; the only thing that previously stopped them was
// the first search call failing, which the server was mapping to a generic
// "session expired" (ProjectDox was observed returning 401, not 403, for a
// role check failure on some calls - indistinguishable from a truly expired
// session by status code alone) - a confusing dead end, not an access
// boundary, and it let an unauthorized account poke around the rest of the
// UI (project resolution, "copy from account", etc.) before hitting it.
// This makes the role check happen ONCE, at login, before any session
// cookie is ever issued. Reuses the cheapest real call this tool already
// needs (a 1-result user search) rather than guessing at JWT role claims,
// which weren't confirmed to reliably distinguish PA from a regular user.
async function hasRequiredRole(sessionId) {
  try {
    await searchUsers(sessionId, 'a', 1);
    return true;
  } catch (e) {
    if (e.forbidden || e.sessionExpired) return false;
    // Confirmed live (2026-09-28) that a plain 401 is one real shape
    // ProjectDox uses for "this account can't do this", but a real
    // low-privilege test account also produced a call that landed here
    // instead - i.e. neither .forbidden (403) nor .sessionExpired (401) -
    // meaning the actual status wasn't one of those two. Any OTHER 4xx
    // (400/404/etc.) from GetActiveUsers almost certainly still means "this
    // request/account isn't permitted" rather than a server malfunction, so
    // it's classified the same way. Only a 5xx or a connection-level
    // failure (no HTTP status at all - pdxRequest only sets e.status on an
    // HTTP error) is genuinely inconclusive and re-thrown as "couldn't
    // verify" rather than "not authorized".
    if (typeof e.status === 'number' && e.status >= 400 && e.status < 500) return false;
    throw e;
  }
}

// Distinguishes System Administrator specifically from "SA or PA" (which
// hasRequiredRole above already confirmed) - used to gate the Activity Log
// to SA-only. Reuses User/GetUserByEmail, which ProjectDox's own docs say
// requires SA specifically ("stricter" than GetActiveUsers's "SA or PA" -
// confirmed in the API catalog memory, never independently verified live
// against a real PA account since none was available to test with). Called
// with the staff member's OWN email/session at login time - since every
// actual data operation now runs through the shared SA session instead
// (see withSaSession below), this is one of the only remaining uses of a
// staff member's own session after login, alongside hasRequiredRole.
async function isSystemAdministrator(sessionId, email) {
  try {
    await pdxGet(sessionId, `User/GetUserByEmail?email=${encodeURIComponent(email)}`);
    return true;
  } catch (e) {
    if (e.forbidden || e.sessionExpired) return false;
    if (typeof e.status === 'number' && e.status >= 400 && e.status < 500) return false;
    throw e; // genuinely inconclusive (5xx/network) - caller decides how to treat this
  }
}

// --- shared SA service-account session --------------------------------------
// Every actual data operation in this file (search/resolve/preview/apply)
// runs under this session, NOT the staff member's own login session - see
// the top-of-file comment for why. Mirrors the cached-session/relogin-once
// pattern permit-status.js already uses for its own service account.

let cachedSaSessionId = null;
let saLoginInFlight = null;

function saCredentials() {
  const email = process.env.PROJECTDOX_ADMIN_EMAIL;
  const password = process.env.PROJECTDOX_ADMIN_PASSWORD;
  if (!email || !password) {
    const err = new Error('PROJECTDOX_ADMIN_EMAIL / PROJECTDOX_ADMIN_PASSWORD are not set - this tool cannot make any ProjectDox API calls without them.');
    // Same client-facing "service_unavailable" outcome as a stale SA session
    // that failed even after a relogin retry - both mean "this tool can't
    // reach ProjectDox right now", not "your own login is the problem".
    err.serviceUnavailable = true;
    throw err;
  }
  return { email, password };
}

async function getSaSessionId() {
  if (cachedSaSessionId) return cachedSaSessionId;
  if (!saLoginInFlight) {
    const { email, password } = saCredentials();
    saLoginInFlight = login(email, password)
      .then(({ sessionId }) => sessionId)
      .finally(() => { saLoginInFlight = null; });
  }
  cachedSaSessionId = await saLoginInFlight;
  return cachedSaSessionId;
}

// Runs fn(saSessionId) against the cached SA session, transparently logging
// in again and retrying ONCE if the cached session had expired (mirrors the
// "call once, relogin on 401, retry once" pattern already established in
// Upload-ProjectDoxFolder.ps1/permit-status.js) - callers never see a stale
// SA session as a reason to bounce the STAFF member back to a login screen,
// since it has nothing to do with their own login.
async function withSaSession(fn) {
  const sessionId = await getSaSessionId();
  try {
    return await fn(sessionId);
  } catch (e) {
    if (!e.sessionExpired) throw e;
    cachedSaSessionId = null;
    const retrySessionId = await getSaSessionId();
    return await fn(retrySessionId);
  }
}

// --- small shared helpers ---------------------------------------------------

// This database right-pads CHAR-typed columns with spaces (same quirk
// documented in permit-status.js/collector.js).
function trimmed(s) {
  return typeof s === 'string' ? (s.trim() || null) : s;
}

// Real project-number prefixes in use on this instance, confirmed live
// 2026-09-28 against the full Projects table: BP (144k, Building Permit),
// PZ (2.1k, Planning & Zoning), CE (1.1k, Code Enforcement), FP (88, Fire
// Prevention), CR (1, Courtesy Review). permit-status.js only ever deals
// with BP by design (it's explicitly BP-scoped), but this tool is not, so
// it must not silently assume BP.
//
// "22-7052" -> "BP22-00007052" convention only safely generalizes to BP/FP/CR:
// those three all zero-pad a plain sequence number to 8 digits
// (confirmed: "FP21-00003829", "CR18-00007767"). PZ/CE do NOT follow that
// pattern - their middle segment encodes a case-type code the bare shorthand
// can't recover (confirmed real examples: "PZ14-04000005", "CE23-65000035" -
// simply zero-padding "5" or "35" to 8 digits would guess "PZ14-00000005",
// which is wrong). So a bare "YY-N" shorthand is only ever expanded against
// BP/FP/CR; a PZ or CE project must be typed out in full.
const SHORT_FORM_SAFE_PREFIXES = ['BP', 'FP', 'CR'];

function candidateNames(input) {
  const candidates = [input];
  const m = input.match(/^(\d{2})-(\d+)$/);
  if (m) {
    for (const prefix of SHORT_FORM_SAFE_PREFIXES) {
      candidates.push(`${prefix}${m[1]}-${m[2].padStart(8, '0')}`);
    }
  }
  return candidates;
}

// --- user search / lookup ---------------------------------------------------

const SEARCH_FIELDS = ['FirstName', 'LastName', 'Email', 'Company'];

async function searchUsers(sessionId, keyword, maxRecords = 20) {
  const fieldsQs = SEARCH_FIELDS.map((f, i) => `fieldsToSearch[${i}]=${encodeURIComponent(f)}`).join('&');
  const qs = `${fieldsQs}&keyword=${encodeURIComponent(keyword)}&orderBy=LastName&maxRecords=${maxRecords}`;
  const users = await pdxGet(sessionId, `User/GetActiveUsers?${qs}`);
  return (Array.isArray(users) ? users : []).map((u) => ({
    userId: u.UserID,
    firstName: trimmed(u.FirstName) || '',
    lastName: trimmed(u.LastName) || '',
    fullName: trimmed(u.FullName) || `${trimmed(u.FirstName) || ''} ${trimmed(u.LastName) || ''}`.trim(),
    email: trimmed(u.Email) || '',
    company: trimmed(u.Company) || '',
    revoked: !!u.Revoked
  }));
}

// Confirmed live: GetUserGroupMembership's own doc description ("active
// projects for the session user") does NOT match its real behavior - it
// genuinely filters by the passed userID. Some accounts on this instance
// have 600k+ membership rows, so this always caps total pages pulled and
// reports back whether it was truncated.
const MEMBERSHIP_PAGE_SIZE = 200;
const MEMBERSHIP_MAX_PAGES = 10; // caps a single lookup at 2000 rows

async function getUserProjectMemberships(sessionId, userId) {
  const items = [];
  let totalRowsCount = 0;
  for (let page = 0; page < MEMBERSHIP_MAX_PAGES; page++) {
    const data = await pdxGet(
      sessionId,
      `Group/GetUserGroupMembership?userID=${userId}&PageIndex=${page}&PageSize=${MEMBERSHIP_PAGE_SIZE}`
    );
    totalRowsCount = data.TotalRowsCount || 0;
    const pageItems = data.Items || [];
    for (const it of pageItems) {
      items.push({
        projectId: it.ProjectID,
        projectName: trimmed(it.ProjectName) || '',
        groupId: it.GroupID,
        groupName: trimmed(it.GroupName) || ''
      });
    }
    if (pageItems.length < MEMBERSHIP_PAGE_SIZE) break; // last page
    if (items.length >= totalRowsCount) break;
  }
  // De-dupe by (projectId, groupName) - a user can show up more than once
  // per project in edge cases (e.g. legacy rows).
  const seen = new Set();
  const deduped = [];
  for (const it of items) {
    const key = `${it.projectId}:${it.groupName}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(it);
  }
  return { items: deduped, totalRowsCount, truncated: totalRowsCount > items.length };
}

// Single-project lookup by ID (not name) - used to enrich a
// getUserProjectMemberships() result with description/location, which
// Group/GetUserGroupMembership itself doesn't return. Same shape/quirks as
// resolveProject()'s Project/GetProjectByName call (right-padded CHAR
// columns), just addressed by the ID the membership row already has instead
// of guessing at a name.
async function getProjectDetails(sessionId, projectId) {
  const p = await pdxGet(sessionId, `Project/GetProject?projectID=${projectId}`);
  if (!p) return null;
  return { description: trimmed(p.Description), location: trimmed(p.Location), status: trimmed(p.Status) };
}

// --- project resolution / groups --------------------------------------------

async function resolveProject(sessionId, rawInput) {
  const input = (rawInput || '').trim();
  if (!input) return { ok: false, input: rawInput, reason: 'empty' };
  for (const name of candidateNames(input)) {
    let p;
    try {
      p = await pdxGet(sessionId, `Project/GetProjectByName?projectName=${encodeURIComponent(name)}`);
    } catch (e) {
      if (e.notFound) continue; // try the next candidate spelling, if any
      throw e;
    }
    if (p && p.ProjectID) {
      return {
        ok: true,
        input: rawInput,
        projectId: p.ProjectID,
        projectName: trimmed(p.Name),
        status: trimmed(p.Status),
        // Right-padded CHAR columns on this database (same quirk documented
        // in permit-status.js/collector.js) - trimmed() strips the padding.
        description: trimmed(p.Description),
        location: trimmed(p.Location)
      };
    }
  }
  return { ok: false, input: rawInput, reason: 'not_found' };
}

// Map<groupName, groupID> for one project. GroupID for the same-named group
// differs per project (confirmed live - "Applicant" was GroupID 5 on one
// project, 1567721 on another), so callers must always resolve fresh per
// project rather than caching a GroupID across projects.
async function getProjectGroups(sessionId, projectId) {
  const groups = await pdxGet(sessionId, `Group/GetProjectGroups?projectID=${projectId}`);
  const map = new Map();
  for (const g of (Array.isArray(groups) ? groups : [])) map.set(trimmed(g.Name), g.GroupID);
  return map;
}

// Members of ONE specific group on ONE project. Deliberately NOT
// User/GetProjectUsersLite (which lists everyone on the project at once) -
// confirmed live 2026-09-28 that its GroupID field is always null on this
// instance regardless of the real data (ProjectID/ProjectTemplateID come
// back null too), so it cannot be used to tell which group a member is
// actually in. User/GetGroupUsersLite?groupID=&projectID=, despite having
// the same null GroupID/ProjectID quirk on each returned row, DOES correctly
// filter the LIST itself to just that group's members (confirmed live
// against a known real Applicant) - so group membership must always be
// checked by calling this once per group, never by filtering a whole-project
// member list on its GroupID field.
async function getGroupMembersLite(sessionId, projectId, groupId) {
  const users = await pdxGet(sessionId, `User/GetGroupUsersLite?groupID=${groupId}&projectID=${projectId}`);
  return (Array.isArray(users) ? users : []).map((u) => ({
    userId: u.UserID,
    email: (trimmed(u.Email) || '').toLowerCase()
  }));
}

// --- preview / apply: add ----------------------------------------------------

// For each requested project: confirms the project exists, confirms it
// actually offers the requested group (not every project template is
// guaranteed to have "View Only Public" configured), and flags whether the
// target email already appears on that project at all (informational only -
// InviteProjectGroupsUser is safe to call again either way).
async function previewAddOne(sessionId, project, groupName, targetEmail) {
  assertAllowedGroup(groupName);
  const row = { projectId: project.projectId, projectName: project.projectName };
  try {
    const groups = await getProjectGroups(sessionId, project.projectId);
    const groupId = groups.get(groupName);
    if (groupId == null) {
      return { ...row, ok: false, reason: 'group_not_available' };
    }
    const members = await getGroupMembersLite(sessionId, project.projectId, groupId);
    const already = members.some((m) => m.email === targetEmail.toLowerCase());
    return { ...row, ok: true, alreadyMember: already };
  } catch (e) {
    if (e.sessionExpired || e.forbidden) throw e;
    return { ...row, ok: false, reason: 'check_failed', error: e.message };
  }
}

async function addAccountToProjectGroup(sessionId, { projectName, groupName, email, firstName, lastName }) {
  assertAllowedGroup(groupName);
  const qs = `projectName=${encodeURIComponent(projectName)}&groupName=${encodeURIComponent(groupName)}` +
    `&userEmail=${encodeURIComponent(email)}&userFirstName=${encodeURIComponent(firstName)}&userLastName=${encodeURIComponent(lastName)}`;
  const result = await pdxPost(sessionId, `Group/InviteProjectGroupsUser?${qs}`);
  return result === true;
}

// --- preview / apply: remove --------------------------------------------------

// Removal never takes a caller-supplied group - it AUTO-DETECTS which of the
// two allowed groups (if any) this userID actually belongs to on this
// project, and reports both if somehow in both (rare edge case: someone
// added twice, once per group). This avoids the failure mode of a staff
// member picking "View Only Public" to remove someone who's actually only in
// "Applicant", which would silently do nothing.
async function previewRemoveOne(sessionId, project, userId) {
  const row = { projectId: project.projectId, projectName: project.projectName };
  try {
    const groups = await getProjectGroups(sessionId, project.projectId);
    const matchedGroups = [];
    for (const groupName of ALLOWED_GROUPS) {
      const groupId = groups.get(groupName);
      if (groupId == null) continue;
      const members = await getGroupMembersLite(sessionId, project.projectId, groupId);
      if (members.some((m) => m.userId === userId)) matchedGroups.push(groupName);
    }
    if (!matchedGroups.length) return { ...row, ok: false, reason: 'not_a_member' };
    return { ...row, ok: true, groups: matchedGroups };
  } catch (e) {
    if (e.sessionExpired || e.forbidden) throw e;
    return { ...row, ok: false, reason: 'check_failed', error: e.message };
  }
}

async function removeAccountFromProjectGroup(sessionId, { projectName, groupName, userId }) {
  assertAllowedGroup(groupName);
  const qs = `projectName=${encodeURIComponent(projectName)}&groupName=${encodeURIComponent(groupName)}&userID=${userId}`;
  const result = await pdxGet(sessionId, `Group/RemoveProjectGroupsUser?${qs}`);
  return result === true;
}

module.exports = {
  ALLOWED_GROUPS,
  SessionExpiredError,
  PermissionError,
  login,
  logout,
  getUser,
  hasRequiredRole,
  isSystemAdministrator,
  withSaSession,
  searchUsers,
  getUserProjectMemberships,
  getProjectDetails,
  resolveProject,
  getProjectGroups,
  previewAddOne,
  addAccountToProjectGroup,
  previewRemoveOne,
  removeAccountFromProjectGroup
};
