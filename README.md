## Summary
- Staff web tool for bulk-adding/removing ProjectDox accounts on projects (Applicant / View Only Public groups)
- Staff log in individually for identity/role checks (SA or PA); all actual ProjectDox data operations route through a shared SA service account (PROJECTDOX_ADMIN_EMAIL/PASSWORD env vars), since PA accounts can't call some ProjectDox APIs directly
- SA-only in-app Activity Log viewer, backed by JSONL audit logs
- Includes the built/deployed copy under deploy/ePlan-Account-Manager/ (what's actually uploaded to scrapcraft.dev via cPanel)

## Test plan
- Verified live against real ProjectDox with SA credentials: login, search-users, user-projects, resolve-projects (including CSRF rejection and prefix tests), preview (add and remove), disallowed-group rejection
- Verified PA-login path returns clean `service_unavailable` when SA env vars are absent, rather than crashing
- Manual UI testing in-browser (mocked fetch) for search/select flows, theming, keyboard accessibility, audit log rendering
