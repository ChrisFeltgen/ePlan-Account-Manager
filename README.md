## Summary
- Staff web tool for bulk-adding/removing ProjectDox accounts on projects (Applicant / View Only Public groups)
- Staff log in individually for identity/role checks (SA or PA); all actual ProjectDox data operations route through a shared SA service account (PROJECTDOX_ADMIN_EMAIL/PASSWORD env vars), since PA accounts can't call some ProjectDox APIs directly
- SA-only in-app Activity Log viewer, backed by JSONL audit logs
- Includes the built/deployed copy under deploy/ePlan-Account-Manager/ (what's actually uploaded to scrapcraft.dev via cPanel)
