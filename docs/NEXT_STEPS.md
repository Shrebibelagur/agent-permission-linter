# Next steps (resume here)

Status: Phases 1-2 done, scan CLI + reports done, report wording fix done (9a1340c).
Next: Phase 3, Entra collector in MOCK mode. Classifier v2 and held-out set #3 after that.

To resume:
  cd ~\Documents\projects\agent-permission-linter\agent-permission-linter
  .\.venv\Scripts\Activate.ps1
  claude        (check /status shows the subscription, not the API key)

## Prompt for Claude Code
Phase 3: Entra collector, MOCK MODE FIRST. One commit per step, pytest after each.
1. src/apl/collectors/entra.py. Read-only. Token via the OAuth2 client-credentials
   flow with direct REST (POST to the tenant token endpoint, scope
   https://graph.microsoft.com/.default) using httpx. Never ClientSecretCredential.
   Credentials from env vars only (TENANT_ID, CLIENT_ID, CLIENT_SECRET). The token
   lives in memory only and is never logged or written. A guard must reject any
   HTTP method other than GET, with a test.
2. Collect: applications (with passwordCredentials/keyCredentials expiry), service
   principals, oauth2PermissionGrants (delegated scopes), appRoleAssignments
   (application permissions), owners. Handle @odata.nextLink pagination and
   retry 429/5xx honouring Retry-After. VERIFY endpoints and field names against
   the current Microsoft Graph docs and cite the URLs in ASSUMPTIONS.md.
   Sign-in activity (beta endpoint) is optional and marked unverified.
3. Mock mode: tests/fixtures/graph/*.json shaped like real Graph responses.
   `apl scan --entra-mock tests/fixtures/graph` uses them with no network.
   Live mode `--entra` requires the env vars and prints a read-only notice.
4. Link: match a server credential's entra_app_id to the Entra app, fill
   granted_scopes, and let APL-001 evaluate. Add src/apl/scopemap.py:
   capability -> minimum Graph permission for a small set (Mail, Files, Calendars,
   User, Directory, Application). Cite the Graph permissions reference. Mark the
   table "suggested mapping".
5. Tests: an over-scoped mail app (Mail.ReadWrite where only read is needed),
   a correctly scoped app, an app with no owner, an unknown scope (skip with reason).
6. Redaction test: a planted fake client secret must not appear anywhere.
Stop after item 6. Do not add rules 003-006 or 009 yet.
