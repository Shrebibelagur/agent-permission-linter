# Next steps (resume here)

Done: Phases 1-3 (mock), rules APL-001/002/004/005/006/007/010, scan CLI + reports, Entra collector (mock),
R2 severity fix, classifier v2 (schema signals), APL-001 hardening. 532 tests, pushed to main.

Next, in this order:
1. Live Entra test in the lab tenant (read-only app: Application.Read.All + Directory.Read.All,
   secret via Read-Host, never in a file, delete the secret/app afterwards).
2. Rules APL-003, 009 (Entra data).
3. Held-out set #4 from real MCP tool lists (blind, measure once). Sets #1-#3 are dev sets.
4. Phase 4 reasoning agent, then CI/packaging and docs.

Known limits to put in the threat model: rename evasion (C3), trusted agreement (E7),
coarse "network" capability, parameters hidden in $ref/anyOf/oneOf/allOf, live mode untested.

To resume: cd to the project folder, activate .venv, git pull, then run claude.
