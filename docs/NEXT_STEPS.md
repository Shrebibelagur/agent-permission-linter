# Next steps (resume here)

Done: Phases 1-3 (mock), rules APL-001/002/004/005/006/007/010, scan CLI + reports, Entra collector (mock),
R2 severity fix, classifier v2 (schema signals), APL-001 hardening. 998 tests (997 pass, 1 skipped), pushed to main.

Next, in this order:
1. Live Entra test in the lab tenant (read-only app: Application.Read.All + Directory.Read.All,
   secret via Read-Host, never in a file, delete the secret/app afterwards).
2. Rules APL-003, 009 (Entra data).
3. Held-out set #4 from real MCP tool lists (blind, measure once). Sets #1-#3 are dev sets.
4. Phase 4 reasoning agent, then CI/packaging and docs.
5. Report prompt-injection warnings as findings in the report; currently a parser warning only (Markdown/JSON); not a finding, not in SARIF. (from competitor teardown 2026-11-04)
6. Check for plaintext secrets in MCP client configs. (from competitor teardown 2026-11-04)
7. Check for npx -y silent execution and unpinned package versions. (from competitor teardown 2026-11-04)
8. Name unused tools-file keys ("tools file entry 'other' matches no server"). (from Fri 13 batch)
9. Add "tools loaded: N" per server to the report. (from Fri 13 batch)

Known limits to put in the threat model: rename evasion (C3), trusted agreement (E7),
coarse "network" capability, parameters hidden in $ref/anyOf/oneOf/allOf, live mode untested.

To resume: cd to the project folder, activate .venv, git pull, then run claude.
