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

## Privacy and supply-chain roadmap (from 2026-11-14 threat-model review)

10. Extend redactor to agent.yaml free-text fields (purpose, justification, env_keys). 0.2.0.
11. Add --extra-secret-patterns flag for user-supplied regex. 0.2.0.
12. Integrate gitleaks for broader secret-shape coverage. 0.3.0.
13. Add --strict flag: refuse --show-ids / --show-urls, no raw IDs or URLs ever. 0.2.0.
14. Record pseudonymised tenant ID in report header. 0.3.0.
15. Warn or refuse if TENANT_ID differs from a previously-seen tenant on the same install. 0.3.0.
16. Store salt in OS keyring (Windows Credential Manager, macOS Keychain, libsecret). File fallback for CI. 0.3.0.
17. Argon2 or scrypt KDF on salt load; apl id-salt rotate command. 0.4.0.

## Supply-chain hardening

18. CycloneDX SBOM output on release. 0.2.0.
19. Sigstore signing on release wheels and tags via GitHub Actions. 0.2.0.
20. Reproducible build process. 0.3.0+.
21. Private vulnerability reporting enabled on repo. Done 2026-11-16.
22. Vulnerability disclosure process in SECURITY.md (response SLA, PGP key, acknowledgements). 0.2.0.
23. Third-party security audit. 1.0+ territory.