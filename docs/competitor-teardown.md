# Competitor teardown (draft)

Date: 2026-11-04. Offline runs on three synthetic fixtures. No live servers contacted, no real tenant data.

Tools: mcp-audit-scanner 0.26.0 (static config scan), Cisco MCP Scanner 4.8.7 (static, YARA analyzer only), apl 0.1.0.dev0.

## Different questions
- Cisco MCP Scanner: is this tool malicious (poisoning, injection)?
- mcp-audit: is this config risky (secrets, unpinned installs, exfiltration paths)?
- apl: does this agent hold more access than its job needs (tools -> Entra identity -> least privilege)?

## Results
| Fixture | apl | mcp-audit | Cisco (YARA) |
|---|---|---|---|
| clean | 0 findings (3 checks ran, 3 not evaluated) | 7 (5 excluding first-scan baseline notes): HIGH npx -y, MEDIUM runtime fetch, unpinned npx, no-auth remote | none |
| entra | 9 (3 high, 4 medium, 2 low): scope broader than needed, no owner, credential expiry/lifetime, unjustified high-risk permission | 18 (10 excluding baseline notes): 2 HIGH file-read + email exfiltration paths, 8 LOW unrecognised binary; no identity findings | none |
| claude_desktop | 0 findings, nothing evaluated | 17 (14 excluding baseline notes): plaintext secret in config, CVEs, CRITICAL exfiltration paths | none |

## Where apl is ahead
- Entra identity: ownership, credential lifecycle, scope vs tool need. Neither other tool reads this data.
- Note: on the entra fixture apl was given extra inputs (agent.yaml, saved Graph data) that the others cannot read.

## Where apl is behind
- Config hygiene: mcp-audit reports a plaintext secret, silent npx -y installs, unpinned versions and known CVEs. apl reports none of these.
- apl evaluated nothing on the claude_desktop fixture (no agent file, no Entra data).
- apl printed a prompt-injection warning for one tool but only in the terminal, not as a report finding.

## Limits of this comparison
- Three synthetic fixtures, authored for apl. Not a benchmark.
- Cisco ran YARA only (no API or LLM analyzer). 25 of 30 tools had no description and were first skipped as incomplete; placeholder text was added to those so it could scan.
- One tool carries a blatant injection phrase. Cisco YARA did not flag it, apl warned. One sample only: no claim about Cisco in general.
- mcp-audit static mode only sees tool descriptions stored in the config file; live tool metadata needs --connect, which was not used.
- apl's skipped checks are by design: it needs Entra data (--entra or --entra-mock), an agent.yaml and an auto-approve list in the config, and it names what is missing. The claude_desktop run had none of those inputs, so it shows what apl does without identity data, not what it can do with it.

## Backlog from this
1. Report prompt-injection warnings as findings.
2. Check for plaintext secrets in client configs.
3. Check for npx -y and unpinned package versions.



