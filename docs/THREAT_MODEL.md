# Threat model (v0.1.0)

What `apl` protects, who it protects it from, how, the test that proves each mitigation, and what
is still open. Entry ids such as R19 or E7 point to [ASSUMPTIONS.md](ASSUMPTIONS.md). "Guard" means
an entry in [tools/mutation/mutants.py](../tools/mutation/mutants.py): the harness breaks it on
purpose and checks that a test fails. The last full run broke 94 guards and caught 94 (R19).

## What `apl` is

A linter that works from local files, with an optional read-only (GET-only) Graph read. It reads MCP client configs, an optional `agent.yaml` (the declared purpose),
saved `tools/list` results and, optionally, Entra data through Microsoft Graph. It reports agents
whose granted capability exceeds what their purpose needs. It never starts or contacts an MCP
server and never writes to Entra.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Secrets in configs: tokens, API keys, PATs, webhook URLs | config `env`, `args`, `headers`, `url` | A leak in a report hands out the credential |
| The scanner's Graph client secret and access token | process memory only | Read access to the whole directory |
| Tenant, client and object ids | configs, Graph responses | Say whose tenant a report is about; let someone holding a report confirm a guess |
| The id salt (`APL_ID_SALT` or the salt file) | env or user config dir | With it, pseudonyms can be reversed by guessing |
| Display, server, agent and owner names | configs, `agent.yaml`, Graph | Identify an organisation when `--anonymise-names` is used |
| The findings themselves | reports, exit code | A hidden finding is a false "all clear" in CI |
| The tenant and the scanning machine | — | The scanner must not change the first or run code on the second |

## Trust boundaries

| Source | Trust | Why |
|---|---|---|
| Command-line flags, the user's environment | trusted | The operator runs the tool |
| MCP client config | **trusted for structure, untrusted for values** | Written by the operator, but may hold secrets and pasted text |
| `agent.yaml` | trusted as the operator's declaration | It is the purpose being checked against. Its free text is printed as written |
| **A server's own `tools/list`**: names, descriptions, `inputSchema`, annotations | **untrusted** | Written by the server being judged. It has every reason to look harmless |
| Microsoft Graph responses | **untrusted data** | Tenant-controlled: display names, scope values and `@odata.nextLink` are written by tenant admins or other apps (G9) |
| Graph token endpoint | trusted for the token only | Its free-text `error_description` is never printed (G1) |

The core rule: **a server's description of itself is never evidence that it is safe.** Descriptions
are never read for classification, and every server-written signal can only add capability.

## Attacker goals

1. **Hide a finding.** A malicious or careless MCP server, or a tenant admin, shapes its data so a
   real over-privilege is reported as a low review or not at all.
2. **Leak a secret.** Get a token, key, client secret, salt or secret URL path into a report, log,
   error or traceback that will be shared, committed or uploaded to a SARIF viewer.
3. **Leak an identifier.** Get a full tenant, client or object id, or a name hidden by
   `--anonymise-names`, into default output.
4. **Use the scanner as a tool.** Make `apl` write to Entra, send its bearer token off Graph, or run
   or contact an MCP server.
5. **Inject instructions.** Put text in a description or schema that steers a reader or a future LLM
   layer.

## Mitigations

### Hide a finding (goal 1)

| Mitigation | Proof |
|---|---|
| Descriptions are never used to classify (S6) | [`test_description_ignored`](../tests/test_classifier.py) |
| Annotations only add capabilities; `readOnlyHint` cannot downgrade (S5) | [`test_read_only_hint_cannot_downgrade`](../tests/test_classifier.py), [`test_schema_never_removes_a_capability`](../tests/test_classifier_schema.py) |
| Unknown verbs are `unknown` + "review required", never guessed safe (C1) | [`test_unknown_verb_is_unclassified_not_guessed`](../tests/test_classifier.py), [`test_unknown_verb_with_read_only_hint_still_unclassified`](../tests/test_classifier.py) |
| A schema conflict takes the widest set and stays above the 0.5 review line, so adding a `content` parameter cannot soften `delete_*` (C2) | [`test_conflict_cannot_be_used_to_dodge_a_verdict`](../tests/test_classifier_schema.py), [`test_weak_write_never_lowers_a_riskier_name`](../tests/test_classifier_schema.py), [`test_weak_write_cannot_soften_a_strong_conflict`](../tests/test_classifier_schema.py) |
| Agreement cannot lift an uncertain tool over the line (C2) | [`test_agreement_cannot_lift_an_uncertain_tool`](../tests/test_classifier_schema.py), [`test_annotations_do_not_restore_confidence_for_read_leaning_run`](../tests/test_classifier.py) |
| APL-001: a low-confidence, conflicted or annotation-only signal is a *possible* need. It can turn a violation into a review, never into no finding (R4, E7) | In [tests/rules/test_apl001.py](../tests/rules/test_apl001.py): `test_one_text_parameter_gives_review_not_no_finding`, `test_low_confidence_tool_cannot_soften_a_scope_it_cannot_need`, `test_annotation_cannot_launder_a_conflict`, `test_annotation_cannot_launder_a_weak_write`, `test_get_status_url_with_mail_send_is_review_not_no_finding` |
| Uncertain tools give `review_required`, which still counts toward `--fail-on` (R6, R11) | [`test_unclassified_tool_is_review_not_violation`](../tests/rules/test_apl007.py), [`test_threshold_boundaries`](../tests/test_scan_cli.py) |
| Unclassified auto-approved tools count as high-impact (R8) | [`test_unclassified_tool_counts_as_high_impact`](../tests/rules/test_apl010.py) |
| A rule missing its input says "not evaluated", and a report never says "no findings" when nothing ran (R12) | [tests/test_report_markdown.py](../tests/test_report_markdown.py), [`test_skip_missing_declared_purpose`](../tests/rules/test_apl007.py) |
| Graph is recognised only by its well-known appId, never by display name, so a custom API's `Mail.Read` cannot pass as Graph's (G9) | [tests/rules/test_entra_link.py](../tests/rules/test_entra_link.py), [tests/test_entra_scenarios.py](../tests/test_entra_scenarios.py) |
| An unresolved app role or a failed owners call is a visible skip, not a pass (G5, R13) | [`test_graph_403_on_one_object_is_a_clean_skip`](../tests/test_no_leaks.py), [tests/rules/test_apl004.py](../tests/rules/test_apl004.py) |
| A non-complete `tools/list` result is rejected, so a truncated list cannot pass as the whole (S3) | [`test_non_complete_result_type_rejected_without_echo`](../tests/test_tools_list.py) |

### Leak a secret (goal 2)

| Mitigation | Proof |
|---|---|
| Secrets are removed as `[REDACTED]` at parse time; env values are never stored, only names | [`test_no_secret_survives_serialization`](../tests/test_mcp_config.py), [`test_redact_patterns`](../tests/test_redact_untrusted.py); guard *exact secret removal* |
| Every output passes `scrub()` again: md, json, sarif, `--out`, `apl inventory`, CLI messages, logs, crash text (R19) | [tests/test_no_leaks.py](../tests/test_no_leaks.py) plants a secret and ids and checks every output in mock and live scans, five failures and one real process; guards *md / json / sarif not scrubbed*, *stderr messages not scrubbed*, *inventory not scrubbed*, *--out writes unscrubbed data*, *log scrub not installed* |
| The exact client secret and access token are scrubbed even if they match no pattern (G12) | [tests/test_entra_redaction.py](../tests/test_entra_redaction.py); guards *client secret not remembered*, *access token not remembered* |
| `secretText`, `hint`, `key` and Graph error bodies are never copied (G3, G12) | [`test_uncopied_fields_do_not_depend_on_the_exact_scrub`](../tests/test_entra_redaction.py), [`test_graph_failure_body_is_never_echoed`](../tests/test_entra_redaction.py) |
| Crashes keep only the exception type name; no locals, no chained request (R19, G12) | [`test_crash_keeps_its_type_name_and_loses_its_values`](../tests/test_error_scrubbing.py), [`test_unexpected_crash_prints_no_locals`](../tests/test_entra_redaction.py), [`test_network_error_does_not_chain_the_request`](../tests/test_entra_client.py); guards *crash guard off*, *crash keeps raw message* |
| Parse errors do not echo file content | [`test_invalid_json_error_does_not_echo_content`](../tests/test_mcp_config.py) |
| URLs print as `scheme://host/[path-redacted]`; userinfo and query strings always go (R21) | [tests/test_safe_urls.py](../tests/test_safe_urls.py); guards *urls not shortened*, *--show-urls keeps the query*, *--show-urls keeps userinfo*, *allowlist matches by substring* |
| Random-looking tokens in `command` and `args` are redacted, with no flag to bring them back (R22) | [tests/test_random_tokens.py](../tests/test_random_tokens.py); guards *arg tokens not redacted*, *command tokens not redacted*, *entropy check off* |
| The salt is scrubbed like a secret | [`test_salt_is_scrubbed_like_a_secret`](../tests/test_idmask.py); guard *salt not scrubbed* |
| `--show-ids` never turns off secret removal | [`test_show_ids_leaves_ids_and_still_removes_secrets`](../tests/test_id_exact_redaction.py); guard *--show-ids disables secrets* |

### Leak an identifier or name (goal 3)

| Mitigation | Proof |
|---|---|
| Ids print as salted pseudonyms (`app-3f9a1c`), HMAC-SHA256 under a per-install salt (R19) | [tests/test_idmask.py](../tests/test_idmask.py); guards *known ids not replaced*, *GUID fallback off*, *Graph path guard off*, *token endpoint guard off*, *unsalted pseudonyms* |
| No usable salt stops the scan; raw ids are never the fallback | [`test_short_salt_fails_closed`](../tests/test_idmask.py), [`test_unwritable_salt_location_fails_closed`](../tests/test_idmask.py), [`test_no_salt_withholds_the_message_rather_than_printing_it`](../tests/test_error_scrubbing.py) |
| `--show-ids` and `--show-urls` warn on stderr, mark the report itself, and end with the command | [tests/test_real_ids_marker.py](../tests/test_real_ids_marker.py), [tests/test_show_ids.py](../tests/test_show_ids.py), [`test_flag_does_not_outlive_the_command`](../tests/test_safe_urls.py); guards *--show-ids outlives the command*, *md / json / sarif marker missing*, *url marker missing in md* |
| `--anonymise-names` replaces display, server, agent and owner names, and `command`/`url`/`args` in inventory (R20) | [tests/test_anonymise_names.py](../tests/test_anonymise_names.py), [tests/test_anonymise_owner.py](../tests/test_anonymise_owner.py), [tests/test_anonymise_more.py](../tests/test_anonymise_more.py), [tests/test_anonymise_urls.py](../tests/test_anonymise_urls.py); guards *names not masked before render*, *command / url / args not masked* |
| Under `--anonymise-names`, a free-text notice on stderr and in the report | [tests/test_free_text_notice.py](../tests/test_free_text_notice.py); guards *free-text notice missing*, *limits line missing* |
| Owner ids and linked app ids are never dumped (`Evidence.app`, `MCPServer.entra_apps` excluded) (R17, G10) | [`test_app_identity_never_reaches_output`](../tests/test_finding_ids.py), [`test_no_full_id_in_any_format`](../tests/test_report_masking.py) |
| Tracked files outside `tests/fixtures/` hold no GUID that is not on an allowlist, and guard entries hold no GUID or known token prefix. `tests/fixtures/` is not scanned for ids, so nothing checks that its GUIDs are fake | [tools/release_check.py](../tools/release_check.py) fails on a GUID outside `tests/fixtures/` that is not on its allowlist; [`test_entries_hold_no_real_values`](../tests/test_mutation_entries.py) |

### Use the scanner as a tool (goal 4)

| Mitigation | Proof |
|---|---|
| No `apply` command; no Graph write call exists | [tests/test_entra_client.py](../tests/test_entra_client.py) |
| The Graph transport refuses everything but `GET https://graph.microsoft.com/...`, so a hostile `@odata.nextLink` cannot receive the token (G1) | [`test_guard_rejects_every_method_except_get`](../tests/test_entra_client.py), [`test_guard_never_sends_the_token_off_graph`](../tests/test_entra_client.py), [`test_transport_is_the_guard_not_a_helper_method`](../tests/test_entra_client.py), [`test_invalid_next_link_does_not_escape_with_its_url`](../tests/test_error_scrubbing.py) |
| The tenant value cannot redirect the token request | [`test_tenant_cannot_change_the_token_url`](../tests/test_entra_client.py) |
| Credentials come from the environment only, via OAuth2 client credentials over REST; no Azure Identity SDK | [`test_credentials_from_env`](../tests/test_entra_client.py), [`test_no_azure_identity_sdk`](../tests/test_entra_client.py) |
| `--connect` is refused with exit 2: no MCP server is started or contacted | [`test_connect_refused`](../tests/test_scan_cli.py) |
| The guard harness itself runs in a temp copy with an allowlisted environment, so real credentials cannot reach it | [`test_real_credentials_do_not_reach_the_tests`](../tests/test_mutation_entries.py), [`test_every_home_points_into_the_copy`](../tests/test_mutation_entries.py) |

### Inject instructions (goal 5)

| Mitigation | Proof |
|---|---|
| Descriptions are dropped after an injection-marker scan, which raises a warning; schema `default` and `enum` values are never read (C2) | [`test_injection_in_descriptions_changes_nothing`](../tests/test_classifier_schema.py), [`test_injection_text_is_not_kept_anywhere_from_the_schema`](../tests/test_classifier_schema.py), [`test_schema_injection_raises_the_inventory_warning`](../tests/test_classifier_schema.py) |
| A parameter named like an instruction is matched as vocabulary, not obeyed | [`test_instruction_as_a_parameter_name_is_matched_not_obeyed`](../tests/test_classifier_schema.py) |
| Untrusted text for any future LLM layer is wrapped in random delimiters, with look-alikes neutralised (`src/apl/untrusted.py`) | [`test_wrap_untrusted_neutralizes_delimiters`](../tests/test_redact_untrusted.py), [`test_injection_detection`](../tests/test_redact_untrusted.py) |

## Known limits

These are open. Each is a way an attacker can still reach a goal above.

1. **Rename evasion (goal 1; C3).** The tool name is server-chosen. On a read-only purpose,
   `run_pipeline` is an APL-007 high violation and `run_report` is a low review at confidence 0.5.
   Renaming a tool to a read-leaning or unknown name softens the verdict. It is not hidden: the
   review still prints and counts toward `--fail-on` at its own severity. The confidence difference
   is pinned by `test_run_with_another_noun_stays_execute` and
   `test_run_on_a_read_noun_is_read_leaning_with_low_confidence` in
   [tests/test_classifier.py](../tests/test_classifier.py). A name that is plainly a read
   (`get_status`) for a tool that writes is not caught at all.
2. **Trusted agreement (goal 1; E7).** When the name and the schema agree, the tool is trusted.
   `browse_status(url)` with `Mail.Send` gives no finding, because on a `browse` name a `url`
   parameter agrees rather than conflicts. A server that lies consistently in its name and its
   parameters cannot be told apart from an honest one. No test pins this case.
3. **Coarse network capability (goal 1).** `network` means "data can cross the network boundary".
   It does not say where to, so a tool that posts to a fixed internal service and one that posts to
   any URL look the same, and `Mail.Send` is justified by any confident network tool on the server.
4. **Hidden parameters (goal 1; C2).** Schema signals do not follow `$ref`, `anyOf`, `oneOf` or
   `allOf`. Parameters there are not seen, and a server can omit or rename parameters, so a clean
   schema proves nothing.
5. **Free text (goals 2, 3; R20).** `purpose`, `justification` text and `env_keys` print as written,
   with only registered names replaced. A secret or a company name typed into them prints.
   `--anonymise-names` says so on stderr and in the report.
6. **Scheme-less URLs (goal 2; R21).** `hooks.example.test/<secret-path>` has no scheme, so it is not
   recognised as a URL and its path prints. No test pins this case.
7. **Secrets with no known shape (goal 2; R22, G12).** Low-entropy secrets, single-case hex, anything
   under 20 characters, anything split by separators, and exact-match secrets under 8 characters are
   missed. Pinned as known misses in [tests/test_random_tokens.py](../tests/test_random_tokens.py).
8. **Pseudonymous, not anonymous (goal 3; R19, R20).** Permission names (including custom ones that
   name the organisation), tool names, env var and header names, and config paths still print.
   Pseudonyms are 24 bits and can be confirmed by anyone who holds the salt.
9. **Identifier shapes (goal 3; R19).** Only exact known values, GUID shapes and known Graph paths
   are matched. An id that is split, encoded or not a GUID is not.
10. **Process-wide log scrub (goals 2, 3; R19).** Code that replaces the log record factory after
    `apl` installs it, or writes straight to stderr, bypasses it. In-memory objects hold raw values.
11. **Classifier accuracy is unmeasured (goal 1; E5, E7).** Every corpus in the repo has been used for
    development, so no current number is an accuracy number. See the README's limits section.
12. **Live Entra mode is untested (goal 4).** `--entra` has been tested only against Graph-shaped
    fixtures, not a real tenant (G section header).
13. **Guard harness proves "some test fails", not "the right test fails" (R19).**
