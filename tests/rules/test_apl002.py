import json

from builders import cred, inventory, server

from apl.models import AgentSpec, CredentialKind, Severity
from apl.rules.apl002_shared_credential import check


def agent(invokers="multiple"):
    return AgentSpec(name="bot", purpose="p", invokers=invokers)


def test_positive_pat_shared_by_many_is_maker_mode():
    res = check(inventory(server(creds=[cred()]), agent=agent()))
    (f,) = res.findings
    assert f.rule_id == "APL-002" and f.severity is Severity.HIGH and f.status == "violation"
    assert "Maker-mode" in f.title
    assert f.granted == ["fixed personal_access_token credential"]
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in f.fix
    assert {m.id for m in f.suggested_mappings} == {"ASI03", "LLM06:2025"}
    assert all(m.label == "suggested mapping" for m in f.suggested_mappings)


def test_positive_app_identity_is_shared_medium():
    c = cred(env="AZURE_CLIENT_SECRET", kind=CredentialKind.SERVICE_PRINCIPAL, source="inferred")
    (f,) = check(inventory(server("graph", creds=[c]), agent=agent())).findings
    assert f.severity is Severity.MEDIUM and "Shared credential" in f.title
    assert "inferred" in f.confidence_reason


def test_inferred_kind_lowers_confidence():
    v = check(inventory(server(creds=[cred()]), agent=agent())).findings[0]
    i = check(inventory(server(creds=[cred(source="inferred")]), agent=agent())).findings[0]
    assert i.confidence < v.confidence


def test_negative_single_invoker():
    res = check(inventory(server(creds=[cred()]), agent=agent("single")))
    assert res.findings == [] and res.skips == []


def test_negative_no_static_credential_and_identifier_only():
    app_id = cred(env="AZURE_CLIENT_ID", kind=CredentialKind.SERVICE_PRINCIPAL,
                  entra_app_id="00000000-0000-0000-0000-000000000001")
    res = check(inventory(server("remote"), server("graph", creds=[app_id]), agent=agent()))
    assert res.findings == []


def test_skip_missing_invokers():
    res = check(inventory(server(creds=[cred()]), agent=agent(None)))
    assert res.findings == []
    assert [s.reason for s in res.skips] == ["not evaluated: missing agent.yaml invokers"]


def test_skip_missing_agent_spec():
    res = check(inventory(server(creds=[cred()])))
    assert [s.reason for s in res.skips] == ["not evaluated: missing agent.yaml"]


def test_dirty_fixture_redacted(fix):
    from apl.inventory import build_inventory

    inv = build_inventory([fix / "configs/claude_desktop.json"])
    inv.agent = agent()
    res = check(inv)
    by = {f.subject: f for f in res.findings}
    assert by["github"].severity is Severity.HIGH
    assert by["graph"].severity is Severity.MEDIUM  # secret in argv, client id excluded
    dumped = json.dumps(res.model_dump(mode="json"))
    assert "ghp_FAKE" not in dumped and "8Q~FAKE" not in dumped


def test_clean_fixture_has_no_findings(clean_inventory):
    res = check(clean_inventory)
    assert res.findings == [] and res.skips == []
