import json
from datetime import UTC, datetime
from functools import partial

import pytest
from builders import cred, inventory, server

from apl.collectors.entra import collect_mock
from apl.models import AgentSpec, CredentialKind, EntraApp, ServerPurpose, Severity
from apl.parsers.agent_spec import load_agent_spec
from apl.parsers.mcp_config import ConfigParseError
from apl.report import render
from apl.rules.apl006_unjustified_permission import check
from apl.scan import run_scan

APP_ID = "a1a1a1a1-0000-4000-8000-000000000001"
PLANTED = "abc8Q~FAKEfakeFAKEfakeFAKEfakeFAKEfake00"


def agent(**justifications):
    """Keyword names use _ for the dots a permission name has."""
    table = {k.replace("_", "."): v for k, v in justifications.items()}
    return AgentSpec(name="bot", purpose="p", justifications=table)


def linked(spec, owner_ids=("u1",), **grants):
    app = EntraApp(
        app_id=APP_ID,
        display_name="agent",
        application_object_id="obj1",
        service_principal_id="sp1",
        owner_ids=None if owner_ids is None else list(owner_ids),
        **grants,
    )
    c = cred(kind=CredentialKind.SERVICE_PRINCIPAL, entra_app_id=APP_ID)
    inv = inventory(server("mail", creds=[c]), agent=spec)
    inv.servers[0].entra_apps = [app]
    inv.entra_source = "mock"
    return inv


def test_positive_no_justification():
    (f,) = check(linked(agent(), application_permissions=["Mail.Send"])).findings
    assert f.rule_id == "APL-006" and f.status == "violation"
    assert f.severity is Severity.MEDIUM and f.subject == "mail/Mail.Send"
    assert f.granted == ["Mail.Send (application)"]
    assert f.confidence == 0.95 and "agent.yaml" in f.confidence_reason
    assert f.evidence[0].pointer == "/servicePrincipals/sp1/appRoleAssignments"
    assert "permissions-reference#mailsend" in f.evidence[0].note
    assert {m.id for m in f.suggested_mappings} == {"NHI5:2025", "ASI03"}
    assert all(m.label == "suggested mapping" for m in f.suggested_mappings)


def test_no_owner_raises_severity_to_high():
    (f,) = check(linked(agent(), [], application_permissions=["Mail.Send"])).findings
    assert f.severity is Severity.HIGH and "no owner (APL-004)" in f.confidence_reason


def test_owner_data_not_collected_stays_medium():
    (f,) = check(linked(agent(), None, application_permissions=["Mail.Send"])).findings
    assert f.severity is Severity.MEDIUM and "APL-004" not in f.confidence_reason


def test_justified_permission_on_an_ownerless_app_does_not_fire():
    inv = linked(agent(Mail_Send="digest"), [], application_permissions=["Mail.Send"])
    assert check(inv).findings == []


@pytest.mark.parametrize("ownerless_first", [True, False])
def test_ownerless_app_decides_severity_whatever_the_app_order(ownerless_first):
    inv = linked(agent(), application_permissions=["Mail.Send"])
    owned = inv.servers[0].entra_apps[0]
    ownerless = owned.model_copy(update={"app_id": "other", "owner_ids": []})
    inv.servers[0].entra_apps = [ownerless, owned] if ownerless_first else [owned, ownerless]
    (f,) = check(inv).findings
    assert f.severity is Severity.HIGH and "other" in f.evidence[0].note


def test_positive_delegated_grant():
    (f,) = check(linked(agent(), delegated_per_user=["Directory.ReadWrite.All"])).findings
    assert f.granted == ["Directory.ReadWrite.All (delegated)"]
    assert f.evidence[0].pointer == "/oauth2PermissionGrants"


def test_positive_each_permission_needs_its_own_reason():
    inv = linked(agent(Mail_Send="digest"), application_permissions=["Mail.Send", "Mail.ReadWrite"])
    assert [f.subject for f in check(inv).findings] == ["mail/Mail.ReadWrite"]


@pytest.mark.parametrize("reason", ["", "   ", "\n"])
def test_positive_blank_reason_is_no_reason(reason):
    inv = linked(agent(Mail_Send=reason), application_permissions=["Mail.Send"])
    assert len(check(inv).findings) == 1


def test_same_permission_on_two_apps_of_a_server_is_one_finding():
    inv = linked(agent(), application_permissions=["Mail.Send"])
    other = inv.servers[0].entra_apps[0].model_copy(update={"app_id": "other"})
    inv.servers[0].entra_apps.append(other)
    assert len(check(inv).findings) == 1


def test_negative_justified():
    res = check(linked(agent(Mail_Send="digest"), application_permissions=["Mail.Send"]))
    assert res.findings == [] and res.skips == []
    assert [e.subject for e in res.evaluated] == ["mail"]


def test_negative_justification_name_ignores_case():
    inv = linked(
        AgentSpec(name="b", purpose="p", justifications={"mail.send": "digest"}),
        application_permissions=["Mail.Send"],
    )
    assert check(inv).findings == []


def test_negative_permission_is_not_high_risk():
    assert check(linked(agent(), application_permissions=["Mail.Read"])).findings == []


def test_negative_delegated_form_of_an_application_only_entry():
    assert check(linked(agent(), delegated_all_principals=["Mail.Send"])).findings == []


def test_negative_another_apis_scope():
    inv = linked(agent(), application_permissions=["Contoso API/Directory.ReadWrite.All"])
    assert check(inv).findings == []


def test_justification_does_not_cover_a_different_permission():
    inv = linked(agent(Mail_Read="triage"), application_permissions=["Mail.ReadWrite"])
    assert len(check(inv).findings) == 1


def test_skip_missing_agent_spec():
    inv = linked(None, application_permissions=["Mail.Send"])
    res = check(inv)
    assert res.findings == []
    assert [s.reason for s in res.skips] == ["not evaluated: missing agent.yaml"]


def test_skip_without_entra():
    c = cred(kind=CredentialKind.SERVICE_PRINCIPAL, entra_app_id=APP_ID)
    res = check(inventory(server("mail", creds=[c]), agent=agent()))
    assert res.findings == [] and res.evaluated == []
    assert [s.reason for s in res.skips] == [
        "not evaluated: missing granted permissions (run with --entra or --entra-mock)"
    ]


def test_skip_app_declared_in_agent_yaml_but_not_found():
    spec = AgentSpec(
        name="b", purpose="p", servers=[ServerPurpose(server="mail", entra_app_id=APP_ID)]
    )
    inv = inventory(server("mail"), agent=spec)
    inv.entra_source = "mock"
    assert check(inv).skips[0].reason == (
        "not evaluated: missing granted permissions (app not found in Entra)"
    )


def test_unresolved_app_role_is_skipped_not_passed():
    inv = linked(agent(), application_permissions=["unresolved-app-role-1234"])
    res = check(inv)
    assert res.findings == []
    (s,) = res.skips
    assert s.subject == "mail/unresolved-app-role-1234"
    assert s.reason == "not evaluated: missing permission name (unresolved in Graph)"


def test_unresolved_role_does_not_stop_the_rest():
    inv = linked(agent(), application_permissions=["unresolved-app-role-1", "Mail.Send"])
    res = check(inv)
    assert len(res.findings) == 1 and len(res.skips) == 1


def test_server_with_no_entra_link_is_out_of_scope():
    res = check(inventory(server("github", creds=[cred()]), agent=agent()))
    assert res.findings == [] and res.skips == [] and res.evaluated == []


def test_output_is_redacted():
    inv = linked(agent(), application_permissions=["Mail.Send"])
    inv.servers[0].entra_apps[0].display_name = f"agent {PLANTED}"
    assert PLANTED not in json.dumps(check(inv).model_dump(mode="json"))


def test_agent_yaml_mapping_is_optional_and_loaded(fix):
    assert load_agent_spec(fix / "clean/agent.yaml").justifications == {}
    spec = load_agent_spec(fix / "entra/agent.yaml")
    assert list(spec.justifications) == ["Mail.ReadWrite"]


def test_agent_yaml_rejects_a_reason_that_is_not_text(tmp_path):
    path = tmp_path / "a.yaml"
    path.write_text("name: a\npurpose: p\njustifications:\n  Mail.Send:\n", encoding="utf-8")
    with pytest.raises(ConfigParseError):
        load_agent_spec(path)


def test_clean_fixture_has_no_findings_or_skips(clean_inventory):
    res = check(clean_inventory)
    assert res.findings == [] and res.skips == []


@pytest.fixture
def scan(fix):
    d = fix / "entra"
    return run_scan(
        [d / "mcp.json"],
        d / "agent.yaml",
        [d / "tools.json"],
        entra=partial(collect_mock, fix / "graph"),
        now=datetime(2026, 11, 1, tzinfo=UTC),
    )


def test_end_to_end_only_the_unjustified_permission_fires(scan):
    """mail holds Mail.ReadWrite, justified in the fixture; mailer holds Mail.Send, not."""
    found = [f for f in scan.result.findings if f.rule_id == "APL-006"]
    assert [f.subject for f in found] == ["mailer/Mail.Send"]
    assert found[0].severity is Severity.HIGH  # ownerless-mailer also fires APL-004
    assert found[0].evidence[0].source == "entra-mock"
    assert found[0].id in render(scan, "md")


def test_end_to_end_well_managed_app_is_silent_on_every_rule(scan):
    assert not [f for f in scan.result.findings if f.subject.startswith("managed/")]
    assert any(e.rule_id == "APL-006" and e.subject == "managed" for e in scan.result.evaluated)
