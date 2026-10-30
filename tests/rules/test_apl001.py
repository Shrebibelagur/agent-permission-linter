import json

import pytest
from builders import cred, inventory, server, tool

from apl.models import CredentialKind, Evidence, Severity
from apl.rules.apl001_overscoped import check, scope_capabilities

READ_TOOLS = [tool("search_repositories"), tool("get_file_contents")]


def test_positive_scope_broader_than_tools():
    c = cred(granted_scopes=["repo", "delete_repo", "read:org"])
    res = check(inventory(server(tools=READ_TOOLS, creds=[c])))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "APL-001" and f.id.startswith("APL-001:")
    assert f.status == "violation" and f.severity is Severity.HIGH
    assert f.granted == ["repo", "delete_repo"]  # read:org is needed (tools read)
    assert f.required == ["read"]
    assert f.confidence == 0.9 and "verified" in f.confidence_reason
    assert {m.id for m in f.suggested_mappings} == {"LLM06:2025", "ASI03"}
    assert all(m.label == "suggested mapping" for m in f.suggested_mappings)
    assert f.fix and f.evidence


def test_graph_readwrite_with_read_only_tools():
    c = cred(env="AZURE_CLIENT_SECRET", granted_scopes=["User.ReadWrite.All", "User.Read.All"])
    res = check(inventory(server("graph", tools=[tool("listUsers")], creds=[c])))
    assert [f.granted for f in res.findings] == [["User.ReadWrite.All"]]


def test_inferred_kind_lowers_confidence():
    def run(source):
        c = cred(source=source, granted_scopes=["repo"])
        return check(inventory(server(tools=READ_TOOLS, creds=[c])))

    verified, inferred = run("verified"), run("inferred")
    v, i = verified.findings[0], inferred.findings[0]
    assert i.confidence < v.confidence
    assert "inferred" in i.confidence_reason
    assert i.status == "violation"


def test_negative_scope_matches_tools():
    tools = [*READ_TOOLS, tool("create_issue")]
    res = check(inventory(server(tools=tools, creds=[cred(granted_scopes=["repo", "read:org"])])))
    assert res.findings == [] and res.skips == []


def test_unclassified_tool_makes_it_review_not_violation():
    tools = [*READ_TOOLS, tool("frobnicate")]
    res = check(inventory(server(tools=tools, creds=[cred(granted_scopes=["delete_repo"])])))
    f = res.findings[0]
    assert f.status == "review_required" and f.confidence <= 0.4
    assert "unclassified" in f.confidence_reason


def test_skip_missing_granted_scopes():
    res = check(inventory(server(tools=READ_TOOLS, creds=[cred()])))
    assert res.findings == []
    assert [s.reason for s in res.skips] == [
        "not evaluated: missing granted scopes (run with --entra or --entra-mock)"
    ]


def test_skip_missing_tool_list():
    res = check(inventory(server(creds=[cred(granted_scopes=["repo"])])))
    assert res.findings == [] and res.skips[0].reason == "not evaluated: missing tool list"


def test_skip_unmapped_scope_but_other_scopes_evaluated():
    c = cred(granted_scopes=["mystery:scope", "delete_repo"])
    res = check(inventory(server(tools=READ_TOOLS, creds=[c])))
    assert res.findings[0].granted == ["delete_repo"]
    assert res.skips[0].reason == "not evaluated: missing scope mapping"
    assert res.skips[0].subject.endswith("mystery:scope")


def test_evidence_is_redacted():
    leak = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000"
    c = cred(granted_scopes=["delete_repo"]).model_copy(
        update={"evidence": Evidence(source="cfg.json", pointer="/x", note=f"value {leak}")}
    )
    res = check(inventory(server(tools=READ_TOOLS, creds=[c])))
    assert leak not in json.dumps(res.model_dump(mode="json"))


def graph_finding(scope, tools=("listUsers",)):
    c = cred(
        env="AZURE_CLIENT_ID",
        kind=CredentialKind.SERVICE_PRINCIPAL,
        granted_scopes=[scope] if isinstance(scope, str) else scope,
    )
    res = check(inventory(server("graph", tools=[tool(t) for t in tools], creds=[c])))
    return res.findings[0]


def test_corrected_user_readwrite_has_no_delete_and_still_write():
    assert scope_capabilities("User.ReadWrite") == {"write"}
    f = graph_finding("User.ReadWrite")
    assert f.severity is Severity.MEDIUM and "needs write." in f.fix


def test_corrected_permission_cannot_justify_a_delete_tool():
    f = graph_finding("User.ReadWrite", tools=("deleteUser",))
    assert f.granted == ["User.ReadWrite"]  # it does not grant what the tool needs


@pytest.mark.parametrize(
    "scope",
    [
        "Mail.ReadWrite",
        "Files.ReadWrite",
        "Files.ReadWrite.All",
        "Calendars.ReadWrite",
        "User.ReadWrite.All",
        "Directory.ReadWrite.All",  # service principals only: see ASSUMPTIONS R2
        "Application.ReadWrite.All",
        "Application.ReadWrite.OwnedBy",
    ],
)
def test_confirmed_delete_is_kept(scope):
    assert scope_capabilities(scope) == {"write", "delete"}
    f = graph_finding(scope)
    assert f.severity is Severity.HIGH and f.confidence == 0.9


def test_unverified_keeps_delete_with_lower_confidence():
    assert scope_capabilities("User.DeleteRestore.All") == {"delete"}
    f = graph_finding("User.DeleteRestore.All")
    assert f.severity is Severity.HIGH and f.status == "violation"
    assert f.confidence == 0.6
    assert "delete unverified in Graph docs for User.DeleteRestore.All" in f.confidence_reason


def test_verified_delete_alongside_keeps_full_confidence():
    f = graph_finding(["User.DeleteRestore.All", "Mail.ReadWrite"])
    assert f.confidence == 0.9 and "unverified" not in f.confidence_reason


def test_scope_table():
    assert scope_capabilities("Files.ReadWrite.All") == {"write", "delete"}
    assert scope_capabilities("User.Read") == {"read"}
    assert scope_capabilities("Sites.Unknownop.All") is None


def test_clean_fixture_has_no_findings(clean_inventory):
    res = check(clean_inventory)
    assert res.findings == []
    assert {s.subject for s in res.skips} == {"tickets"}  # has a credential, no granted scopes
