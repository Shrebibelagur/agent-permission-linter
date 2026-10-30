"""Linking Entra apps to credentials, and the capability -> permission table."""

from datetime import UTC, datetime

import pytest
from builders import cred, inventory, server, tool

from apl.collectors.entra import CredentialExpiry, EntraApp, EntraSnapshot
from apl.collectors.link import link_entra, linkable_app_ids
from apl.models import (
    AgentSpec,
    Capability,
    CredentialKind,
    ServerPurpose,
)
from apl.rules.apl001_overscoped import check as apl001
from apl.rules.apl001_overscoped import scope_capabilities
from apl.rules.apl002_shared_credential import check as apl002
from apl.scopemap import (
    LABEL,
    MINIMUM_PERMISSIONS,
    minimum_permission,
    suggest_replacements,
)

APP_ID = "a1a1a1a1-0000-4000-8000-000000000001"
C = Capability


def snapshot(**kw):
    fields = {
        "app_id": APP_ID,
        "display_name": "agent",
        "service_principal_id": "sp1",
        "service_principal_type": "Application",
        "owner_ids": ["u1"],
        "application_permissions": ["Mail.ReadWrite"],
    }
    return EntraSnapshot(source="mock", apps={APP_ID: EntraApp(**(fields | kw))})


def id_cred(app_id=APP_ID):
    return cred(
        env="AZURE_CLIENT_ID",
        kind=CredentialKind.SERVICE_PRINCIPAL,
        source="inferred",
        entra_app_id=app_id,
    )


def test_match_is_by_app_id_and_case_insensitive():
    inv = inventory(server("mail", creds=[id_cred(APP_ID.upper())]))
    link_entra(inv, snapshot())
    c = inv.servers[0].credentials[0]
    assert c.granted_scopes == ["Mail.ReadWrite"]
    assert c.kind_source == "verified" and c.kind is CredentialKind.SERVICE_PRINCIPAL
    assert c.evidence.source == "entra-mock" and c.evidence.pointer == "/servicePrincipals/sp1"
    assert inv.entra_source == "mock"


def test_managed_identity_kind_comes_from_entra():
    inv = inventory(server("mail", creds=[id_cred()]))
    link_entra(inv, snapshot(service_principal_type="ManagedIdentity"))
    assert inv.servers[0].credentials[0].kind is CredentialKind.MANAGED_IDENTITY


def test_unknown_service_principal_type_does_not_claim_verified():
    inv = inventory(server("mail", creds=[id_cred()]))
    link_entra(inv, snapshot(service_principal_type="Legacy"))
    assert inv.servers[0].credentials[0].kind_source == "inferred"


def test_app_not_in_entra_stays_unknown_and_warns():
    inv = inventory(server("mail", tools=[tool("list_messages")], creds=[id_cred("other")]))
    link_entra(inv, snapshot())
    assert inv.servers[0].credentials[0].granted_scopes is None
    assert "mail: app other not found in Entra" in inv.warnings
    res = apl001(inv)
    assert [s.reason for s in res.skips] == [
        "not evaluated: missing granted scopes (no credential linked to an Entra app)"
    ]


def test_app_with_no_grants_is_evaluated_not_skipped():
    inv = inventory(server("mail", tools=[tool("list_messages")], creds=[id_cred()]))
    link_entra(inv, snapshot(application_permissions=[]))
    res = apl001(inv)
    assert res.findings == [] and res.skips == [] and len(res.evaluated) == 1


def agent(server_name="mail", app_id=APP_ID):
    return AgentSpec(
        name="a", purpose="p", servers=[ServerPurpose(server=server_name, entra_app_id=app_id)]
    )


def test_agent_yaml_id_links_a_server_with_no_id_in_its_config():
    inv = inventory(server("mail"), agent=agent())
    assert linkable_app_ids(inv) == {APP_ID}
    link_entra(inv, snapshot())
    assert inv.servers[0].credentials[0].granted_scopes == ["Mail.ReadWrite"]
    assert inv.servers[0].credentials[0].entra_app_id == APP_ID


def test_agent_yaml_link_keeps_the_secret_flagged_by_apl002():
    secret_ref = cred(
        env="AZURE_CLIENT_SECRET", kind=CredentialKind.SERVICE_PRINCIPAL, source="inferred"
    )
    spec = agent().model_copy(update={"invokers": "multiple"})
    inv = inventory(server("mail", creds=[secret_ref]), agent=spec)
    before = len(apl002(inv).findings)
    link_entra(inv, snapshot())
    assert before == 1 and len(apl002(inv).findings) == 1
    assert inv.servers[0].credentials[0].entra_app_id is None  # the secret ref was not stamped


def test_mismatched_ids_warn_and_both_are_linked():
    inv = inventory(server("mail", creds=[id_cred("other")]), agent=agent())
    link_entra(inv, snapshot())
    assert "mail: agent.yaml entra_app_id differs from the config's" in inv.warnings


def test_expired_credential_warns_once_across_servers():
    past = datetime(2020, 1, 1, tzinfo=UTC)
    snap = snapshot(credentials=[CredentialExpiry(kind="password", end_date_time=past)])
    inv = inventory(server("mail", creds=[id_cred(), id_cred()]))
    link_entra(inv, snap)
    assert inv.warnings.count("mail: Entra app agent has 1 expired credential(s)") == 1


def test_future_credential_does_not_warn():
    future = datetime(2099, 1, 1)  # naive: Graph documents these as UTC
    snap = snapshot(credentials=[CredentialExpiry(kind="key", end_date_time=future)])
    inv = inventory(server("mail", creds=[id_cred()]))
    link_entra(inv, snap)
    assert inv.warnings == []


def test_per_user_grants_are_called_out():
    inv = inventory(server("mail", creds=[id_cred()]))
    link_entra(inv, snapshot(delegated_per_user=["Files.Read"]))
    assert "per-user delegated grants: Files.Read" in inv.warnings[0]


def test_no_entra_keeps_the_hint_to_run_it():
    res = apl001(inventory(server("mail", tools=[tool("list_messages")], creds=[id_cred()])))
    assert res.skips[0].reason == (
        "not evaluated: missing granted scopes (run with --entra or --entra-mock)"
    )


def test_table_covers_the_requested_resources_and_label():
    assert set(MINIMUM_PERMISSIONS) == {
        "Mail", "Files", "Calendars", "User", "Directory", "Application",
    }
    assert LABEL == "suggested mapping"


@pytest.mark.parametrize(
    "resource,capability,delegated,application",
    [
        ("Mail", C.READ, "Mail.Read", "Mail.Read"),
        ("Mail", C.NETWORK, "Mail.Send", "Mail.Send"),
        ("Files", C.READ, "Files.Read", "Files.Read.All"),  # Files.Read has no application form
        ("User", C.READ, "User.Read", "User.Read.All"),
        ("User", C.DELETE, "User.DeleteRestore.All", "User.DeleteRestore.All"),
        ("Application", C.WRITE, "Application.ReadWrite.All", "Application.ReadWrite.OwnedBy"),
    ],
)
def test_table_rows(resource, capability, delegated, application):
    assert minimum_permission(resource, capability) == (delegated, application)


def test_directory_write_is_not_offered_for_delete():
    assert minimum_permission("Directory", C.DELETE) is None


def test_every_row_is_understood_by_apl001():
    for rows in MINIMUM_PERMISSIONS.values():
        for row in rows.values():
            for name in row:
                assert scope_capabilities(name) is not None, name


def test_suggestions():
    assert suggest_replacements("Mail.ReadWrite", {C.READ}) == ["Mail.Read"]
    assert suggest_replacements("Files.ReadWrite.All", {C.READ}) == [
        "Files.Read (delegated) or Files.Read.All (application)"
    ]
    assert suggest_replacements("Mail.Read", {C.READ}) == []  # already minimal
    assert suggest_replacements("Sites.ReadWrite.All", {C.READ}) == []  # not in the table


def test_mail_send_maps_to_network():
    assert scope_capabilities("Mail.Send") == {C.NETWORK}
