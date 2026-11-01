"""Join Entra data onto the inventory: fill `granted_scopes` so APL-001 can evaluate.

Matches on appId (client id). ASSUMPTION G10.
"""

from __future__ import annotations

from apl import idmask
from apl.collectors.entra import EntraApp, EntraSnapshot
from apl.models import AppRef, CredentialKind, CredentialRef, Evidence, Inventory, MCPServer
from apl.redact import redact

# servicePrincipalType values that settle the credential kind. Others leave it as it was.
_VERIFIED_KINDS = {
    "Application": CredentialKind.SERVICE_PRINCIPAL,
    "ManagedIdentity": CredentialKind.MANAGED_IDENTITY,
}


def _declared(inv: Inventory) -> dict[str, str]:
    """server name -> entra_app_id from agent.yaml."""
    servers = inv.agent.servers if inv.agent else []
    return {s.server: s.entra_app_id for s in servers if s.entra_app_id}


def linkable_app_ids(inv: Inventory) -> set[str]:
    ids = {c.entra_app_id for s in inv.servers for c in s.credentials if c.entra_app_id}
    return ids | set(_declared(inv).values())


def _register_ids(app: EntraApp) -> None:
    idmask.register_name("app-name", app.display_name)
    idmask.register("app", app.app_id)
    if app.application_object_id:
        idmask.register("app", app.application_object_id)
    if app.service_principal_id:
        idmask.register("sp", app.service_principal_id)
    for c in app.credentials:
        if c.key_id:
            idmask.register("cred", c.key_id)


def _warnings(srv: MCPServer, app: EntraApp) -> list[str]:
    who = f"{srv.name}: Entra app {app.display_name or app.app_id}"
    out = []
    if app.service_principal_id is None:
        out.append(f"{who} has no service principal in this tenant, so nothing is granted")
    if app.delegated_per_user:
        out.append(f"{who} has per-user delegated grants: {', '.join(app.delegated_per_user)}")
    return out


def _link(cred: CredentialRef, app: EntraApp, source: str) -> CredentialRef:
    origin = "graph.microsoft.com/v1.0" if source == "live" else "entra-mock"
    resource = "servicePrincipals" if app.service_principal_id else "applications"
    object_id = app.service_principal_id or app.application_object_id
    tenant_wide = len(app.delegated_all_principals)
    per_user = len(app.delegated_per_user)
    note = (
        f"Entra ({source}): {app.display_name or app.app_id}; "
        f"{len(app.application_permissions)} application permission(s), "
        f"{tenant_wide + per_user} delegated scope(s) "
        f"(tenant-wide consent: {tenant_wide}, per-user: {per_user})"
    )
    update: dict = {
        "granted_scopes": app.granted_scopes(),
        "evidence": Evidence(
            source=origin,
            pointer=f"/{resource}/{object_id}",
            note=redact(note),
            app=AppRef(app_id=app.app_id, display_name=app.display_name),
        ),
    }
    kind = _VERIFIED_KINDS.get(app.service_principal_type or "")
    if kind is not None:
        update |= {"kind": kind, "kind_source": "verified"}
    return cred.model_copy(update=update)


def link_entra(inv: Inventory, snapshot: EntraSnapshot) -> None:
    """Mutates `inv`. Credentials are frozen, so each linked one is replaced."""
    inv.entra_source = snapshot.source
    declared = _declared(inv)
    notes: list[str] = []
    for srv in inv.servers:
        creds = list(srv.credentials)
        config_ids = {c.entra_app_id.lower() for c in creds if c.entra_app_id}
        yaml_id = declared.get(srv.name)
        if yaml_id and yaml_id.lower() not in config_ids:
            if config_ids:
                notes.append(f"{srv.name}: agent.yaml entra_app_id differs from the config's")
            # Always a separate id-only ref. Stamping the id on a secret-bearing ref would make
            # APL-002 treat that secret as "just a client id" and stop flagging it.
            creds.append(
                CredentialRef(
                    entra_app_id=yaml_id,
                    evidence=Evidence(
                        source="agent.yaml", pointer=f"/servers/{srv.name}/entra_app_id"
                    ),
                )
            )
        linked = []
        for cred in creds:
            app = snapshot.apps.get(cred.entra_app_id.lower()) if cred.entra_app_id else None
            if app is None:
                if cred.entra_app_id:
                    notes.append(f"{srv.name}: app {cred.entra_app_id} not found in Entra")
                linked.append(cred)
                continue
            linked.append(_link(cred, app, snapshot.source))
            if app not in srv.entra_apps:
                srv.entra_apps.append(app)
            _register_ids(app)
            notes.extend(_warnings(srv, app))
        srv.credentials = linked
    inv.warnings.extend(redact(n) for n in dict.fromkeys(notes))
