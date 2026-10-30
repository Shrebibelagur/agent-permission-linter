"""Read-only Microsoft Entra collector. No writes: Graph traffic can only be GET (GetOnlyTransport).

The token is an OAuth2 client-credentials POST to the tenant token endpoint over plain REST, kept
in memory only. That POST uses its own short-lived client and never carries the bearer token;
nothing reachable from Graph responses can change where it goes. See docs/ASSUMPTIONS.md G1.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Literal
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field

from apl.redact import redact

GRAPH_HOST = "graph.microsoft.com"
GRAPH_BASE = f"https://{GRAPH_HOST}/v1.0"
GRAPH_SCOPE = f"https://{GRAPH_HOST}/.default"
LOGIN_BASE = "https://login.microsoftonline.com"
ENV_VARS = ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET")
TIMEOUT = 30.0
TOKEN_EXPIRY_MARGIN = 60  # seconds; refresh before the token can expire mid-request
MAX_ATTEMPTS = 6
BACKOFF_BASE = 1.0  # seconds; doubles each attempt when the response has no Retry-After
BACKOFF_MAX = 60.0
MAX_RETRY_AFTER = 300  # longer than this we stop: retrying sooner would ignore the server
MAX_PAGES = 10_000
MAX_TEXT = 200  # display names and scope values are tenant-controlled
# Well-known appId of Microsoft Graph. Names are never trusted to identify a resource.
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
NO_SPECIFIC_ROLE = "00000000-0000-0000-0000-000000000000"

_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]*$")  # GUID or domain name; goes into a URL
_ERROR_CODE = re.compile(r"^[a-z_]{1,64}$")


class EntraError(RuntimeError):
    """A collector failure. Messages hold status codes and paths, never bodies or credentials."""


class ReadOnlyViolation(EntraError):
    """Something tried to send a non-GET or off-Graph request through the Graph client."""


@dataclass(frozen=True)
class EntraCredentials:
    tenant_id: str
    client_id: str
    client_secret: str = field(repr=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> EntraCredentials:
        env = os.environ if env is None else env
        missing = [name for name in ENV_VARS if not env.get(name)]
        if missing:
            raise EntraError(f"missing environment variable(s): {', '.join(missing)}")
        tenant = env["TENANT_ID"]
        if not _TENANT.match(tenant):
            raise EntraError("TENANT_ID must be a tenant GUID or domain name")
        return cls(tenant, env["CLIENT_ID"], env["CLIENT_SECRET"])


class GetOnlyTransport(httpx.BaseTransport):
    """The read-only guard. Every Graph request passes here, so a bug or a hostile
    `@odata.nextLink` cannot write to Entra or send the bearer token anywhere but Graph."""

    def __init__(self, inner: httpx.BaseTransport) -> None:
        self._inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.method != "GET":
            raise ReadOnlyViolation(f"read-only collector: refused {redact(request.method)}")
        if request.url.scheme != "https" or request.url.host != GRAPH_HOST:
            raise ReadOnlyViolation(f"refused request to {redact(request.url.host)}: not Graph")
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


class ClientCredentialsToken:
    """Callable returning a current access token. In memory only; re-fetched near expiry."""

    def __init__(
        self,
        creds: EntraCredentials,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._creds = creds
        self._transport = transport
        self._clock = clock
        self._value: str | None = None
        self._expires_at = 0.0

    def __repr__(self) -> str:
        return "<ClientCredentialsToken>"

    def __call__(self) -> str:
        if self._value is None or self._clock() >= self._expires_at:
            self._value, lifetime = self._fetch()
            self._expires_at = self._clock() + lifetime - TOKEN_EXPIRY_MARGIN
        return self._value

    def _fetch(self) -> tuple[str, float]:
        url = f"{LOGIN_BASE}/{self._creds.tenant_id}/oauth2/v2.0/token"
        form = {
            "client_id": self._creds.client_id,
            "client_secret": self._creds.client_secret,
            "scope": GRAPH_SCOPE,
            "grant_type": "client_credentials",
        }
        try:
            with httpx.Client(transport=self._transport, timeout=TIMEOUT) as http:
                resp = http.post(url, data=form)
            body = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            raise EntraError(f"token request failed: {type(e).__name__}") from None
        if resp.status_code != 200 or not isinstance(body, dict):
            raise EntraError(_token_failure(resp.status_code, body))
        token = body.get("access_token")
        lifetime = body.get("expires_in")
        if not isinstance(token, str) or not token or not isinstance(lifetime, int):
            raise EntraError("token response has no usable access_token/expires_in")
        return token, float(lifetime)


def _token_failure(status: int, body: Any) -> str:
    """Status and error code only: `error_description` is free text, so it is never echoed."""
    code = body.get("error") if isinstance(body, dict) else None
    if isinstance(code, str) and _ERROR_CODE.match(code):
        return f"token request failed: HTTP {status} ({code})"
    return f"token request failed: HTTP {status}"


def _retry_delay(resp: httpx.Response, attempt: int) -> float:
    """Seconds to wait: Retry-After (seconds or HTTP-date) if usable, else exponential backoff."""
    header = (resp.headers.get("retry-after") or "").strip()
    delay: float | None = None
    if header.isdigit():
        delay = float(header)
    elif header:
        try:
            delay = (parsedate_to_datetime(header) - datetime.now(UTC)).total_seconds()
        except (TypeError, ValueError):
            delay = None
    if delay is None:
        return min(BACKOFF_BASE * 2**attempt, BACKOFF_MAX)
    return max(delay, 0.0)


class GraphClient:
    def __init__(
        self,
        token: Callable[[], str],
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._token = token
        self._sleep = sleep
        inner = transport if transport is not None else httpx.HTTPTransport()
        self._http = httpx.Client(transport=GetOnlyTransport(inner), timeout=TIMEOUT)

    def close(self) -> None:
        self._http.close()

    def get(self, url: str) -> dict[str, Any]:
        """One page, retrying 429 and 5xx. Bodies of failed responses are never read."""
        path = httpx.URL(url).path
        for attempt in range(MAX_ATTEMPTS):
            headers = {"Authorization": f"Bearer {self._token()}"}
            try:
                resp = self._http.get(url, headers=headers)
            except httpx.HTTPError as e:
                raise EntraError(f"Graph request failed: {type(e).__name__}") from None
            status = resp.status_code
            if status == 200:
                return _page(resp, path)
            if status != 429 and status < 500:
                hint = ": needs Application.Read.All, Directory.Read.All" if status == 403 else ""
                raise EntraError(f"Graph HTTP {status} for {path}{hint}")
            delay = _retry_delay(resp, attempt)
            if delay > MAX_RETRY_AFTER:
                raise EntraError(f"Graph HTTP {status} for {path}: wait {delay:.0f}s too long")
            if attempt + 1 < MAX_ATTEMPTS:
                self._sleep(delay)
        raise EntraError(f"Graph HTTP {status} for {path}: gave up after {MAX_ATTEMPTS} attempts")

    def get_all(self, path: str) -> list[dict[str, Any]]:
        """Every item of a collection, following `@odata.nextLink` verbatim until it is absent."""
        url: str | None = f"{GRAPH_BASE}{path}"
        items: list[dict[str, Any]] = []
        seen: set[str] = set()
        while url is not None:
            if url in seen or len(seen) >= MAX_PAGES:
                raise EntraError(f"Graph paging did not terminate for {path}")
            seen.add(url)
            page = self.get(url)
            value = page.get("value")
            if not isinstance(value, list):
                raise EntraError(f"Graph response for {path} has no 'value' list")
            items.extend(v for v in value if isinstance(v, dict))
            next_link = page.get("@odata.nextLink")
            if next_link is not None and not isinstance(next_link, str):
                raise EntraError(f"Graph response for {path} has a malformed nextLink")
            url = next_link
        return items


def _page(resp: httpx.Response, path: str) -> dict[str, Any]:
    try:
        page = resp.json()
    except ValueError:
        raise EntraError(f"Graph response for {path} is not JSON") from None
    if not isinstance(page, dict):
        raise EntraError(f"Graph response for {path} is not an object")
    return page


class CredentialExpiry(BaseModel):
    """Expiry metadata only. `secretText`, `hint` and `key` are deliberately not copied."""

    kind: Literal["password", "key"]
    key_id: str | None = None
    end_date_time: datetime | None = None


class EntraApp(BaseModel):
    """One app as linked to a scan. Keyed by appId (client id), never by object id."""

    app_id: str
    display_name: str = ""
    application_object_id: str | None = None  # None: registered in another tenant
    service_principal_id: str | None = None  # None: no enterprise app, so nothing is granted
    service_principal_type: str | None = None
    credentials: list[CredentialExpiry] = Field(default_factory=list)
    owner_ids: list[str] = Field(default_factory=list)  # ids only: names and UPNs are personal data
    delegated_all_principals: list[str] = Field(default_factory=list)  # admin consent, all users
    delegated_per_user: list[str] = Field(default_factory=list)  # consent for specific users
    application_permissions: list[str] = Field(default_factory=list)

    def granted_scopes(self) -> list[str]:
        return sorted(
            {
                *self.delegated_all_principals,
                *self.delegated_per_user,
                *self.application_permissions,
            }
        )


class EntraSnapshot(BaseModel):
    source: Literal["live", "mock"]
    apps: dict[str, EntraApp] = Field(default_factory=dict)


def _text(value: Any) -> str:
    return redact(str(value))[:MAX_TEXT] if value else ""


def _key(app_id: Any) -> str:
    return str(app_id).lower()


def _expiries(obj: dict[str, Any]) -> list[CredentialExpiry]:
    found = [("password", c) for c in obj.get("passwordCredentials") or []]
    found += [("key", c) for c in obj.get("keyCredentials") or []]
    return [
        CredentialExpiry(
            kind=kind, key_id=_text(c.get("keyId")) or None, end_date_time=c.get("endDateTime")
        )
        for kind, c in found
        if isinstance(c, dict)
    ]


def _qualified(resource: dict[str, Any] | None, resource_id: Any, value: str) -> str:
    """A Graph permission stays bare; another API's scope never reads as a Graph one."""
    if resource is None:
        return f"unknown-resource-{_text(resource_id)}/{value}"
    if _key(resource.get("appId")) == GRAPH_APP_ID:
        return value
    return f"{_text(resource.get('displayName')) or _text(resource_id)}/{value}"


def _app_role_name(assignment: dict[str, Any], sps: dict[str, dict[str, Any]]) -> str:
    """appRoleAssignment holds only a GUID; its name is on the resource service principal."""
    resource_id = assignment.get("resourceId")
    resource = sps.get(str(resource_id))
    role_id = _text(assignment.get("appRoleId"))
    if role_id == NO_SPECIFIC_ROLE:
        return _qualified(resource, resource_id, "default-access")
    roles = (resource or {}).get("appRoles") or []
    value = next((r.get("value") for r in roles if str(r.get("id")) == role_id), None)
    return _qualified(resource, resource_id, _text(value) or f"unresolved-app-role-{role_id}")


def _owners(client: GraphClient, *paths: str) -> list[str]:
    ids = {str(o["id"]) for p in paths for o in client.get_all(p) if o.get("id")}
    return sorted(_text(i) for i in ids)


def _add_delegated(
    entry: EntraApp,
    sp_id: str,
    grants: list[dict[str, Any]],
    sps: dict[str, dict[str, Any]],
) -> None:
    """`clientId` on a grant is the client SP's object id, not its appId."""
    tenant_wide: set[str] = set()
    per_user: set[str] = set()
    for grant in grants:
        if str(grant.get("clientId")) != sp_id:
            continue
        resource_id = grant.get("resourceId")
        resource = sps.get(str(resource_id))
        target = tenant_wide if grant.get("consentType") == "AllPrincipals" else per_user
        target.update(
            _qualified(resource, resource_id, _text(scope))
            for scope in str(grant.get("scope") or "").split()
        )
    entry.delegated_all_principals = sorted(tenant_wide)
    entry.delegated_per_user = sorted(per_user)


def collect_entra(
    client: GraphClient,
    app_ids: Iterable[str] | None = None,
    source: Literal["live", "mock"] = "live",
) -> EntraSnapshot:
    """Read the tenant. `app_ids` limits per-object calls to the apps a scan links to; the
    tenant-wide lists are always read, because resolving role names needs every resource SP."""
    wanted = None if app_ids is None else {_key(a) for a in app_ids}
    apps = {_key(a.get("appId")): a for a in client.get_all("/applications") if a.get("appId")}
    all_sps = [s for s in client.get_all("/servicePrincipals") if s.get("id")]
    sp_by_id = {str(s["id"]): s for s in all_sps}
    sps = {_key(s.get("appId")): s for s in all_sps if s.get("appId")}
    grants = client.get_all("/oauth2PermissionGrants")

    snapshot = EntraSnapshot(source=source)
    for app_id in sorted(set(apps) | set(sps)):
        if wanted is not None and app_id not in wanted:
            continue
        app, sp = apps.get(app_id), sps.get(app_id)
        entry = EntraApp(
            app_id=app_id,
            display_name=_text((app or sp or {}).get("displayName")),
            application_object_id=_text(app["id"]) if app and app.get("id") else None,
            credentials=[*_expiries(app or {}), *_expiries(sp or {})],
        )
        owner_paths = []
        if app and app.get("id"):
            owner_paths.append(f"/applications/{quote(str(app['id']), safe='')}/owners")
        if sp:
            sp_path = f"/servicePrincipals/{quote(str(sp['id']), safe='')}"
            owner_paths.append(f"{sp_path}/owners")
            entry.service_principal_id = _text(sp["id"])
            entry.service_principal_type = _text(sp.get("servicePrincipalType")) or None
            entry.application_permissions = sorted(
                {
                    _app_role_name(a, sp_by_id)
                    for a in client.get_all(f"{sp_path}/appRoleAssignments")
                    if not a.get("deletedDateTime")
                }
            )
            _add_delegated(entry, str(sp["id"]), grants, sp_by_id)
        entry.owner_ids = _owners(client, *owner_paths)
        snapshot.apps[app_id] = entry
    return snapshot
