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
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field, TypeAdapter, ValidationError

from apl.models import CredentialExpiry, EntraApp
from apl.redact import redact, remember_secret

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
_FIXTURE_NAME = re.compile(r"^[A-Za-z0-9_.\-]+$")
_DATE = TypeAdapter(datetime)


class EntraError(RuntimeError):
    """A collector failure. Messages hold status codes and paths, never bodies or credentials."""


class GraphUnreadable(EntraError):
    """Graph answered 403 or 404: this one object cannot be read."""


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
        remember_secret(env["CLIENT_SECRET"])
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


class FixtureTransport(httpx.BaseTransport):
    """Mock mode: answers Graph requests from local JSON, so it cannot touch the network.

    `/v1.0/applications/{id}/owners` -> `applications.{id}.owners.json`; a `$skiptoken` value is
    appended the same way, so a fixture pages through the same `@odata.nextLink` code as live.
    """

    def __init__(self, root: Path) -> None:
        self._root = root

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        name = request.url.path.removeprefix("/v1.0/").replace("/", ".")
        token = request.url.params.get("$skiptoken")
        if token:
            name += f".{token}"
        path = self._root / f"{name}.json"
        if not _FIXTURE_NAME.match(name) or not path.is_file():
            return httpx.Response(404, json={"error": {"code": "Request_ResourceNotFound"}})
        return httpx.Response(200, content=path.read_bytes())


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
        remember_secret(token)
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
                failure = GraphUnreadable if status in (403, 404) else EntraError
                raise failure(f"Graph HTTP {status} for {path}{hint}")
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


class EntraSnapshot(BaseModel):
    source: Literal["live", "mock"]
    apps: dict[str, EntraApp] = Field(default_factory=dict)


def _text(value: Any) -> str:
    return redact(str(value))[:MAX_TEXT] if value else ""


def _key(app_id: Any) -> str:
    return str(app_id).lower()


def _date(value: Any) -> tuple[datetime | None, bool]:
    """(date, unreadable). The validation message echoes the input, so it is never surfaced."""
    if value is None:
        return None, False
    try:
        return _DATE.validate_python(value), False
    except ValidationError:
        return None, True


def _expiries(obj: dict[str, Any], resource: str = "applications") -> list[CredentialExpiry]:
    fields = {"password": "passwordCredentials", "key": "keyCredentials"}
    out = []
    for kind, name in fields.items():
        for c in obj.get(name) or []:
            if not isinstance(c, dict):
                continue
            end, unreadable = _date(c.get("endDateTime"))
            out.append(
                CredentialExpiry(
                    kind=kind,
                    key_id=_text(c.get("keyId")) or None,
                    start_date_time=_date(c.get("startDateTime"))[0],
                    end_date_time=end,
                    end_unreadable=unreadable,
                    pointer=f"/{resource}/{_text(obj.get('id'))}/{name}",
                )
            )
    return out


def _credentials_gap(app: dict[str, Any] | None, sp: dict[str, Any] | None) -> str | None:
    """An empty result proves "no credentials" only if Graph really returned both lists."""
    names = ("passwordCredentials", "keyCredentials")
    if any(not isinstance(o.get(n), list) for o in (app, sp) if o for n in names):
        return "credential lists absent from the Graph response"
    return None if app else "application object is in another tenant"


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


def _owners(client: GraphClient, *paths: str) -> list[str] | None:
    """Union across objects. None if one was unreadable and the rest show no owner: unknown."""
    ids: set[str] = set()
    unreadable = False
    for path in paths:
        try:
            ids.update(str(o["id"]) for o in client.get_all(path) if o.get("id"))
        except GraphUnreadable:
            unreadable = True
    return None if unreadable and not ids else sorted(_text(i) for i in ids)


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
            credentials=[*_expiries(app or {}), *_expiries(sp or {}, "servicePrincipals")],
            credentials_gap=_credentials_gap(app, sp),
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


def collect_mock(root: Path, app_ids: Iterable[str] | None = None) -> EntraSnapshot:
    """`--entra-mock`: no credentials, no network."""
    if not root.is_dir():
        raise EntraError(f"mock Graph directory not found: {root}")
    client = GraphClient(lambda: "mock", FixtureTransport(root))
    try:
        return collect_entra(client, app_ids, source="mock")
    finally:
        client.close()


def _live_transport() -> httpx.BaseTransport:
    return httpx.HTTPTransport()


def collect_live(
    app_ids: Iterable[str] | None = None, env: Mapping[str, str] | None = None
) -> EntraSnapshot:
    """`--entra`: credentials from the environment only."""
    creds = EntraCredentials.from_env(env)
    token = ClientCredentialsToken(creds, _live_transport())
    client = GraphClient(token, _live_transport())
    try:
        return collect_entra(client, app_ids, source="live")
    finally:
        client.close()
