"""Read-only Microsoft Entra collector. No writes: Graph traffic can only be GET (GetOnlyTransport).

The token is an OAuth2 client-credentials POST to the tenant token endpoint over plain REST, kept
in memory only. That POST uses its own short-lived client and never carries the bearer token;
nothing reachable from Graph responses can change where it goes. See docs/ASSUMPTIONS.md G1.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from apl.redact import redact

GRAPH_HOST = "graph.microsoft.com"
GRAPH_BASE = f"https://{GRAPH_HOST}/v1.0"
GRAPH_SCOPE = f"https://{GRAPH_HOST}/.default"
LOGIN_BASE = "https://login.microsoftonline.com"
ENV_VARS = ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET")
TIMEOUT = 30.0
TOKEN_EXPIRY_MARGIN = 60  # seconds; refresh before the token can expire mid-request

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


class GraphClient:
    def __init__(
        self,
        token: Callable[[], str],
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._token = token
        inner = transport if transport is not None else httpx.HTTPTransport()
        self._http = httpx.Client(transport=GetOnlyTransport(inner), timeout=TIMEOUT)

    def close(self) -> None:
        self._http.close()

    def get(self, url: str) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._token()}"}
        try:
            resp = self._http.get(url, headers=headers)
        except httpx.HTTPError as e:
            raise EntraError(f"Graph request failed: {type(e).__name__}") from None
        if resp.status_code != 200:
            raise EntraError(f"Graph HTTP {resp.status_code} for {httpx.URL(url).path}")
        return resp.json()
