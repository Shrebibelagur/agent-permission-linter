# Security policy

## Reporting a vulnerability

Please report privately. Do not open a public issue for a security problem.

Use GitHub's **private vulnerability reporting**:

1. Open this repository on GitHub and go to the **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the advisory form and submit. Only you and the maintainers can see it.

There is no security email address. If the button is missing, open a public issue that says only
that you have a security report and asks for a private channel, with no details of the problem.

Include the version or commit, the command you ran, and a minimal config that shows the problem.
**Use fake values only.** Do not send real tenant ids, client ids, secrets, tokens or report output
from a real tenant. If a report from a real scan is the evidence, describe the leak instead
(which field, which output format) and send a reproduction built from fake data.

There is no bug bounty. We aim to acknowledge a report within 7 days.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |
| older | no |

## Scope

In scope: anything that breaks a promise below.

- A secret, token, salt or client secret appearing in any output: stdout, stderr, `--out`, md,
  json, sarif, `apl inventory`, logs or tracebacks.
- A full tenant, client or object id appearing in default output (without `--show-ids`).
- A URL path, query string or userinfo appearing in default output (without `--show-urls`).
- A name that `--anonymise-names` promises to replace appearing in its output.
- Any write to Entra or Microsoft Graph, any request that is not a `GET` to
  `https://graph.microsoft.com/` (apart from the token request), or the bearer token being sent
  anywhere else.
- `apl` starting, connecting to or executing an MCP server.
- Server-controlled data (tool names, descriptions, schemas, annotations, Graph display names)
  hiding or softening a finding in a way [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) does not
  already list as a known limit.

Out of scope:

- The known limits listed in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
  [docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md), unless you show they are worse than stated.
- Output produced with `--show-ids` or `--show-urls`. Those flags exist to print real values, and
  say so.
- Free text that prints as written: `purpose`, `justification` text and `env_keys` (R20).
- Classifier accuracy on its own. A wrong capability is a bug, not a vulnerability, unless a server
  can cause it on purpose to hide a finding.
- Attacks that need control of the machine running `apl`, its Python environment, or the salt file.

## What the tool protects, and what it does not

**Protects:**

- **Your tenant from the scanner.** Read-only by design. There is no `apply` command. Entra access
  is optional, uses an app with `Application.Read.All` and `Directory.Read.All` only, and the HTTP
  client refuses anything but `GET https://graph.microsoft.com/...`.
- **Your machine from the servers it inspects.** `apl` never launches or contacts an MCP server.
  `--connect` is refused with exit code 2. Tool lists are read from saved files.
- **Secrets in its output.** Secrets are removed as `[REDACTED]` at parse time and again on every
  output. Environment variable values are never stored, only their names.
- **Identifiers in its output.** Tenant, client and object ids print as salted pseudonyms such as
  `app-3f9a1c`. Without a usable salt the scan stops (exit 2) rather than printing raw ids.
- **Findings from the servers it inspects.** Tool descriptions are never used to classify. Annotations
  and schemas can only add capabilities, never remove them.

**Does not protect:**

- **Against a lying server, fully.** A tool name is chosen by the server. A server that renames a
  tool, or picks a name and parameters that agree, can soften a verdict. See the known limits in
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **Anonymity.** Pseudonyms are not anonymity. Permission names, tool names, env var names, file
  paths and free text still print and can identify an organisation.
- **Secrets it cannot recognise.** A secret with no known shape, under 20 characters, low in entropy,
  or outside `command` and `args` may print. A URL with no scheme is not shortened.
- **Your credentials at rest.** `apl` reads `TENANT_ID`, `CLIENT_ID` and `CLIENT_SECRET` from the
  environment. Keeping them out of shell history, files and CI logs is up to you.
- **A real tenant, tested.** Live `--entra` mode has been tested only against Graph-shaped
  fixtures, not a real tenant.
