# Contributing

Thanks for helping. Read [CLAUDE.md](CLAUDE.md) and [SECURITY.md](SECURITY.md) first: the project
rules there (read-only, no secrets in output, untrusted server text) apply to every change.

## Setup

Python 3.11 or later.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -e '.[dev]'
```

You do not need an Azure tenant or any credentials. Every test runs offline against fixtures.

## Tests

```bash
pytest
ruff check .
```

Both must pass before a pull request. Before a release, run the full check:

```bash
python tools/release_check.py
```

It runs pytest and ruff, checks that the license and docs exist, looks for GUIDs outside the
fixtures, and scans git history with [gitleaks](https://github.com/gitleaks/gitleaks) if it is
installed (8.25 or later). It exits non-zero on any failure.

`.gitleaks.toml` keeps every default gitleaks rule and allowlists only the fake values the tests
plant on purpose: each entry is one rule, one exact value, and only under `tests/`. If a new test
needs a planted secret, prefer reusing one of those values. If you must add one, add a narrow
entry in the same form; a path-wide or rule-wide ignore will be refused in review.

Report snapshots live in `tests/snapshots/`. If you change report wording on purpose, update the
snapshot in the same commit, and check that the README excerpt still matches
(`tests/test_readme.py` enforces it).

## The guard harness

Passing tests do not prove a guard works. `tools/mutation/` breaks each output guard (redaction,
id pseudonyms, URL shortening, name masking, report markers) one at a time in a throwaway copy, and
checks that some test then fails.

```bash
python tools/mutation/guards.py list
python tools/mutation/guards.py run                 # 10 to 15 minutes
python tools/mutation/guards.py run --only <name>
```

Run it after changing `redact.py`, `idmask.py`, a renderer or `cli.py`. If you add a guard, add a
`Mutant` to `tools/mutation/mutants.py` and update the guard count in `docs/ASSUMPTIONS.md` (R19);
`tests/test_mutation_entries.py` fails if the count or an entry is stale. A guard that survives a
run has no real test: write one. Details: [tools/mutation/README.md](tools/mutation/README.md).

## No real data in fixtures

Everything under `tests/` must be invented.

- **Ids:** use obviously fake GUIDs such as `a1a1a1a1-0000-4000-8000-000000000001`. Never paste a
  tenant, client or object id from a real tenant, even your own lab. Public, documented ids (the
  Microsoft Graph appId, a documented app role id) are fine; add them to the allowlist in
  `tools/release_check.py` with the reason.
- **Secrets:** use values that are clearly fake and say so, such as `FAKE-SECRET-...`. Never a real
  token, revoked or not.
- **Names:** use `Contoso`, `example.test` and similar. No real people, companies or hostnames.
- **Graph responses:** build them from the shapes in the Microsoft Learn examples, not by saving a
  live response.
- **Tool lists:** hand-written, or from a public server's published schema with nothing
  tenant-specific in it.

`tools/release_check.py` fails on any GUID outside `tests/fixtures/` that is not on its allowlist.

## Changes to rules and the classifier

- Tool descriptions and server output are untrusted. Never classify from a description, and never
  let a server-written signal remove a capability.
- A rule that lacks its input must emit a visible skip ("not evaluated: missing X"), not pass.
- Framework references are labelled "suggested mapping". Prefer OWASP ids you have looked up.
- Record every assumption in [docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md) as verified, corrected or
  unverified, with the source URL.
- Held-out corpora are measured once. Do not tune the classifier against a set and then report its
  numbers as accuracy (see E5 and E7).

## Commits

Small steps, one change per commit, with pytest and ruff passing on each.
