# Guard harness

Tests passing does not show that a guard works: a test can pass for the wrong reason. This harness
breaks each output guard on purpose, one at a time, and checks that some test then fails. A guard
that survives means that protection could disappear without anyone noticing.

```
python tools/mutation/guards.py list
python tools/mutation/guards.py run
python tools/mutation/guards.py run --only show-urls
```

`run` takes about 10 to 15 minutes. It exits 0 if every guard was caught, 1 if one survived and 2 if
it could not run safely. It is not part of the default `pytest` run. Run it after changing `redact.py`,
`idmask.py`, the renderers or `cli.py`.

## Safety

- **Throwaway copy.** It works in a new temp directory, outside the repo, deleted afterwards. The
  repo is only read.
- **Allowlisted environment.** Tests get `PATH` and a few system variables, not your shell. Real
  `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` and `APL_ID_SALT` values cannot get in.
- **Isolated home.** `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA` and `XDG_CONFIG_HOME` all
  point into the temp directory, so a salt file cannot reach your real config dir.
- **Fake values only.** The salt is a fixed fake, and the entries hold code, no credentials or ids.
- **Checked, not assumed.** The run fails if tests would import the real package, if any file
  appears in the isolated home, or if the repo changed.

## Adding a guard

Add a `Mutant` to `mutants.py`: a name, the file, the exact text to change and what to change it
to. Then run `run --only <name>`. If it survives, the guard has no real test: write one.

If you change a line an entry points at, `tests/test_mutation_entries.py` fails in the normal
`pytest` run, so entries cannot go stale unnoticed. That test is excluded from harness runs, because
inside a broken copy it would fail every time and make every guard look caught.

The number of guards is also recorded in `docs/ASSUMPTIONS.md` (R19), and that same test keeps it
correct.
