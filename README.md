# Agent Permission Linter (apl) — v0.1.0.dev0, Phase 1

Finds AI agents that hold more power than their declared task needs: a finding is *granted*
capability exceeding *required* capability.

**Safety:** read-only. Never connects to MCP servers (`--connect` is refused in v0.1). Secrets are
redacted at parse time and only env var *names* are stored. There is no `apply` command.

```bash
pip install -e '.[dev]'
apl inventory -c tests/fixtures/configs/claude_desktop.json \
  -a tests/fixtures/agents/release_notes_bot.yaml \
  -t tests/fixtures/tools/claude_desktop_tools.json
pytest && ruff check .
```

Phase status: 1 ✅ models/parsers/classifier/fixtures · 2 rules APL-001..010 · 3 Entra collector ·
4 LLM reasoning layer · 5 reporters (JSON/MD/SARIF) · 6 docs.

See [docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md).
