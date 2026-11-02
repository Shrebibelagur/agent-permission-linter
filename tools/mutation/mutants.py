"""Every output guard, as text to change. `guards.py` runs them; see README.md here.

Code only: entries hold no credentials, ids or other real values. Long lines are data.
"""

# ruff: noqa: E501

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Mutant:
    name: str
    file: str
    old: str
    new: str
    also: tuple[tuple[str, str], ...] = ()  # further replacements the change needs


MUTANTS = (
    Mutant(
        'exact secret removal',
        'src/apl/redact.py',
        '        out = out.replace(known, REDACTED)\n',
        '        pass\n',
    ),
    Mutant(
        'client secret not remembered',
        'src/apl/collectors/entra.py',
        '        remember_secret(env["CLIENT_SECRET"])\n',
        '',
    ),
    Mutant(
        'access token not remembered',
        'src/apl/collectors/entra.py',
        '        remember_secret(token)\n',
        '',
    ),
    Mutant(
        'tenant not registered',
        'src/apl/collectors/entra.py',
        '        idmask.register("tenant", tenant)\n',
        '',
    ),
    Mutant(
        'client not registered',
        'src/apl/collectors/entra.py',
        '        idmask.register("app", env["CLIENT_ID"])\n',
        '',
    ),
    Mutant(
        'known ids not replaced',
        'src/apl/idmask.py',
        '    if not _known:\n        return text\n',
        '    return text\n',
    ),
    Mutant(
        'GUID fallback off',
        'src/apl/idmask.py',
        '    return _GUID.sub(lambda m: pseudonym("id", m.group()), out)\n',
        '    return out\n',
    ),
    Mutant(
        'Graph path guard off',
        'src/apl/idmask.py',
        '    for pattern, kind in _PATHS:\n',
        '    for pattern, kind in ():\n',
    ),
    Mutant(
        'token endpoint guard off',
        'src/apl/idmask.py',
        '    (re.compile(rf"(login\\.microsoftonline\\.com/)({_SEGMENT})"), "tenant"),\n',
        '',
    ),
    Mutant(
        'scrub skips identifiers',
        'src/apl/redact.py',
        '    return shorten_urls(mask(redact(text)))\n',
        '    return shorten_urls(redact(text))\n',
    ),
    Mutant(
        'md not scrubbed',
        'src/apl/report/markdown.py',
        'return scrub("\\n".join(out))',
        'return "\\n".join(out)',
    ),
    Mutant(
        'json not scrubbed',
        'src/apl/report/json_report.py',
        'return scrub(text) + "\\n"',
        'return text + "\\n"',
    ),
    Mutant(
        'sarif not scrubbed',
        'src/apl/report/sarif.py',
        'return scrub(text) + "\\n"',
        'return text + "\\n"',
    ),
    Mutant(
        'stderr messages not scrubbed',
        'src/apl/cli.py',
        '    typer.secho(_clean(text), fg=fg, err=True)\n',
        '    typer.secho(text, fg=fg, err=True)\n',
    ),
    Mutant(
        'EntraError not scrubbed',
        'src/apl/collectors/entra.py',
        '        super().__init__(scrub(message))\n',
        '        super().__init__(message)\n',
    ),
    Mutant(
        'log scrub not installed',
        'src/apl/collectors/entra.py',
        'install_log_scrub()  # httpx logs full URLs: the token endpoint holds the tenant id\n',
        '',
    ),
    Mutant(
        'crash guard off',
        'src/apl/cli.py',
        '        raise UnexpectedError(f"{type(e).__name__}: {_clean(str(e))}") from None\n',
        '        raise\n',
    ),
    Mutant(
        'crash keeps raw message',
        'src/apl/cli.py',
        '{_clean(str(e))}") from None',
        '{e}") from None',
    ),
    Mutant(
        'InvalidURL escapes token call',
        'src/apl/collectors/entra.py',
        'except (httpx.HTTPError, httpx.InvalidURL, ValueError) as e:',
        'except (httpx.HTTPError, ValueError) as e:',
    ),
    Mutant(
        'inventory not scrubbed',
        'src/apl/cli.py',
        'text = scrub(json.dumps(inventory_data(inv), indent=2, ensure_ascii=False))',
        'text = json.dumps(inventory_data(inv), indent=2, ensure_ascii=False)',
    ),
    Mutant(
        '--out writes unscrubbed data',
        'src/apl/cli.py',
        '            out.write_text(text, encoding="utf-8")\n',
        '            out.write_text(str(report.inventory.servers) + text, encoding="utf-8")\n',
    ),
    Mutant(
        '--show-ids disables secrets',
        'src/apl/redact.py',
        '    out = value\n    for known in sorted',
        '    from apl import idmask\n    if idmask._show_ids:\n        return value\n    out = value\n    for known in sorted',
    ),
    Mutant(
        '--show-ids gives no warning',
        'src/apl/cli.py',
        '            _say(_SHOW_IDS_WARNING)\n',
        '            pass\n',
    ),
    Mutant(
        '--show-ids outlives the command',
        'src/apl/cli.py',
        '    finally:\n        idmask.set_show_ids(False)\n',
        '',
    ),
    Mutant(
        '--show-ids changes finding ids',
        'src/apl/rules/base.py',
        'identity = f"{rule_id}|{idmask.pseudonymise(remove_secrets(subject))[:MAX_SUBJECT]}"',
        'identity = f"{rule_id}|{remove_secrets(subject)[:MAX_SUBJECT]}"',
    ),
    Mutant(
        'salt not scrubbed',
        'src/apl/idmask.py',
        '    remember_secret(value)\n',
        '',
    ),
    Mutant(
        'unsalted pseudonyms',
        'src/apl/idmask.py',
        '    return hmac.new(_key(), value.strip().lower().encode(), hashlib.sha256).hexdigest()\n',
        '    return hashlib.sha256(value.strip().lower().encode()).hexdigest()\n',
    ),
    Mutant(
        'names not masked before render',
        'src/apl/report/__init__.py',
        '    report = report.model_copy(update={"inventory": anonymised(report.inventory)})\n',
        '',
    ),
    Mutant(
        'names not masked in findings',
        'src/apl/rules/base.py',
        '    return redact(idmask.mask_names(s))\n',
        '    return redact(s)\n',
    ),
    Mutant(
        'names not masked at the last step',
        'src/apl/idmask.py',
        '    named = mask_names(text)\n',
        '    named = text\n',
    ),
    Mutant(
        'cut name not registered',
        'src/apl/rules/base.py',
        '    idmask.register_name("app-name", name[:60], full=name)  # the cut form must match too\n',
        '',
    ),
    Mutant(
        'server names not registered',
        'src/apl/inventory.py',
        '        idmask.register_name("server-name", name)\n',
        '        pass\n',
    ),
    Mutant(
        'agent.yaml servers not registered',
        'src/apl/inventory.py',
        ' + [p.server for p in (spec.servers if spec else [])]',
        '',
    ),
    Mutant(
        'app names not registered',
        'src/apl/collectors/link.py',
        '    idmask.register_name("app-name", app.display_name)\n',
        '',
    ),
    Mutant(
        'other API names not registered',
        'src/apl/collectors/entra.py',
        '        idmask.register_name("sp-name", name)  # printed inside the permission\n',
        '        pass\n',
    ),
    Mutant(
        'no word boundaries',
        'src/apl/idmask.py',
        'return re.compile(rf"(?<![\\w-])(?<!\\w\\.)(?:{\'|\'.join(parts)})(?![\\w-]|\\.\\w)")',
        'return re.compile("|".join(parts))',
    ),
    Mutant(
        '--show-ids also skips names',
        'src/apl/idmask.py',
        '    return named if _show_ids else pseudonymise(named)\n',
        '    return text if _show_ids else pseudonymise(named)\n',
    ),
    Mutant(
        'flag changes finding ids',
        'src/apl/rules/base.py',
        'idmask.pseudonymise(remove_secrets(subject))[:MAX_SUBJECT]',
        'idmask.pseudonymise(_r(subject))[:MAX_SUBJECT]',
    ),
    Mutant(
        'flag outlives the command',
        'src/apl/cli.py',
        '        idmask.set_anonymise_names(False)\n',
        '',
    ),
    Mutant(
        'inventory names not masked',
        'src/apl/report/common.py',
        '    return idmask.mask_names_obj(data)\n',
        '    return data\n',
    ),
    Mutant(
        'md marker missing',
        'src/apl/report/markdown.py',
        'if idmask.showing_ids() else []',
        'if False else []',
    ),
    Mutant(
        'json marker missing',
        'src/apl/report/json_report.py',
        '    if idmask.showing_ids():\n',
        '    if False:\n',
    ),
    Mutant(
        'sarif marker missing',
        'src/apl/report/sarif.py',
        '    if idmask.showing_ids():\n',
        '    if False:\n',
    ),
    Mutant(
        'sarif note dropped',
        'src/apl/report/sarif.py',
        '        notes.insert(0, {"level": "warning", "message": {"text": REAL_IDS_WARNING}})\n',
        '',
    ),
    Mutant(
        'sarif property dropped',
        'src/apl/report/sarif.py',
        '        properties["containsRealIds"] = True\n',
        '',
    ),
    Mutant(
        'marker printed without the flag',
        'src/apl/report/json_report.py',
        '    if idmask.showing_ids():\n',
        '    if True:\n',
    ),
    Mutant(
        'marker lost with --anonymise-names',
        'src/apl/report/markdown.py',
        'if idmask.showing_ids() else []',
        'if idmask.showing_ids() and not idmask.anonymising_names() else []',
    ),
    Mutant(
        'agent name not masked in copy',
        'src/apl/report/common.py',
        '        copy.agent.name = idmask.mask_names(copy.agent.name)\n',
        '        pass\n',
    ),
    Mutant(
        'agent name not registered',
        'src/apl/inventory.py',
        '        idmask.register_name("agent-name", spec.name)\n',
        '        pass\n',
    ),
    Mutant(
        'command not masked',
        'src/apl/report/common.py',
        '            srv["command"] = f"[cmd-{index}]"\n',
        '            pass\n',
    ),
    Mutant(
        'url not masked',
        'src/apl/report/common.py',
        '            srv["url"] = f"[url-{index}]"\n',
        '            pass\n',
    ),
    Mutant(
        'args not masked',
        'src/apl/report/common.py',
        '        srv["args"] = _placeholder_args(srv.get("args", []))\n',
        '',
    ),
    Mutant(
        'redacted args get hashed',
        'src/apl/report/common.py',
        '        if REDACTED in arg:\n            out.append(arg)\n        else:\n            count += 1\n            out.append(f"[arg-{count}]")\n',
        '        count += 1\n        out.append(f"[arg-{count}]")\n',
    ),
    Mutant(
        'inventory fields masked without the flag',
        'src/apl/report/common.py',
        '    if not idmask.anonymising_names():\n        return data\n',
        '',
    ),
    Mutant(
        'owner field not masked',
        'src/apl/report/common.py',
        '        data["agent"]["owner"] = idmask.pseudonym("owner-name", data["agent"]["owner"])\n',
        '        pass\n',
    ),
    Mutant(
        'owner not registered',
        'src/apl/inventory.py',
        '            idmask.register_name("owner-name", spec.owner)\n',
        '            pass\n',
    ),
    Mutant(
        'args pseudonymised again',
        'src/apl/report/common.py',
        '            out.append(f"[arg-{count}]")\n',
        '            out.append(idmask.pseudonym("id", arg))\n',
    ),
    Mutant(
        'arg numbering shared across servers',
        'src/apl/report/common.py',
        '    count = 0\n    for arg in args:\n',
        '    count = len(_SEEN)\n    for arg in args:\n        _SEEN.append(arg)\n',
        also=(('def _placeholder_args', '_SEEN: list[str] = []\n\n\ndef _placeholder_args'),),
    ),
    Mutant(
        'redacted arg counted',
        'src/apl/report/common.py',
        '        if REDACTED in arg:\n            out.append(arg)\n',
        '        if REDACTED in arg:\n            count += 1\n            out.append(arg)\n',
    ),
    Mutant(
        'free-text notice missing',
        'src/apl/cli.py',
        '            _say(_FREE_TEXT_NOTICE)\n',
        '            pass\n',
    ),
    Mutant(
        'free-text notice without the flag',
        'src/apl/cli.py',
        '        if anonymise_names:\n            _say(_FREE_TEXT_NOTICE)\n',
        '        _say(_FREE_TEXT_NOTICE)\n',
    ),
    Mutant(
        'url hashed instead of placeholder',
        'src/apl/report/common.py',
        '            srv["url"] = f"[url-{index}]"\n',
        '            srv["url"] = idmask.pseudonym("id", srv["url"])\n',
    ),
    Mutant(
        'command hashed instead of placeholder',
        'src/apl/report/common.py',
        '            srv["command"] = f"[cmd-{index}]"\n',
        '            srv["command"] = idmask.pseudonym("id", srv["command"])\n',
    ),
    Mutant(
        'url numbering restarts per server',
        'src/apl/report/common.py',
        '            srv["url"] = f"[url-{index}]"\n',
        '            srv["url"] = "[url-1]"\n',
    ),
    Mutant(
        'scan notice missing',
        'src/apl/cli.py',
        '    if idmask.anonymising_names():\n        _say(_FREE_TEXT_NOTICE)\n',
        '',
    ),
    Mutant(
        'scan notice without the flag',
        'src/apl/cli.py',
        '    if idmask.anonymising_names():\n        _say(_FREE_TEXT_NOTICE)\n',
        '    _say(_FREE_TEXT_NOTICE)\n',
    ),
    Mutant(
        'limits line missing',
        'src/apl/report/common.py',
        '    if idmask.anonymising_names():\n        lim.standing.append(FREE_TEXT_LIMIT)\n',
        '',
    ),
    Mutant(
        'limits line without the flag',
        'src/apl/report/common.py',
        '    if idmask.anonymising_names():\n        lim.standing.append(FREE_TEXT_LIMIT)\n',
        '    lim.standing.append(FREE_TEXT_LIMIT)\n',
    ),
    Mutant(
        'sarif free-text note missing',
        'src/apl/report/sarif.py',
        '        notes.insert(0, {"level": "note", "message": {"text": FREE_TEXT_LIMIT}})\n',
        '        pass\n',
    ),
    Mutant(
        'urls not shortened',
        'src/apl/redact.py',
        '    return shorten_urls(mask(redact(text)))\n',
        '    return mask(redact(text))\n',
    ),
    Mutant(
        '--show-urls has no effect',
        'src/apl/redact.py',
        '    return text if _show_urls else _URL.sub(_short_url, text)\n',
        '    return _URL.sub(_short_url, text)\n',
    ),
    Mutant(
        '--show-urls gives no warning',
        'src/apl/cli.py',
        '            _say(_SHOW_URLS_WARNING)\n',
        '            pass\n',
    ),
    Mutant(
        '--show-urls outlives the command',
        'src/apl/cli.py',
        '        set_show_urls(False)\n',
        '',
    ),
    Mutant(
        '--show-urls keeps the query',
        'src/apl/redact.py',
        '    query = REDACTED if parts.query else ""\n',
        '    query = parts.query\n',
    ),
    Mutant(
        '--show-urls keeps userinfo',
        'src/apl/redact.py',
        '    netloc = parts.hostname or ""\n',
        '    netloc = parts.netloc\n',
    ),
    Mutant(
        'allowlist emptied',
        'src/apl/redact.py',
        '    if host.lower() in _TRUSTED_URL_HOSTS and "@" not in authority:\n',
        '    if False:\n',
    ),
    Mutant(
        'allowlist matches by substring',
        'src/apl/redact.py',
        '    if host.lower() in _TRUSTED_URL_HOSTS and "@" not in authority:\n',
        '    if any(h in rest for h in _TRUSTED_URL_HOSTS):\n',
    ),
    Mutant(
        'allowlist ignores userinfo',
        'src/apl/redact.py',
        '    if host.lower() in _TRUSTED_URL_HOSTS and "@" not in authority:\n',
        '    if host.lower() in _TRUSTED_URL_HOSTS:\n',
    ),
    Mutant(
        'short url keeps userinfo',
        'src/apl/redact.py',
        '    host = authority.rsplit("@", 1)[-1]\n',
        '    host = authority\n',
    ),
    Mutant(
        'file uris shortened',
        'src/apl/redact.py',
        '(?!file://)',
        '',
    ),
    Mutant(
        'url step before names',
        'src/apl/redact.py',
        '    return shorten_urls(mask(redact(text)))\n',
        '    return mask(shorten_urls(redact(text)))\n',
    ),
    Mutant(
        'arg tokens not redacted',
        'src/apl/parsers/mcp_config.py',
        '        args = [redact_random_tokens(a) for a in args]  # a guess, so it does not count as inline\n',
        '',
    ),
    Mutant(
        'command tokens not redacted',
        'src/apl/parsers/mcp_config.py',
        'redact_random_tokens(redact(str(entry["command"])))',
        'redact(str(entry["command"]))',
    ),
    Mutant(
        'token floor lowered',
        'src/apl/redact.py',
        'MIN_TOKEN_CHARS = 20\n',
        'MIN_TOKEN_CHARS = 12\n',
    ),
    Mutant(
        'token floor raised',
        'src/apl/redact.py',
        'MIN_TOKEN_CHARS = 20\n',
        'MIN_TOKEN_CHARS = 21\n',
    ),
    Mutant(
        'entropy check off',
        'src/apl/redact.py',
        '    if entropy < MIN_TOKEN_ENTROPY:\n        return False\n',
        '',
    ),
    Mutant(
        'kind-change check off',
        'src/apl/redact.py',
        '    return changes / size >= MIN_KIND_CHANGES\n',
        '    return True\n',
    ),
    Mutant(
        'mixed-case check off',
        'src/apl/redact.py',
        '        any(c.isupper() for c in token)\n        and any(c.islower() for c in token)\n        and any(c.isdigit() for c in token)\n',
        '        True\n',
    ),
    Mutant(
        'a guess counts as inline secret',
        'src/apl/parsers/mcp_config.py',
        '        args = [redact_random_tokens(a) for a in args]  # a guess, so it does not count as inline\n',
        '        inline_in_args = inline_in_args or any(redact_random_tokens(a) != a for a in args)\n        args = [redact_random_tokens(a) for a in args]\n',
    ),
    Mutant(
        'url marker missing in md',
        'src/apl/report/markdown.py',
        '    if showing_urls():\n        out += [f"**{REAL_URLS_WARNING}**", ""]\n',
        '',
    ),
    Mutant(
        'url marker missing in json',
        'src/apl/report/json_report.py',
        '    if showing_urls():\n        data["contains_real_urls"] = True  # likewise\n',
        '',
    ),
    Mutant(
        'url note missing in sarif',
        'src/apl/report/sarif.py',
        '        notes.insert(0, {"level": "warning", "message": {"text": REAL_URLS_WARNING}})\n',
        '',
    ),
    Mutant(
        'url property missing in sarif',
        'src/apl/report/sarif.py',
        '        properties["containsRealUrls"] = True\n',
        '',
    ),
    Mutant(
        'url marker printed without the flag',
        'src/apl/report/json_report.py',
        '    if showing_urls():\n        data["contains_real_urls"]',
        '    if True:\n        data["contains_real_urls"]',
    ),
)
