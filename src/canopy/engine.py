from __future__ import annotations

from pathlib import Path

from canopy.discover import discover
from canopy.models import Finding
from canopy.parse import parse_source
from canopy.rules import Rule, all_rules


def scan_path(
    root: Path,
    *,
    lang: str | None = None,
    rules: list[Rule] | None = None,
) -> list[Finding]:
    selected = rules if rules is not None else all_rules()
    findings: list[Finding] = []
    for path, language in discover(root, lang):
        source = path.read_bytes()
        tree = parse_source(source, language)
        display = _display_path(path)
        for rule in selected:
            if not rule.applies_to(language):
                continue
            findings.extend(rule.check(tree.root_node, source, display))
    findings.sort(key=lambda item: (item.path, item.line, item.column, item.rule_id))
    return findings


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()
