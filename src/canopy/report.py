from __future__ import annotations

import json
from collections.abc import Iterable

from canopy import __version__
from canopy.models import Finding, Severity
from canopy.rules import Rule, all_rules

SUPPORTED_FORMATS = ("text", "json", "sarif")
_SARIF_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def render(findings: list[Finding], fmt: str) -> str:
    if fmt == "json":
        return render_json(findings)
    if fmt == "sarif":
        return render_sarif(findings)
    if fmt == "text":
        return render_text(findings)
    supported = ", ".join(SUPPORTED_FORMATS)
    raise ValueError(f"unknown format {fmt!r}; expected {supported}")


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return ""
    lines = [
        f"{item.path}:{item.line}:{item.column}: {item.severity.name} {item.rule_id}: {item.message}"
        for item in findings
    ]
    return "\n".join(lines) + "\n"


def render_json(findings: list[Finding]) -> str:
    return json.dumps({"findings": [item.to_dict() for item in findings]}, indent=2) + "\n"


def render_sarif(findings: list[Finding], rules: Iterable[Rule] | None = None) -> str:
    catalog = list(rules) if rules is not None else all_rules()
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Canopy",
                        "version": __version__,
                        "informationUri": "https://github.com/smaefr/canopy",
                        "rules": [_sarif_rule(rule) for rule in catalog],
                    }
                },
                "results": [_sarif_result(item) for item in findings],
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def _sarif_rule(rule: Rule) -> dict[str, object]:
    return {
        "id": rule.id,
        "shortDescription": {"text": rule.message},
        "helpUri": f"https://cwe.mitre.org/data/definitions/{rule.cwe.removeprefix('CWE-')}.html",
        "properties": {
            "cwe": rule.cwe,
            "severity": str(rule.severity),
            "languages": list(rule.languages),
        },
        "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
    }


def _sarif_result(item: Finding) -> dict[str, object]:
    return {
        "ruleId": item.rule_id,
        "level": _SARIF_LEVEL[item.severity],
        "message": {"text": item.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": item.path.replace("\\", "/")},
                    "region": {
                        "startLine": item.line,
                        "startColumn": item.column,
                        "endLine": item.end_line,
                        "endColumn": item.end_column,
                    },
                }
            }
        ],
    }
