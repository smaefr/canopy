from __future__ import annotations

import json

from canopy.models import Finding

SUPPORTED_FORMATS = ("text", "json")


def render(findings: list[Finding], fmt: str) -> str:
    if fmt == "json":
        return render_json(findings)
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
