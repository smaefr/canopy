from __future__ import annotations

from canopy.models import Finding, Severity
from canopy.report import render, render_sarif
from canopy.rules import all_rules


def _finding() -> Finding:
    return Finding(
        rule_id="java-sql-injection",
        severity=Severity.HIGH,
        cwe="CWE-89",
        message="SQL statement built with string concatenation or format",
        path="Login.java",
        line=4,
        column=9,
        end_line=4,
        end_column=40,
        snippet='stmt.executeQuery("SELECT " + name);',
    )


def test_text_and_json_renderers() -> None:
    findings = [_finding()]
    text = render(findings, "text")
    assert "Login.java:4:9: HIGH java-sql-injection:" in text
    payload = render(findings, "json")
    assert '"rule_id": "java-sql-injection"' in payload
    assert render([], "text") == ""


def test_sarif_includes_rules_and_results() -> None:
    document = render_sarif([_finding()])
    assert '"version": "2.1.0"' in document
    assert '"ruleId": "java-sql-injection"' in document
    for rule in all_rules():
        assert f'"id": "{rule.id}"' in document
