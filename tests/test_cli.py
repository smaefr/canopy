from __future__ import annotations

import json
from pathlib import Path

from canopy.cli import main
from canopy.rules import all_rules

FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_text_reports_finding(capsys) -> None:
    target = FIXTURES / "java" / "sql_vuln.java"
    assert main(["scan", str(target)]) == 1
    out = capsys.readouterr().out
    assert "java-sql-injection" in out
    assert str(target) in out or target.name in out


def test_scan_json_and_sarif(capsys) -> None:
    target = FIXTURES / "c" / "command_vuln.c"
    assert main(["scan", str(target), "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    ids = {item["rule_id"] for item in payload["findings"]}
    assert "c-command-injection" in ids

    assert main(["scan", str(target), "--format", "sarif"]) == 1
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert any(item["ruleId"] == "c-command-injection" for item in results)


def test_severity_filter_hides_medium(capsys) -> None:
    target = FIXTURES / "java" / "path_vuln.java"
    assert main(["scan", str(target), "--severity", "high"]) == 0
    assert capsys.readouterr().out == ""


def test_rules_lists_catalog(capsys) -> None:
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    for rule in all_rules():
        assert rule.id in out


def test_missing_path_is_error(capsys) -> None:
    assert main(["scan", "/tmp/canopy-does-not-exist-xyz"]) == 2
    assert "path not found" in capsys.readouterr().err
