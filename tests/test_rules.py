from __future__ import annotations

from pathlib import Path

import pytest

from canopy.engine import scan_path

FIXTURES = Path(__file__).parent / "fixtures"

VULN_CASES = [
    ("java/sql_vuln.java", "java-sql-injection", 3),
    ("java/command_vuln.java", "java-command-injection", 2),
    ("java/path_vuln.java", "java-path-traversal", 3),
    ("java/crypto_vuln.java", "java-weak-crypto", 4),
    ("java/deser_vuln.java", "java-insecure-deserialization", 1),
    ("java/xxe_vuln.java", "java-xxe", 1),
    ("java/secret_vuln.java", "hardcoded-credential", 2),
    ("c/banned_vuln.c", "c-banned-api", 8),
    ("c/format_vuln.c", "c-format-string", 5),
    ("c/command_vuln.c", "c-command-injection", 2),
    ("c/secret_vuln.c", "hardcoded-credential", 2),
    ("cpp/command_vuln.cpp", "c-command-injection", 1),
]

SAFE_FILES = [
    "java/sql_safe.java",
    "java/command_safe.java",
    "java/path_safe.java",
    "java/crypto_safe.java",
    "java/deser_safe.java",
    "java/xxe_safe.java",
    "java/secret_safe.java",
    "c/banned_safe.c",
    "c/format_safe.c",
    "c/command_safe.c",
    "c/secret_safe.c",
    "cpp/command_safe.cpp",
]


def _ids(relative: str) -> list[str]:
    findings = scan_path(FIXTURES / relative)
    return [item.rule_id for item in findings]


@pytest.mark.parametrize(("relative", "rule_id", "count"), VULN_CASES)
def test_vulnerable_fixture_flags_rule(relative: str, rule_id: str, count: int) -> None:
    ids = _ids(relative)
    matched = [item for item in ids if item == rule_id]
    assert matched, f"expected {rule_id} in {ids} for {relative}"
    assert len(matched) == count


@pytest.mark.parametrize("relative", SAFE_FILES)
def test_safe_fixture_is_clean(relative: str) -> None:
    assert _ids(relative) == []
