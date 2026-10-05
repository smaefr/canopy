from __future__ import annotations

import re

from tree_sitter import Node

from canopy.astutil import field, make_finding, string_value, text_of, unwrap, walk
from canopy.models import Finding
from canopy.rules import Rule

SECRET_NAME = re.compile(
    r"(password|passwd|secret|token|api[_-]?key)",
    re.IGNORECASE,
)
PLACEHOLDERS = {
    "password",
    "passwd",
    "secret",
    "token",
    "changeme",
    "changeit",
    "todo",
    "xxx",
    "xxxx",
    "placeholder",
}


def _hardcoded_credential(root: Node, source: bytes, path: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[int, int]] = set()
    for node in walk(root):
        name, value_node = _assignment(node)
        if name is None or value_node is None:
            continue
        if not SECRET_NAME.search(name):
            continue
        value = string_value(value_node)
        if value is None or _is_placeholder(value):
            continue
        key = (node.start_byte, node.end_byte)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            make_finding(
                rule_id="hardcoded-credential",
                severity="high",
                cwe="CWE-798",
                message=f"Hardcoded credential assigned to {name!r}",
                path=path,
                source=source,
                node=value_node,
            )
        )
    return findings


def _assignment(node: Node) -> tuple[str | None, Node | None]:
    if node.type in {"variable_declarator", "init_declarator"}:
        return _declarator_name(node), _value_node(node)
    if node.type == "assignment_expression":
        left = unwrap(field(node, "left") or node.named_children[0])
        right = field(node, "right")
        if right is None and len(node.named_children) > 1:
            right = node.named_children[-1]
        return _name_from_lhs(left), right
    return None, None


def _value_node(node: Node) -> Node | None:
    value = field(node, "value")
    if value is not None:
        return value
    for child in reversed(node.named_children):
        if child.type in {"identifier", "array_declarator", "pointer_declarator"}:
            continue
        if child.type in {"string_literal", "concatenated_string", "raw_string_literal"}:
            return child
    return None


def _declarator_name(node: Node) -> str | None:
    name = field(node, "name")
    if name is not None:
        return text_of(name)
    for child in walk(node):
        if child.type == "identifier":
            return text_of(child)
    return None


def _name_from_lhs(node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type == "identifier":
        return text_of(node)
    if node.type in {"field_access", "field_expression", "pointer_expression"}:
        identifiers = [text_of(child) for child in walk(node) if child.type == "identifier"]
        return identifiers[-1] if identifiers else None
    identifiers = [text_of(child) for child in walk(node) if child.type == "identifier"]
    return identifiers[-1] if identifiers else None


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 4:
        return True
    if stripped.startswith("$"):
        return True
    if stripped.lower() in PLACEHOLDERS:
        return True
    lowered = stripped.lower()
    return set(lowered) <= {"x", "*"}


SECRETS_RULES = [
    Rule(
        id="hardcoded-credential",
        languages=("java", "c", "cpp"),
        severity="high",
        cwe="CWE-798",
        message="Hardcoded password, secret, token, or API key",
        check=_hardcoded_credential,
    )
]
