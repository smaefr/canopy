from __future__ import annotations

from tree_sitter import Node

from canopy.astutil import (
    call_args,
    first_arg,
    looks_constructed,
    make_finding,
    method_name,
    text_of,
    walk,
)
from canopy.models import Finding
from canopy.rules import Rule

SQL_METHODS = {"execute", "executeQuery", "executeUpdate"}


def _sql_injection(root: Node, source: bytes, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(root):
        if node.type != "method_invocation" or method_name(node) not in SQL_METHODS:
            continue
        argument = first_arg(node)
        if not looks_constructed(argument):
            continue
        findings.append(
            make_finding(
                rule_id="java-sql-injection",
                severity="high",
                cwe="CWE-89",
                message="SQL statement built with string concatenation or format",
                path=path,
                source=source,
                node=node,
            )
        )
    return findings


def _command_injection(root: Node, source: bytes, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(root):
        if _is_runtime_exec(node) or _is_process_builder(node):
            findings.append(
                make_finding(
                    rule_id="java-command-injection",
                    severity="high",
                    cwe="CWE-78",
                    message="Operating system command built with string concatenation",
                    path=path,
                    source=source,
                    node=node,
                )
            )
    return findings


def _is_runtime_exec(node: Node) -> bool:
    if node.type != "method_invocation" or method_name(node) != "exec":
        return False
    return looks_constructed(first_arg(node))


def _is_process_builder(node: Node) -> bool:
    if node.type != "object_creation_expression":
        return False
    if text_of(_created_type(node)) != "ProcessBuilder":
        return False
    return any(looks_constructed(argument) for argument in call_args(node))


def _created_type(node: Node) -> Node | None:
    type_node = node.child_by_field_name("type")
    if type_node is None:
        named = [child for child in node.named_children if child.type in {"type_identifier", "generic_type"}]
        return named[0] if named else None
    if type_node.type == "generic_type":
        inner = type_node.child_by_field_name("type")
        return inner if inner is not None else type_node
    return type_node


JAVA_RULES = [
    Rule(
        id="java-sql-injection",
        languages=("java",),
        severity="high",
        cwe="CWE-89",
        message="SQL statement built with string concatenation or format",
        check=_sql_injection,
    ),
    Rule(
        id="java-command-injection",
        languages=("java",),
        severity="high",
        cwe="CWE-78",
        message="Operating system command built with string concatenation",
        check=_command_injection,
    ),
]
