from __future__ import annotations

import re

from tree_sitter import Node

from canopy.astutil import (
    call_args,
    callee_name,
    first_arg,
    is_string_literal,
    make_finding,
    string_value,
    walk,
)
from canopy.models import Finding
from canopy.rules import Rule

BANNED_APIS = {
    "gets": "Unbounded gets() reads into a buffer",
    "strcpy": "strcpy does not bound the destination buffer",
    "strcat": "strcat does not bound the destination buffer",
    "sprintf": "sprintf does not bound the destination buffer",
    "vsprintf": "vsprintf does not bound the destination buffer",
    "mktemp": "mktemp is racy and creates a predictable file name",
    "tmpnam": "tmpnam is racy and creates a predictable file name",
}

SCANF_FUNCS = {
    "scanf": 0,
    "fscanf": 1,
    "sscanf": 1,
}

FORMAT_FUNCS = {
    "printf": 0,
    "fprintf": 1,
    "sprintf": 1,
    "snprintf": 2,
    "syslog": 1,
}

UNBOUNDED_S = re.compile(r"(?<!%)%s")


def _nth_arg(node: Node, index: int) -> Node | None:
    args = call_args(node)
    if index >= len(args):
        return None
    return args[index]


def _banned_api(root: Node, source: bytes, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(root):
        if node.type != "call_expression":
            continue
        name = callee_name(node)
        if name in BANNED_APIS:
            findings.append(
                make_finding(
                    rule_id="c-banned-api",
                    severity="high",
                    cwe="CWE-120",
                    message=BANNED_APIS[name],
                    path=path,
                    source=source,
                    node=node,
                )
            )
            continue
        index = SCANF_FUNCS.get(name)
        if index is None:
            continue
        fmt = _nth_arg(node, index)
        value = string_value(fmt) if fmt is not None else None
        if value is None or not UNBOUNDED_S.search(value):
            continue
        findings.append(
            make_finding(
                rule_id="c-banned-api",
                severity="high",
                cwe="CWE-120",
                message=f"{name} uses an unbounded %s conversion",
                path=path,
                source=source,
                node=node,
            )
        )
    return findings


def _format_string(root: Node, source: bytes, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(root):
        if node.type != "call_expression":
            continue
        name = callee_name(node)
        index = FORMAT_FUNCS.get(name)
        if index is None:
            continue
        fmt = _nth_arg(node, index)
        if fmt is None or is_string_literal(fmt):
            continue
        findings.append(
            make_finding(
                rule_id="c-format-string",
                severity="high",
                cwe="CWE-134",
                message=f"{name} format argument is not a string literal",
                path=path,
                source=source,
                node=node,
            )
        )
    return findings


def _command_injection(root: Node, source: bytes, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(root):
        if node.type != "call_expression":
            continue
        name = callee_name(node)
        if name not in {"system", "popen"}:
            continue
        command = first_arg(node)
        if command is None or is_string_literal(command):
            continue
        findings.append(
            make_finding(
                rule_id="c-command-injection",
                severity="high",
                cwe="CWE-78",
                message=f"{name} command is not a string literal",
                path=path,
                source=source,
                node=node,
            )
        )
    return findings


C_FAMILY_RULES = [
    Rule(
        id="c-banned-api",
        languages=("c", "cpp"),
        severity="high",
        cwe="CWE-120",
        message="Unsafe C library function",
        check=_banned_api,
    ),
    Rule(
        id="c-format-string",
        languages=("c", "cpp"),
        severity="high",
        cwe="CWE-134",
        message="Non-literal format string",
        check=_format_string,
    ),
    Rule(
        id="c-command-injection",
        languages=("c", "cpp"),
        severity="high",
        cwe="CWE-78",
        message="system or popen with a non-literal command",
        check=_command_injection,
    ),
]
