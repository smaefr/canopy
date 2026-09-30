from __future__ import annotations

from tree_sitter import Node

from canopy.astutil import (
    call_args,
    field,
    first_arg,
    looks_constructed,
    make_finding,
    method_name,
    string_value,
    text_of,
    walk,
)
from canopy.models import Finding
from canopy.rules import Rule

SQL_METHODS = {"execute", "executeQuery", "executeUpdate"}
PATH_TYPES = {"File", "FileInputStream"}
WEAK_DIGESTS = {"MD5", "SHA-1", "SHA1"}
XXE_FACTORIES = {"DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory"}
XXE_HARDENING = (
    "disallow-doctype-decl",
    "external-general-entities",
    "external-parameter-entities",
    "accessExternalDTD",
    "accessExternalSchema",
    "ACCESS_EXTERNAL_DTD",
    "ACCESS_EXTERNAL_SCHEMA",
    "isSupportingExternalEntities",
    "setExpandEntityReferences",
)


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
        named = [
            child
            for child in node.named_children
            if child.type in {"type_identifier", "generic_type"}
        ]
        return named[0] if named else None
    if type_node.type == "generic_type":
        inner = type_node.child_by_field_name("type")
        return inner if inner is not None else type_node
    return type_node


def _path_traversal(root: Node, source: bytes, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(root):
        if node.type == "object_creation_expression":
            created = text_of(_created_type(node))
            if created not in PATH_TYPES:
                continue
            if not any(looks_constructed(argument) for argument in call_args(node)):
                continue
        elif node.type == "method_invocation":
            if method_name(node) != "get":
                continue
            if not text_of(field(node, "object")).endswith("Paths"):
                continue
            if not any(looks_constructed(argument) for argument in call_args(node)):
                continue
        else:
            continue
        findings.append(
            make_finding(
                rule_id="java-path-traversal",
                severity="medium",
                cwe="CWE-22",
                message="Filesystem path built with string concatenation",
                path=path,
                source=source,
                node=node,
            )
        )
    return findings


def _weak_crypto(root: Node, source: bytes, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(root):
        if node.type != "method_invocation" or method_name(node) != "getInstance":
            continue
        receiver = text_of(field(node, "object"))
        algorithm = string_value(first_arg(node) or node)
        if algorithm is None:
            continue
        if receiver.endswith("MessageDigest") and _is_weak_digest(algorithm):
            message = f"Weak message digest {algorithm!r}"
        elif receiver.endswith("Cipher") and _is_weak_cipher(algorithm):
            message = f"Weak or ECB cipher {algorithm!r}"
        else:
            continue
        findings.append(
            make_finding(
                rule_id="java-weak-crypto",
                severity="medium",
                cwe="CWE-327",
                message=message,
                path=path,
                source=source,
                node=node,
            )
        )
    return findings


def _is_weak_digest(algorithm: str) -> bool:
    normalized = algorithm.strip().upper().replace("_", "-")
    return normalized in WEAK_DIGESTS


def _is_weak_cipher(algorithm: str) -> bool:
    upper = algorithm.upper()
    return "DES" in upper or "/ECB" in upper or upper.startswith("ECB")


def _insecure_deserialization(root: Node, source: bytes, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk(root):
        if node.type != "method_invocation" or method_name(node) != "readObject":
            continue
        findings.append(
            make_finding(
                rule_id="java-insecure-deserialization",
                severity="high",
                cwe="CWE-502",
                message="Java deserialization via ObjectInputStream.readObject",
                path=path,
                source=source,
                node=node,
            )
        )
    return findings


def _xxe(root: Node, source: bytes, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for method in walk(root):
        if method.type != "method_declaration":
            continue
        if _method_hardens_xml(method):
            continue
        for node in walk(method):
            if not _is_xml_factory(node):
                continue
            findings.append(
                make_finding(
                    rule_id="java-xxe",
                    severity="high",
                    cwe="CWE-611",
                    message="XML factory created without disabling external entities",
                    path=path,
                    source=source,
                    node=node,
                )
            )
    return findings


def _is_xml_factory(node: Node) -> bool:
    if node.type != "method_invocation":
        return False
    name = method_name(node)
    if name not in {"newInstance", "newFactory"}:
        return False
    return text_of(field(node, "object")) in XXE_FACTORIES


def _method_hardens_xml(method: Node) -> bool:
    body = text_of(method)
    return any(marker in body for marker in XXE_HARDENING)


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
    Rule(
        id="java-path-traversal",
        languages=("java",),
        severity="medium",
        cwe="CWE-22",
        message="Filesystem path built with string concatenation",
        check=_path_traversal,
    ),
    Rule(
        id="java-weak-crypto",
        languages=("java",),
        severity="medium",
        cwe="CWE-327",
        message="Weak hash or cipher algorithm",
        check=_weak_crypto,
    ),
    Rule(
        id="java-insecure-deserialization",
        languages=("java",),
        severity="high",
        cwe="CWE-502",
        message="Java deserialization via ObjectInputStream.readObject",
        check=_insecure_deserialization,
    ),
    Rule(
        id="java-xxe",
        languages=("java",),
        severity="high",
        cwe="CWE-611",
        message="XML factory created without disabling external entities",
        check=_xxe,
    ),
]
