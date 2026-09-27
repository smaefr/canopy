from __future__ import annotations

from collections.abc import Iterator

from tree_sitter import Node

from canopy.models import Finding, Severity


def walk(node: Node) -> Iterator[Node]:
    yield node
    for child in node.children:
        yield from walk(child)


def text_of(node: Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def field(node: Node, name: str) -> Node | None:
    return node.child_by_field_name(name)


def call_args(node: Node) -> list[Node]:
    arguments = field(node, "arguments")
    if arguments is None:
        return []
    return list(arguments.named_children)


def first_arg(node: Node) -> Node | None:
    args = call_args(node)
    return args[0] if args else None


def method_name(node: Node) -> str:
    return text_of(field(node, "name"))


def callee_name(node: Node) -> str:
    function = field(node, "function")
    if function is None:
        return ""
    if function.type == "identifier":
        return text_of(function)
    identifiers = [child for child in walk(function) if child.type == "identifier"]
    return text_of(identifiers[-1]) if identifiers else text_of(function)


def unwrap(node: Node) -> Node:
    current = node
    while current.type == "parenthesized_expression" and current.named_child_count:
        current = current.named_children[0]
    return current


def line_snippet(source: bytes, node: Node) -> str:
    start = source.rfind(b"\n", 0, node.start_byte) + 1
    end = source.find(b"\n", node.start_byte)
    if end == -1:
        end = len(source)
    return source[start:end].decode("utf-8", errors="replace").rstrip()


def string_value(node: Node) -> str | None:
    node = unwrap(node)
    if node.type not in {"string_literal", "concatenated_string", "raw_string_literal"}:
        return None
    chunks: list[str] = []
    for child in walk(node):
        if child.type in {"string_fragment", "string_content", "escape_sequence"}:
            chunks.append(text_of(child))
    if chunks:
        return "".join(chunks)
    raw = text_of(node)
    if len(raw) >= 2 and raw[0] in {'"', "'"}:
        return raw[1:-1]
    return raw


def is_string_literal(node: Node | None) -> bool:
    if node is None:
        return False
    node = unwrap(node)
    return node.type in {"string_literal", "concatenated_string", "raw_string_literal"}


def looks_constructed(node: Node | None) -> bool:
    """True when an expression is built at the call site (concat, format, +)."""
    if node is None:
        return False
    node = unwrap(node)
    if node.type == "binary_expression":
        return any(child.type == "+" for child in node.children)
    if node.type == "method_invocation":
        name = method_name(node)
        receiver = text_of(field(node, "object"))
        if name in {"concat", "formatted"}:
            return True
        if name == "format" and receiver.endswith("String"):
            return True
    return False


def make_finding(
    *,
    rule_id: str,
    severity: Severity | str,
    cwe: str,
    message: str,
    path: str,
    source: bytes,
    node: Node,
) -> Finding:
    start_row, start_col = node.start_point
    end_row, end_col = node.end_point
    parsed = Severity.parse(severity) if isinstance(severity, str) else severity
    return Finding(
        rule_id=rule_id,
        severity=parsed,
        cwe=cwe,
        message=message,
        path=path,
        line=start_row + 1,
        column=start_col + 1,
        end_line=end_row + 1,
        end_column=end_col + 1,
        snippet=line_snippet(source, node),
    )
