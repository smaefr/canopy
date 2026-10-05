from __future__ import annotations

from collections.abc import Callable, Sequence

from tree_sitter import Node

from canopy.models import Finding

Checker = Callable[[Node, bytes, str], list[Finding]]


class Rule:
    def __init__(
        self,
        *,
        id: str,
        languages: Sequence[str],
        severity: str,
        cwe: str,
        message: str,
        check: Checker,
    ) -> None:
        from canopy.models import Severity

        self.id = id
        self.languages = tuple(languages)
        self.severity = Severity.parse(severity)
        self.cwe = cwe
        self.message = message
        self._check = check

    def applies_to(self, language: str) -> bool:
        return language in self.languages

    def check(self, root: Node, source: bytes, path: str) -> list[Finding]:
        return self._check(root, source, path)


def all_rules() -> list[Rule]:
    from canopy.rules.c_family import C_FAMILY_RULES
    from canopy.rules.java import JAVA_RULES
    from canopy.rules.secrets import SECRETS_RULES

    return [*JAVA_RULES, *C_FAMILY_RULES, *SECRETS_RULES]
