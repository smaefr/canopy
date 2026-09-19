from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            expected = ", ".join(item.name.lower() for item in cls)
            raise ValueError(f"unknown severity {value!r}; expected {expected}") from exc

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    cwe: str
    message: str
    path: str
    line: int
    column: int
    end_line: int
    end_column: int
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = str(self.severity)
        return data
