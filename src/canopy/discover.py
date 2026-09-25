from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

LANGUAGE_BY_SUFFIX = {
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "target",
    "build",
    "dist",
}


def language_for_path(path: Path, override: str | None = None) -> str | None:
    if override is not None:
        return override
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def discover(root: Path, lang: str | None = None) -> Iterator[tuple[Path, str]]:
    root = root.expanduser()
    if not root.exists():
        raise FileNotFoundError(root)

    if root.is_file():
        language = language_for_path(root, lang)
        if language is None:
            return
        yield root, language
        return

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        language = language_for_path(path, lang)
        if language is None:
            continue
        yield path, language
