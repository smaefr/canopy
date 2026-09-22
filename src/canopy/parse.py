from __future__ import annotations

from tree_sitter import Language, Parser, Tree

_LANGUAGES: dict[str, Language] = {}
_PARSERS: dict[str, Parser] = {}


def language_for(name: str) -> Language:
    cached = _LANGUAGES.get(name)
    if cached is not None:
        return cached

    if name == "java":
        import tree_sitter_java as grammar
    elif name == "c":
        import tree_sitter_c as grammar
    elif name == "cpp":
        import tree_sitter_cpp as grammar
    else:
        raise ValueError(f"unsupported language {name!r}")

    language = Language(grammar.language())
    _LANGUAGES[name] = language
    return language


def parser_for(name: str) -> Parser:
    cached = _PARSERS.get(name)
    if cached is not None:
        return cached

    parser = Parser(language_for(name))
    _PARSERS[name] = parser
    return parser


def parse_source(source: bytes, language: str) -> Tree:
    return parser_for(language).parse(source)
