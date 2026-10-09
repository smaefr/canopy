# Canopy

A small AST scanner for Java, C, and C++. Canopy parses each file with
tree-sitter, walks the syntax tree, and reports high-signal patterns that often
turn into vulnerabilities.

It does not compile the project, resolve types, or follow data across methods.
A finding means the syntax matched a known-bad shape, not that the program is
definitely exploitable.

## Install

Python 3.11 or newer:

```bash
pip install .
```

Or run from a checkout:

```bash
pip install -e ".[dev]"
canopy scan examples
```

## Usage

```bash
canopy scan PATH
canopy scan PATH --format json
canopy scan PATH --format sarif
canopy scan PATH --severity high
canopy scan PATH --lang java
canopy rules
```

`--lang` overrides the file extension for a single file or a whole directory.
The default text output is one finding per line:

```text
examples/Login.java:6:9: HIGH java-sql-injection: SQL statement built with string concatenation or format
```

Exit status is `1` when any reported finding is at or above `--severity`
(default `low`), and `0` when the scan is clean.

## Rules

| ID | Languages | Severity | CWE | What it flags |
| --- | --- | --- | --- | --- |
| `java-sql-injection` | Java | high | CWE-89 | `execute` / `executeQuery` / `executeUpdate` with `+`, `concat`, or `String.format` |
| `java-command-injection` | Java | high | CWE-78 | `Runtime.exec` or `ProcessBuilder` built with concatenation |
| `java-path-traversal` | Java | medium | CWE-22 | `new File`, `new FileInputStream`, or `Paths.get` with concatenation |
| `java-weak-crypto` | Java | medium | CWE-327 | `MD5` / `SHA-1` digests and `DES` or `ECB` ciphers |
| `java-insecure-deserialization` | Java | high | CWE-502 | `readObject` |
| `java-xxe` | Java | high | CWE-611 | XML factory created in a method that never disables external entities |
| `c-banned-api` | C, C++ | high | CWE-120 | `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `mktemp`, `tmpnam`, unbounded `%s` in `scanf` |
| `c-format-string` | C, C++ | high | CWE-134 | `printf` family / `syslog` whose format argument is not a string literal |
| `c-command-injection` | C, C++ | high | CWE-78 | `system` or `popen` with a non-literal command |
| `hardcoded-credential` | Java, C, C++ | high | CWE-798 | Literal assigned to a password, secret, token, or API key |

## Adding a rule

1. Write a checker in `src/canopy/rules/` that walks a tree-sitter tree and
   returns `Finding` objects.
2. Register a `Rule` with an id, languages, severity, CWE, and message.
3. Add it to `all_rules()` in `src/canopy/rules/__init__.py`.
4. Drop a short vulnerable snippet and a safe snippet under `tests/fixtures/`
   and extend `tests/test_rules.py`.

Keep the matcher local to the call or assignment. If you need cross-method
taint, Canopy is the wrong tool.

## Limitations

- No compiler, no classpath, no include paths, no macros beyond what the
  grammar recovers.
- No interprocedural taint. `String query = a + b; stmt.execute(query)` is not
  flagged; `stmt.execute(a + b)` is.
- `.h` files are parsed as C. `.hpp` / `.hh` / `.hxx` are parsed as C++.
- XXE hardening is a same-method text check, not object tracking.
- Hardcoded-credential matching is a name heuristic. Placeholders such as
  `changeme`, `todo`, `xxx`, and `${ENV}` are ignored.

## License

MIT. See [LICENSE](LICENSE).
