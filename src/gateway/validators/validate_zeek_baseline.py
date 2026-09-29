#!/usr/bin/env python3
"""
Jeffrey Toolkit — baseline conservative Zeek baseline validator.

This is an independent structural/safety validator for generated Zeek scripts
while no approved Zeek engine is installed on the production host.

IMPORTANT:
- This is NOT equivalent to `zeek -C`, script loading, or real Zeek parsing.
- It does NOT execute generated scripts.
- It intentionally rejects package/load directives and external-command
  execution primitives in baseline-v1.
- A real Zeek engine remains the required second validation layer before
  Jeffrey may claim engine-equivalent script validation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

VALIDATOR_VERSION = "zeek-baseline-v1"
VALIDATION_LEVEL = "baseline_not_engine"
MAX_CONTENT_BYTES = 131072
MAX_HANDLERS = 32

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
SCOPED_IDENT = rf"{IDENT}(?:::{IDENT})*"

MODULE_RE = re.compile(rf"(?im)^[ \t]*module[ \t]+({SCOPED_IDENT})[ \t]*;[ \t]*$")
HANDLER_START_RE = re.compile(
    rf"(?ims)^[ \t]*(event|hook|function)[ \t]+({SCOPED_IDENT})[ \t]*\("
)
DIRECTIVE_RE = re.compile(r"(?im)^[ \t]*@[A-Za-z_-]+")
BLOCKED_RE = re.compile(
    r"(?i)(?:"
    r"\bsystem\s*\(|"
    r"\bExec::run(?:_shell)?\s*\(|"
    r"\bexecute_command\s*\(|"
    r"\bPipe::[A-Za-z_][A-Za-z0-9_]*"
    r")"
)
REDEF_RE = re.compile(r"(?im)^[ \t]*redef\b")
EXPORT_RE = re.compile(r"(?im)^[ \t]*export[ \t]*\{")


def problem(path: str, message: str) -> dict[str, str]:
    return {"path": path, "message": message}


def result(valid: bool, errors: list[dict[str, str]], warnings: list[str] | None = None) -> dict[str, Any]:
    return {
        "valid": valid,
        "validator_version": VALIDATOR_VERSION,
        "validation_level": VALIDATION_LEVEL,
        "engine_equivalent": False,
        "zeek_engine": "not_available",
        "errors": errors,
        "warnings": warnings or [],
    }


def strip_hash_comments(text: str) -> str:
    """
    Remove Zeek # comments while preserving line count.
    A # begins a comment only outside strings and when it is at line start or
    follows whitespace. This intentionally avoids treating common regex text as
    a comment opener.
    """
    out: list[str] = []
    for raw in text.splitlines(keepends=True):
        in_string = False
        escaped = False
        cut = None
        for i, ch in enumerate(raw):
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue

            if ch == '"':
                in_string = True
                continue

            if ch == "#" and (i == 0 or raw[i - 1].isspace()):
                cut = i
                break

        if cut is None:
            out.append(raw)
        else:
            suffix = raw[cut:]
            newline = ""
            if suffix.endswith("\r\n"):
                newline = "\r\n"
            elif suffix.endswith("\n"):
                newline = "\n"
            elif suffix.endswith("\r"):
                newline = "\r"
            out.append(raw[:cut] + newline)

    return "".join(out)


def balance(text: str) -> tuple[bool, str]:
    """
    Balance (), {}, [] while ignoring quoted strings and conservative /regex/
    literals. This is a structural guard, not a Zeek parser.
    """
    pairs = {"(": ")", "{": "}", "[": "]"}
    inverse = {v: k for k, v in pairs.items()}
    stack: list[str] = []
    in_string = False
    in_regex = False
    escaped = False
    i = 0

    def previous_nonspace(pos: int) -> str:
        j = pos - 1
        while j >= 0 and text[j].isspace():
            j -= 1
        return text[j] if j >= 0 else ""

    while i < len(text):
        ch = text[i]

        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if in_regex:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "/":
                in_regex = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            i += 1
            continue

        if ch == "/":
            prev = previous_nonspace(i)
            # Conservative recognition of Zeek pattern literals in contexts
            # such as: if ( /foo/ in x ) or x == /foo/
            if prev in {"", "(", "=", "!", ",", "[", ":"}:
                in_regex = True
                i += 1
                continue

        if ch in pairs:
            stack.append(ch)
        elif ch in inverse:
            if not stack or stack[-1] != inverse[ch]:
                return False, f"unexpected closing delimiter {ch}"
            stack.pop()

        i += 1

    if in_string:
        return False, "unterminated quoted string"
    if in_regex:
        return False, "unterminated regex literal"
    if stack:
        return False, f"unclosed delimiter {stack[-1]}"
    return True, ""


def find_matching_paren(text: str, start: int) -> int:
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
            if depth < 0:
                return -1
    return -1


def validate_handler_declarations(text: str, errors: list[dict[str, str]]) -> int:
    handlers = list(HANDLER_START_RE.finditer(text))
    if not handlers:
        errors.append(
            problem(
                "$.content.handlers",
                "baseline-v1 requires at least one event, hook, or function declaration",
            )
        )
        return 0

    if len(handlers) > MAX_HANDLERS:
        errors.append(
            problem(
                "$.content.handlers",
                f"more than {MAX_HANDLERS} handlers/functions are not allowed",
            )
        )

    for index, match in enumerate(handlers):
        kind = match.group(1).lower()
        name = match.group(2)
        open_paren = text.find("(", match.start())
        close_paren = find_matching_paren(text, open_paren)
        if close_paren < 0:
            errors.append(
                problem(
                    f"$.content.handlers[{index}]",
                    f"{kind} {name} has an unterminated parameter list",
                )
            )
            continue

        # From closing ')' to the opening body '{' we permit only whitespace
        # and a conservative function return type such as ': bool'.
        body_open = text.find("{", close_paren + 1)
        if body_open < 0:
            errors.append(
                problem(
                    f"$.content.handlers[{index}]",
                    f"{kind} {name} has no opening body brace",
                )
            )
            continue

        between = text[close_paren + 1 : body_open].strip()
        if kind in {"event", "hook"}:
            if between:
                errors.append(
                    problem(
                        f"$.content.handlers[{index}]",
                        f"{kind} {name} must not declare a return type in baseline-v1",
                    )
                )
        else:
            if between and not re.fullmatch(
                rf":[ \t]*(?:{SCOPED_IDENT}|bool|count|int|string|double|time|interval|addr|port)",
                between,
            ):
                errors.append(
                    problem(
                        f"$.content.handlers[{index}]",
                        f"unsupported function return type syntax: {between}",
                    )
                )

    return len(handlers)


def validate_basic_statement_safety(text: str, errors: list[dict[str, str]]) -> None:
    if DIRECTIVE_RE.search(text):
        errors.append(
            problem(
                "$.content",
                "@load/@if/package-style directives are intentionally unsupported in baseline-v1",
            )
        )

    blocked = BLOCKED_RE.search(text)
    if blocked:
        errors.append(
            problem(
                "$.content",
                f"external command/process primitive is not allowed: {blocked.group(0)}",
            )
        )

    if REDEF_RE.search(text):
        errors.append(
            problem(
                "$.content",
                "redef is intentionally unsupported until a real Zeek runtime/module set is validated",
            )
        )

    if EXPORT_RE.search(text):
        errors.append(
            problem(
                "$.content",
                "export blocks are intentionally unsupported in baseline-v1",
            )
        )


def validate_modules(text: str, errors: list[dict[str, str]]) -> None:
    module_matches = list(MODULE_RE.finditer(text))
    module_keyword_count = len(re.findall(r"(?im)^[ \t]*module\b", text))

    if module_keyword_count != len(module_matches):
        errors.append(
            problem(
                "$.content.module",
                "invalid module declaration syntax",
            )
        )

    if len(module_matches) > 1:
        errors.append(
            problem(
                "$.content.module",
                "at most one module declaration is allowed in baseline-v1",
            )
        )


def validate_content(content: str) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    warnings = [
        "baseline validator is not Zeek-engine-equivalent",
        "real Zeek parser/load validation is still required when approved engine tooling becomes available",
        "baseline-v1 intentionally rejects @load, redef, export blocks, and external-command primitives",
    ]

    if not isinstance(content, str):
        return result(False, [problem("$.content", "content must be a string")], warnings)

    try:
        raw = content.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return result(False, [problem("$.content", "content must be valid UTF-8")], warnings)

    if len(raw) > MAX_CONTENT_BYTES:
        errors.append(problem("$.content", f"content exceeds {MAX_CONTENT_BYTES} bytes"))
    if "\x00" in content:
        errors.append(problem("$.content", "NUL bytes are not allowed"))
    if "```" in content:
        errors.append(problem("$.content", "markdown code fences are not allowed"))

    for ch in content:
        if ord(ch) < 32 and ch not in "\r\n\t":
            errors.append(problem("$.content", "unsupported control character"))
            break

    clean = strip_hash_comments(content).strip()
    if not clean:
        errors.append(problem("$.content", "script is empty after comments"))
        return result(False, errors, warnings)

    ok, message = balance(clean)
    if not ok:
        errors.append(problem("$.content", f"unbalanced syntax: {message}"))

    validate_basic_statement_safety(clean, errors)
    validate_modules(clean, errors)
    validate_handler_declarations(clean, errors)

    return result(not errors, errors, warnings)


def validate_envelope(obj: Any, schema_path: Path) -> dict[str, Any]:
    try:
        import jsonschema
    except Exception as exc:
        return result(False, [problem("$", f"jsonschema import failed: {exc}")])

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        issues = list(jsonschema.Draft202012Validator(schema).iter_errors(obj))
    except Exception as exc:
        return result(False, [problem("$", f"schema validation failure: {exc}")])

    if issues:
        errors: list[dict[str, str]] = []
        for issue in issues:
            path = "$"
            for item in issue.path:
                path += f"[{json.dumps(item)}]" if isinstance(item, str) else f"[{item}]"
            errors.append(problem(path, issue.message))
        return result(False, errors)

    return validate_content(obj["content"])


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--content", action="store_true")
    mode.add_argument("--envelope", action="store_true")
    parser.add_argument(
        "--schema",
        default="/opt/jeffrey-gateway/schemas/zeek-output-v1.schema.json",
    )
    args = parser.parse_args()

    raw = sys.stdin.read()
    if args.content:
        out = validate_content(raw)
    else:
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as exc:
            out = result(False, [problem("$", f"invalid JSON: {exc.msg}")])
        else:
            out = validate_envelope(obj, Path(args.schema))

    print(json.dumps(out, ensure_ascii=False, sort_keys=True))
    return 0 if out["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
