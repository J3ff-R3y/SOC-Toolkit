#!/usr/bin/env python3
"""
Jeffrey Toolkit — baseline conservative YARA baseline validator.

This validator intentionally implements a constrained YARA-v1 subset so the
production host can gain an independent deterministic control layer before an
approved YARA compiler/engine is staged offline.

IMPORTANT:
- It is NOT compiler-equivalent.
- It does NOT execute or load generated rules.
- It rejects imports/includes in baseline-v1.
- It accepts exactly one rule per artifact.
- It validates structure, sections, string declarations, identifier references
  and delimiter balance within the supported subset.

A real YARA compiler remains the target second validation layer once approved
offline YARA tooling is available.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

VALIDATOR_VERSION = "yara-baseline-v1"
MAX_CONTENT_BYTES = 131072
MAX_STRINGS = 256

RULE_RE = re.compile(
    r"(?im)^[ \t]*(?:(global|private)[ \t]+)?rule[ \t]+"
    r"([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:[ \t]*:[ \t]*([A-Za-z0-9_][A-Za-z0-9_.-]*(?:[ \t]+[A-Za-z0-9_][A-Za-z0-9_.-]*)*))?"
    r"[ \t]*\{"
)

SECTION_RE = re.compile(r"(?im)^[ \t]*(meta|strings|condition)[ \t]*:[ \t]*(?:\r?\n|$)")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
STRING_ID_RE = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")
REF_RE = re.compile(r"(?<![A-Za-z0-9_])([\$#@])([A-Za-z_][A-Za-z0-9_]*)(\*)?")

ALLOWED_MODIFIER_RE = re.compile(
    r"^(?:ascii|wide|nocase|fullword|base64|base64wide|"
    r"xor(?:\([0-9]{1,3}(?:-[0-9]{1,3})?\))?)$",
    re.IGNORECASE,
)

META_LINE_RE = re.compile(
    r'^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*'
    r'(?:"(?:\\.|[^"\\])*"|-?[0-9]+|true|false)[ \t]*$',
    re.IGNORECASE,
)


def result(valid: bool, errors: list[dict[str, str]], warnings: list[str] | None = None) -> dict[str, Any]:
    return {
        "valid": valid,
        "validator_version": VALIDATOR_VERSION,
        "validation_level": "baseline_not_compiler",
        "compiler_equivalent": False,
        "engine": "jeffrey_internal_baseline",
        "errors": errors,
        "warnings": warnings or [],
    }


def err(path: str, message: str) -> dict[str, str]:
    return {"path": path, "message": message}


def strip_comments(text: str) -> str:
    """Remove // and /* */ comments while preserving quoted strings and newlines."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    escaped = False

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and nxt == "/":
            out.extend("  ")
            i += 2
            while i < n and text[i] not in "\r\n":
                out.append(" ")
                i += 1
            continue

        if ch == "/" and nxt == "*":
            out.extend("  ")
            i += 2
            closed = False
            while i < n:
                if i + 1 < n and text[i] == "*" and text[i + 1] == "/":
                    out.extend("  ")
                    i += 2
                    closed = True
                    break
                out.append("\n" if text[i] == "\n" else "\r" if text[i] == "\r" else " ")
                i += 1
            if not closed:
                raise ValueError("unterminated block comment")
            continue

        out.append(ch)
        i += 1

    if in_string:
        raise ValueError("unterminated quoted string")
    return "".join(out)


def balanced(text: str, pairs: dict[str, str]) -> tuple[bool, str]:
    """Balance delimiters while ignoring quoted strings and slash regexes."""
    stack: list[str] = []
    inverse = {v: k for k, v in pairs.items()}
    in_string = False
    in_regex = False
    escaped = False
    i = 0

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

        # Only treat slash as regex opener when it looks like a YARA regex
        # literal. This is intentionally conservative.
        if ch == "/" and (i == 0 or text[i - 1] in "=(:, \t\r\n"):
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


def split_literal_and_modifiers(expr: str) -> tuple[str, list[str]] | None:
    expr = expr.strip()
    if not expr:
        return None

    if expr[0] == '"':
        escaped = False
        for i in range(1, len(expr)):
            ch = expr[i]
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                return expr[: i + 1], expr[i + 1 :].strip().split()
        return None

    if expr[0] == "/":
        escaped = False
        for i in range(1, len(expr)):
            ch = expr[i]
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "/":
                # Consume optional regex flags i/s immediately after /
                j = i + 1
                while j < len(expr) and expr[j] in "is":
                    j += 1
                return expr[:j], expr[j:].strip().split()
        return None

    if expr[0] == "{":
        depth = 0
        for i, ch in enumerate(expr):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return expr[: i + 1], expr[i + 1 :].strip().split()
                if depth < 0:
                    return None
        return None

    return None


def validate_meta(section: str, errors: list[dict[str, str]]) -> None:
    seen: set[str] = set()
    for line_no, raw in enumerate(section.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        m = META_LINE_RE.match(raw)
        if not m:
            errors.append(err(f"$.content.meta.line{line_no}", "unsupported or invalid meta assignment"))
            continue
        key = m.group(1)
        if key in seen:
            errors.append(err(f"$.content.meta.{key}", "duplicate meta key"))
        seen.add(key)


def validate_strings(section: str, errors: list[dict[str, str]]) -> set[str]:
    ids: set[str] = set()
    count = 0
    for line_no, raw in enumerate(section.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue

        if "=" not in line:
            errors.append(err(f"$.content.strings.line{line_no}", "string declaration must contain '='"))
            continue

        left, right = line.split("=", 1)
        sid = left.strip()
        if not STRING_ID_RE.match(sid):
            errors.append(err(f"$.content.strings.line{line_no}", "invalid YARA string identifier"))
            continue

        if sid in ids:
            errors.append(err(f"$.content.strings.{sid}", "duplicate YARA string identifier"))
        ids.add(sid)
        count += 1
        if count > MAX_STRINGS:
            errors.append(err("$.content.strings", f"more than {MAX_STRINGS} strings are not allowed"))
            break

        parsed = split_literal_and_modifiers(right)
        if parsed is None:
            errors.append(err(f"$.content.strings.{sid}", "unsupported or unterminated string/regex/hex literal"))
            continue

        literal, modifiers = parsed
        if literal.startswith("{"):
            ok, message = balanced(literal, {"{": "}", "(": ")", "[": "]"})
            if not ok:
                errors.append(err(f"$.content.strings.{sid}", f"invalid hex literal delimiters: {message}"))

        for modifier in modifiers:
            if not ALLOWED_MODIFIER_RE.match(modifier):
                errors.append(err(f"$.content.strings.{sid}", f"unsupported modifier: {modifier}"))

    return ids


def validate_condition(section: str, string_ids: set[str], errors: list[dict[str, str]]) -> None:
    condition = section.strip()
    if not condition:
        errors.append(err("$.content.condition", "condition must not be empty"))
        return

    ok, message = balanced(condition, {"(": ")", "[": "]"})
    if not ok:
        errors.append(err("$.content.condition", f"unbalanced condition delimiters: {message}"))

    known = {sid[1:] for sid in string_ids}
    for prefix, name, wildcard in REF_RE.findall(condition):
        if wildcard:
            if not any(k.startswith(name) for k in known):
                errors.append(err("$.content.condition", f"unknown wildcard string reference: {prefix}{name}*"))
        elif name not in known:
            errors.append(err("$.content.condition", f"unknown string reference: {prefix}{name}"))


def validate_content(content: str) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    warnings: list[str] = []

    if not isinstance(content, str):
        return result(False, [err("$.content", "content must be a string")])

    raw_bytes = content.encode("utf-8", errors="strict")
    if len(raw_bytes) > MAX_CONTENT_BYTES:
        errors.append(err("$.content", f"content exceeds {MAX_CONTENT_BYTES} bytes"))

    if "\x00" in content:
        errors.append(err("$.content", "NUL bytes are not allowed"))

    if "```" in content:
        errors.append(err("$.content", "markdown code fences are not allowed"))

    for ch in content:
        if ord(ch) < 32 and ch not in "\r\n\t":
            errors.append(err("$.content", "unsupported control character"))
            break

    try:
        clean = strip_comments(content)
    except ValueError as exc:
        errors.append(err("$.content", str(exc)))
        return result(False, errors, warnings)

    if re.search(r"(?im)^[ \t]*(include|import)\b", clean):
        errors.append(
            err(
                "$.content",
                "baseline-v1 rejects include/import; module-aware validation requires a real YARA engine",
            )
        )

    rules = list(RULE_RE.finditer(clean))
    if len(rules) != 1:
        errors.append(err("$.content", f"exactly one YARA rule is required; found {len(rules)}"))
        return result(False, errors, warnings)

    rule = rules[0]
    rule_name = rule.group(2)
    if not IDENT_RE.match(rule_name):
        errors.append(err("$.content.rule", "invalid rule identifier"))

    open_brace = clean.find("{", rule.start())
    close_brace = clean.rfind("}")
    if open_brace < 0 or close_brace <= open_brace:
        errors.append(err("$.content", "rule braces are incomplete"))
        return result(False, errors, warnings)

    before = clean[: rule.start()].strip()
    after = clean[close_brace + 1 :].strip()
    if before:
        errors.append(err("$.content", "unexpected content before rule declaration"))
    if after:
        errors.append(err("$.content", "unexpected content after closing rule brace"))

    body = clean[open_brace + 1 : close_brace]
    section_matches = list(SECTION_RE.finditer(body))
    names = [m.group(1).lower() for m in section_matches]

    if names.count("condition") != 1:
        errors.append(err("$.content.condition", f"exactly one condition section is required; found {names.count('condition')}"))
    if names.count("meta") > 1:
        errors.append(err("$.content.meta", "duplicate meta section"))
    if names.count("strings") > 1:
        errors.append(err("$.content.strings", "duplicate strings section"))

    order_index = {"meta": 0, "strings": 1, "condition": 2}
    if names and [order_index[n] for n in names] != sorted(order_index[n] for n in names):
        errors.append(err("$.content", "sections must be ordered meta -> strings -> condition"))

    sections: dict[str, str] = {}
    for idx, match in enumerate(section_matches):
        name = match.group(1).lower()
        start = match.end()
        end = section_matches[idx + 1].start() if idx + 1 < len(section_matches) else len(body)
        sections[name] = body[start:end]

    if "meta" in sections:
        validate_meta(sections["meta"], errors)

    string_ids: set[str] = set()
    if "strings" in sections:
        string_ids = validate_strings(sections["strings"], errors)

    if "condition" in sections:
        validate_condition(sections["condition"], string_ids, errors)

    if not string_ids and "condition" in sections:
        if REF_RE.search(sections["condition"]):
            errors.append(err("$.content.condition", "condition references strings but no strings section exists"))

    warnings.append("baseline validator is not YARA-compiler-equivalent")
    warnings.append("imports/includes are intentionally unsupported until an approved YARA engine is available")

    return result(not errors, errors, warnings)


def validate_envelope(obj: Any, schema_path: Path) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    try:
        import jsonschema
    except Exception as exc:
        return result(False, [err("$", f"jsonschema import failed: {exc}")])

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
        for issue in sorted(validator.iter_errors(obj), key=lambda e: list(e.path)):
            path = "$" + "".join(f"[{json.dumps(p)}]" if isinstance(p, str) else f"[{p}]" for p in issue.path)
            errors.append(err(path, issue.message))
    except Exception as exc:
        return result(False, [err("$", f"schema validation failure: {exc}")])

    if errors:
        return result(False, errors)

    content_result = validate_content(obj["content"])
    return content_result


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--content", action="store_true", help="read raw YARA content from stdin")
    mode.add_argument("--envelope", action="store_true", help="read structured JSON envelope from stdin")
    parser.add_argument(
        "--schema",
        default="/opt/jeffrey-gateway/schemas/yara-output-v1.schema.json",
        help="JSON schema path for --envelope mode",
    )
    args = parser.parse_args()

    data = sys.stdin.read()
    if args.content:
        output = validate_content(data)
    else:
        try:
            obj = json.loads(data)
        except json.JSONDecodeError as exc:
            output = result(False, [err("$", f"invalid JSON: {exc.msg}")])
        else:
            output = validate_envelope(obj, Path(args.schema))

    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return 0 if output["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
