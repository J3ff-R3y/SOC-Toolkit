#!/usr/bin/env python3
"""
Jeffrey Toolkit — baseline conservative Suricata rule baseline validator.

Purpose
-------
Provide an independent deterministic control layer for one generated Suricata
rule while the production host does not yet have an approved Suricata engine.

This validator is intentionally NOT equivalent to `suricata -T`.

Supported baseline
------------------
- exactly one rule;
- conservative header:
    action proto src_addr src_port ->|<> dst_addr dst_port
- action: alert/pass/drop/reject;
- protocol: tcp/udp/icmp/ip;
- address: any, $VARIABLE, IPv4, IPv4/CIDR, [comma,separated,list];
- port: any, $VARIABLE, integer, range such as 80:90, list;
- option list in parentheses;
- mandatory msg, sid, rev;
- local sid range >= 1,000,000;
- selected common content/flow/network metadata keywords;
- quoted-string and delimiter checks;
- selected numeric/range checks;
- no multiline rule concatenation tricks, includes, shell, or config directives.

A real Suricata engine remains the required second validation layer before
Jeffrey may claim engine-equivalent rule validation.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

VALIDATOR_VERSION = "suricata-baseline-v1"
VALIDATION_LEVEL = "baseline_not_engine"
MAX_CONTENT_BYTES = 131072

ACTIONS = {"alert", "pass", "drop", "reject"}
PROTOCOLS = {"tcp", "udp", "icmp", "ip"}

# Keywords we can at least structurally constrain without a Suricata engine.
VALUE_KEYWORDS = {
    "msg",
    "sid",
    "rev",
    "gid",
    "classtype",
    "priority",
    "reference",
    "metadata",
    "flow",
    "content",
    "pcre",
    "depth",
    "offset",
    "distance",
    "within",
    "dsize",
    "flags",
    "ttl",
    "detection_filter",
    "threshold",
    "flowbits",
    "xbits",
    "tag",
    "byte_test",
    "byte_jump",
    "byte_extract",
    "isdataat",
}

FLAG_KEYWORDS = {
    "nocase",
    "startswith",
    "endswith",
    "fast_pattern",
    "rawbytes",
    # Conservative app-layer sticky buffers frequently used in generated rules.
    "http.uri",
    "http.uri.raw",
    "http.method",
    "http.request_body",
    "http.header",
    "http.header.raw",
    "http.user_agent",
    "http.host",
    "http.host.raw",
    "dns.query",
    "tls.sni",
}

HEADER_RE = re.compile(
    r"^\s*(?P<action>[A-Za-z]+)\s+"
    r"(?P<proto>[A-Za-z0-9_]+)\s+"
    r"(?P<src_addr>\S+)\s+"
    r"(?P<src_port>\S+)\s+"
    r"(?P<direction>->|<>)\s+"
    r"(?P<dst_addr>\S+)\s+"
    r"(?P<dst_port>\S+)\s*"
    r"\((?P<options>.*)\)\s*$",
    re.DOTALL,
)

VAR_RE = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")
INT_RE = re.compile(r"^[0-9]+$")
PORT_RANGE_RE = re.compile(r"^(?:[0-9]+)?:(?:[0-9]+)?$")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


def issue(path: str, message: str) -> dict[str, str]:
    return {"path": path, "message": message}


def output(valid: bool, errors: list[dict[str, str]], warnings: list[str] | None = None) -> dict[str, Any]:
    return {
        "valid": valid,
        "validator_version": VALIDATOR_VERSION,
        "validation_level": VALIDATION_LEVEL,
        "engine_equivalent": False,
        "suricata_engine": "not_available",
        "errors": errors,
        "warnings": warnings or [],
    }


def strip_comments(text: str) -> str:
    # Suricata rules use # comments. Only treat a # outside a quoted string
    # and at line-start/after whitespace as comment start.
    out: list[str] = []
    for raw_line in text.splitlines():
        in_quote = False
        escaped = False
        cut = len(raw_line)
        for i, ch in enumerate(raw_line):
            if in_quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_quote = False
                continue
            if ch == '"':
                in_quote = True
                continue
            if ch == "#" and (i == 0 or raw_line[i - 1].isspace()):
                cut = i
                break
        out.append(raw_line[:cut])
    return "\n".join(out).strip()


def split_outside(text: str, delimiter: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    escaped = False
    bracket_depth = 0

    for ch in text:
        if in_quote:
            buf.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False
            continue

        if ch == '"':
            in_quote = True
            buf.append(ch)
            continue

        if ch == "[":
            bracket_depth += 1
            buf.append(ch)
            continue
        if ch == "]":
            bracket_depth -= 1
            if bracket_depth < 0:
                raise ValueError("unexpected closing bracket")
            buf.append(ch)
            continue

        if ch == delimiter and bracket_depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)

    if in_quote:
        raise ValueError("unterminated quoted string")
    if bracket_depth != 0:
        raise ValueError("unbalanced square brackets")

    parts.append("".join(buf))
    return parts


def validate_addr_token(token: str) -> bool:
    token = token.strip()
    if token == "any" or VAR_RE.match(token):
        return True

    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        if not inner:
            return False
        try:
            parts = split_outside(inner, ",")
        except ValueError:
            return False
        return all(validate_addr_token(p.strip()) for p in parts if p.strip()) and all(p.strip() for p in parts)

    negated = token.startswith("!")
    if negated:
        token = token[1:]
        if token == "any":
            return False
        if VAR_RE.match(token):
            return True

    try:
        if "/" in token:
            ipaddress.ip_network(token, strict=False)
        else:
            ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def validate_port_token(token: str) -> bool:
    token = token.strip()
    if token == "any" or VAR_RE.match(token):
        return True

    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        if not inner:
            return False
        try:
            parts = split_outside(inner, ",")
        except ValueError:
            return False
        return all(validate_port_token(p.strip()) for p in parts if p.strip()) and all(p.strip() for p in parts)

    if token.startswith("!"):
        return validate_port_token(token[1:])

    if INT_RE.match(token):
        value = int(token)
        return 0 <= value <= 65535

    if PORT_RANGE_RE.match(token):
        left, right = token.split(":", 1)
        if left and not (0 <= int(left) <= 65535):
            return False
        if right and not (0 <= int(right) <= 65535):
            return False
        if left and right and int(left) > int(right):
            return False
        return bool(left or right)

    return False


def validate_quoted_value(value: str) -> bool:
    value = value.strip()
    if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
        return False
    escaped = False
    for ch in value[1:-1]:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            return False
    return not escaped


def parse_options(options_text: str, errors: list[dict[str, str]]) -> list[tuple[str, str | None]]:
    try:
        raw_options = split_outside(options_text, ";")
    except ValueError as exc:
        errors.append(issue("$.content.options", str(exc)))
        return []

    parsed: list[tuple[str, str | None]] = []

    # A valid Suricata rule normally ends its final option with ';'.
    if options_text.strip() and not options_text.rstrip().endswith(";"):
        errors.append(issue("$.content.options", "final option must end with ';'"))

    for index, raw in enumerate(raw_options):
        text = raw.strip()
        if not text:
            continue

        if ":" in text:
            keyword, value = text.split(":", 1)
            keyword = keyword.strip().lower()
            value = value.strip()
            if keyword not in VALUE_KEYWORDS:
                errors.append(issue(f"$.content.options[{index}]", f"unsupported baseline keyword: {keyword}"))
                continue
            if not value:
                errors.append(issue(f"$.content.options[{index}]", f"{keyword} requires a value"))
                continue
            parsed.append((keyword, value))
        else:
            keyword = text.strip().lower()
            if keyword not in FLAG_KEYWORDS:
                errors.append(issue(f"$.content.options[{index}]", f"unsupported baseline flag: {keyword}"))
                continue
            parsed.append((keyword, None))

    return parsed


def validate_options(parsed: list[tuple[str, str | None]], errors: list[dict[str, str]]) -> None:
    by_key: dict[str, list[str | None]] = {}
    for k, v in parsed:
        by_key.setdefault(k, []).append(v)

    for required in ("msg", "sid", "rev"):
        if required not in by_key:
            errors.append(issue(f"$.content.options.{required}", f"required option '{required}' is missing"))

    if len(by_key.get("msg", [])) > 1:
        errors.append(issue("$.content.options.msg", "msg must occur exactly once"))
    if len(by_key.get("sid", [])) > 1:
        errors.append(issue("$.content.options.sid", "sid must occur exactly once"))
    if len(by_key.get("rev", [])) > 1:
        errors.append(issue("$.content.options.rev", "rev must occur exactly once"))

    for value in by_key.get("msg", []):
        if value is None or not validate_quoted_value(value):
            errors.append(issue("$.content.options.msg", "msg must be one quoted string"))

    for value in by_key.get("sid", []):
        if value is None or not INT_RE.match(value):
            errors.append(issue("$.content.options.sid", "sid must be an integer"))
        else:
            sid = int(value)
            if sid < 1_000_000 or sid > 4_294_967_295:
                errors.append(issue("$.content.options.sid", "generated local sid must be in range 1000000..4294967295"))

    for value in by_key.get("rev", []):
        if value is None or not INT_RE.match(value) or int(value) < 1:
            errors.append(issue("$.content.options.rev", "rev must be an integer >= 1"))

    for key in ("priority", "depth", "offset", "distance", "within", "dsize", "ttl"):
        for value in by_key.get(key, []):
            if value is None:
                errors.append(issue(f"$.content.options.{key}", f"{key} requires a value"))
                continue
            # dsize/ttl can contain simple ranges/comparators in real Suricata.
            # Baseline accepts digits, comparator/range characters and spaces only.
            if not re.fullmatch(r"[0-9:<>=!\-\s]+", value):
                errors.append(issue(f"$.content.options.{key}", f"unsupported baseline value for {key}"))

    for value in by_key.get("content", []):
        if value is None:
            errors.append(issue("$.content.options.content", "content requires a value"))
            continue
        v = value
        if v.startswith("!"):
            v = v[1:].lstrip()
        if not validate_quoted_value(v):
            errors.append(issue("$.content.options.content", "content must be a quoted string, optionally negated"))

    for value in by_key.get("pcre", []):
        if value is None or not validate_quoted_value(value):
            errors.append(issue("$.content.options.pcre", "pcre must be a quoted string"))

    for value in by_key.get("classtype", []):
        if value is None or not IDENT_RE.match(value):
            errors.append(issue("$.content.options.classtype", "classtype must be a simple identifier"))

    for value in by_key.get("flow", []):
        if value is None or not re.fullmatch(r"[A-Za-z0-9_,\s]+", value):
            errors.append(issue("$.content.options.flow", "flow contains unsupported characters"))

    # Modifiers that logically belong to a preceding content/pcre are only useful
    # if a pattern option exists somewhere in the rule.
    pattern_present = bool(by_key.get("content") or by_key.get("pcre"))
    for modifier in ("nocase", "startswith", "endswith", "fast_pattern", "rawbytes"):
        if modifier in by_key and not pattern_present:
            errors.append(issue(f"$.content.options.{modifier}", f"{modifier} requires content or pcre in baseline-v1"))


def validate_rule(text: str) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    warnings = [
        "baseline validator is not Suricata-engine-equivalent",
        "real suricata -T validation is still required when approved engine tooling becomes available",
    ]

    if not isinstance(text, str):
        return output(False, [issue("$.content", "content must be a string")], warnings)

    try:
        encoded = text.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return output(False, [issue("$.content", "content must be valid UTF-8")], warnings)

    if len(encoded) > MAX_CONTENT_BYTES:
        errors.append(issue("$.content", f"content exceeds {MAX_CONTENT_BYTES} bytes"))

    if "\x00" in text:
        errors.append(issue("$.content", "NUL bytes are not allowed"))
    if "```" in text:
        errors.append(issue("$.content", "markdown code fences are not allowed"))

    clean = strip_comments(text)
    if not clean:
        errors.append(issue("$.content", "rule is empty after comments"))
        return output(False, errors, warnings)

    # Config/directive forms are intentionally outside this rule-only baseline.
    if re.search(r"(?im)^\s*(include|default-rule-path|rule-files|vars|outputs)\b", clean):
        errors.append(issue("$.content", "configuration directives are not allowed in rule content"))

    # Baseline-v1 is one logical rule only.
    # Multiple top-level opening parentheses are a strong indicator of multiple rules.
    # We parse the complete text with one anchored header expression.
    match = HEADER_RE.match(clean)
    if not match:
        errors.append(issue("$.content", "rule does not match the supported Suricata baseline header/options form"))
        return output(False, errors, warnings)

    action = match.group("action").lower()
    proto = match.group("proto").lower()

    if action not in ACTIONS:
        errors.append(issue("$.content.header.action", f"unsupported action: {action}"))
    if proto not in PROTOCOLS:
        errors.append(issue("$.content.header.protocol", f"unsupported protocol: {proto}"))

    for name in ("src_addr", "dst_addr"):
        token = match.group(name)
        if not validate_addr_token(token):
            errors.append(issue(f"$.content.header.{name}", f"invalid/unsupported address token: {token}"))

    for name in ("src_port", "dst_port"):
        token = match.group(name)
        if not validate_port_token(token):
            errors.append(issue(f"$.content.header.{name}", f"invalid/unsupported port token: {token}"))

    direction = match.group("direction")
    if direction not in {"->", "<>"}:
        errors.append(issue("$.content.header.direction", "direction must be -> or <>"))

    parsed = parse_options(match.group("options"), errors)
    validate_options(parsed, errors)

    return output(not errors, errors, warnings)


def validate_envelope(obj: Any, schema_path: Path) -> dict[str, Any]:
    try:
        import jsonschema
    except Exception as exc:
        return output(False, [issue("$", f"jsonschema import failed: {exc}")])

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        problems = list(jsonschema.Draft202012Validator(schema).iter_errors(obj))
    except Exception as exc:
        return output(False, [issue("$", f"schema validation failure: {exc}")])

    if problems:
        errs: list[dict[str, str]] = []
        for problem in problems:
            path = "$"
            for item in problem.path:
                path += f"[{json.dumps(item)}]" if isinstance(item, str) else f"[{item}]"
            errs.append(issue(path, problem.message))
        return output(False, errs)

    return validate_rule(obj["content"])


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--content", action="store_true")
    group.add_argument("--envelope", action="store_true")
    parser.add_argument(
        "--schema",
        default="/opt/jeffrey-gateway/schemas/suricata-output-v1.schema.json",
    )
    args = parser.parse_args()

    raw = sys.stdin.read()
    if args.content:
        result = validate_rule(raw)
    else:
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as exc:
            result = output(False, [issue("$", f"invalid JSON: {exc.msg}")])
        else:
            result = validate_envelope(obj, Path(args.schema))

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
