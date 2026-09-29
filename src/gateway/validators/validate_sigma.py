#!/usr/bin/env python3
"""Deterministic Sigma YAML validator for Jeffrey Toolkit baseline.

This validator intentionally implements a conservative, offline validation
baseline for Sigma detection rules. It validates YAML syntax, core Sigma rule
structure, common field types/enums, and basic condition/search-identifier
references. It does NOT claim to prove detection correctness and does not
perform SIEM/backend conversion.

Exit codes:
  0 = valid
  1 = validation failed
  2 = input/configuration error
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any

import yaml

VALIDATOR_VERSION = "sigma-baseline-v1"
MAX_BYTES_DEFAULT = 1_048_576

STATUS_VALUES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVEL_VALUES = {"informational", "low", "medium", "high", "critical"}
RELATED_TYPES = {"derived", "obsolete", "merged", "renamed", "similar"}

IDENTIFIER_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*(?:\*)?")
TAG_RE = re.compile(r"^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$")
LOGSOURCE_VALUE_RE = re.compile(r"^[a-z0-9_.-]+$")
DATE_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$")

CONDITION_STOPWORDS = {
    "and", "or", "not", "all", "any", "of", "them",
}


class DuplicateKeyLoader(yaml.SafeLoader):
    """PyYAML SafeLoader that rejects duplicate mapping keys."""



def _construct_mapping(loader: DuplicateKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            mark = getattr(key_node, "start_mark", None)
            location = f"line {mark.line + 1}, column {mark.column + 1}" if mark else "unknown location"
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"duplicate YAML key {key!r} at {location}",
                key_node.start_mark,
            )
        value = loader.construct_object(value_node, deep=deep)
        mapping[key] = value
    return mapping


DuplicateKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))


def add_error(errors: list[dict[str, str]], path: str, message: str) -> None:
    errors.append({"path": path or "$", "message": message})


def is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def validate_recursive_detection_value(value: Any, path: str, errors: list[dict[str, str]]) -> None:
    if is_scalar(value):
        return
    if isinstance(value, list):
        if not value:
            add_error(errors, path, "search-identifier lists must not be empty")
            return
        for idx, item in enumerate(value):
            if isinstance(item, (dict, list)):
                validate_recursive_detection_value(item, f"{path}[{idx}]", errors)
            elif not is_scalar(item):
                add_error(errors, f"{path}[{idx}]", "unsupported YAML value type")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                add_error(errors, path, "mapping keys in detection must be strings")
            validate_recursive_detection_value(item, f"{path}.{key}", errors)
        return
    add_error(errors, path, f"unsupported YAML value type: {type(value).__name__}")


def normalize_condition(condition: Any, path: str, errors: list[dict[str, str]]) -> list[str]:
    if isinstance(condition, str):
        if not condition.strip():
            add_error(errors, path, "condition must not be empty")
            return []
        return [condition]
    if isinstance(condition, list):
        if not condition:
            add_error(errors, path, "condition list must not be empty")
            return []
        result: list[str] = []
        for idx, item in enumerate(condition):
            if not isinstance(item, str) or not item.strip():
                add_error(errors, f"{path}[{idx}]", "condition list items must be non-empty strings")
            else:
                result.append(item)
        return result
    add_error(errors, path, "condition must be a string or a list of strings")
    return []


def validate_condition_references(condition: str, identifiers: set[str], path: str, errors: list[dict[str, str]]) -> None:
    for token in IDENTIFIER_TOKEN_RE.findall(condition):
        lowered = token.lower()
        if lowered in CONDITION_STOPWORDS or token.isdigit():
            continue
        # Numeric forms such as "1" are handled above; other bare tokens are
        # interpreted as search identifiers in the core condition grammar.
        if token.endswith("*"):
            pattern = re.compile("^" + re.escape(token[:-1]) + ".*$")
            matches = [name for name in identifiers if pattern.match(name)]
            if not matches:
                add_error(errors, path, f"condition references pattern {token!r} but no matching search identifier exists")
        else:
            if token not in identifiers:
                add_error(errors, path, f"condition references unknown search identifier {token!r}")


def validate_date(value: Any, path: str, errors: list[dict[str, str]]) -> None:
    if isinstance(value, dt.datetime):
        value = value.date()
    if isinstance(value, dt.date):
        value = value.isoformat()
    if not isinstance(value, str) or not DATE_RE.fullmatch(value):
        add_error(errors, path, "must be an ISO date in YYYY-MM-DD format")


def validate_uuid(value: Any, path: str, errors: list[dict[str, str]]) -> None:
    if not isinstance(value, str):
        add_error(errors, path, "must be a string containing a UUID")
        return
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError):
        add_error(errors, path, "must contain a valid UUID")


def validate_string(value: Any, path: str, errors: list[dict[str, str]], max_len: int | None = None) -> None:
    if not isinstance(value, str):
        add_error(errors, path, "must be a string")
        return
    if max_len is not None and len(value) > max_len:
        add_error(errors, path, f"must be at most {max_len} characters")


def validate_string_list(value: Any, path: str, errors: list[dict[str, str]], unique: bool = False, min_item_len: int | None = None) -> None:
    if not isinstance(value, list):
        add_error(errors, path, "must be a list")
        return
    seen: set[str] = set()
    for idx, item in enumerate(value):
        item_path = f"{path}[{idx}]"
        if not isinstance(item, str):
            add_error(errors, item_path, "must be a string")
            continue
        if min_item_len is not None and len(item) < min_item_len:
            add_error(errors, item_path, f"must be at least {min_item_len} characters")
        if unique:
            if item in seen:
                add_error(errors, item_path, "duplicate item is not allowed")
            seen.add(item)


def validate_rule(rule: Any) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []

    if not isinstance(rule, dict):
        add_error(errors, "$", "Sigma document must be a YAML mapping/object")
        return errors

    # Mandatory core sections from the Sigma rule specification.
    for required in ("title", "logsource", "detection"):
        if required not in rule:
            add_error(errors, f"$.{required}", "required Sigma field is missing")

    if "title" in rule:
        validate_string(rule["title"], "$.title", errors, 256)

    if "id" in rule:
        validate_uuid(rule["id"], "$.id", errors)

    if "name" in rule:
        validate_string(rule["name"], "$.name", errors, 256)

    if "taxonomy" in rule:
        validate_string(rule["taxonomy"], "$.taxonomy", errors, 256)

    if "status" in rule:
        validate_string(rule["status"], "$.status", errors)
        if isinstance(rule["status"], str) and rule["status"] not in STATUS_VALUES:
            add_error(errors, "$.status", f"unsupported status {rule['status']!r}")

    for field in ("description", "license", "author"):
        if field in rule:
            validate_string(rule[field], f"$.{field}", errors)

    if "references" in rule:
        validate_string_list(rule["references"], "$.references", errors, unique=True)

    for field in ("date", "modified"):
        if field in rule:
            validate_date(rule[field], f"$.{field}", errors)

    if "falsepositives" in rule:
        validate_string_list(rule["falsepositives"], "$.falsepositives", errors, unique=True, min_item_len=2)

    if "fields" in rule:
        validate_string_list(rule["fields"], "$.fields", errors, unique=True)

    if "tags" in rule:
        if not isinstance(rule["tags"], list):
            add_error(errors, "$.tags", "must be a list")
        else:
            seen: set[str] = set()
            for idx, tag in enumerate(rule["tags"]):
                path = f"$.tags[{idx}]"
                if not isinstance(tag, str):
                    add_error(errors, path, "must be a string")
                    continue
                if not TAG_RE.fullmatch(tag):
                    add_error(errors, path, "must be lowercase namespaced Sigma tag syntax (for example attack.t1059)")
                if tag in seen:
                    add_error(errors, path, "duplicate item is not allowed")
                seen.add(tag)

    if "scope" in rule:
        validate_string_list(rule["scope"], "$.scope", errors, unique=False, min_item_len=2)

    if "level" in rule:
        validate_string(rule["level"], "$.level", errors)
        if isinstance(rule["level"], str) and rule["level"] not in LEVEL_VALUES:
            add_error(errors, "$.level", f"unsupported level {rule['level']!r}")

    if "related" in rule:
        if not isinstance(rule["related"], list):
            add_error(errors, "$.related", "must be a list")
        else:
            for idx, related in enumerate(rule["related"]):
                path = f"$.related[{idx}]"
                if not isinstance(related, dict):
                    add_error(errors, path, "must be a mapping")
                    continue
                for required in ("id", "type"):
                    if required not in related:
                        add_error(errors, f"{path}.{required}", "required field is missing")
                if "id" in related:
                    validate_uuid(related["id"], f"{path}.id", errors)
                if "type" in related:
                    validate_string(related["type"], f"{path}.type", errors)
                    if isinstance(related["type"], str) and related["type"] not in RELATED_TYPES:
                        add_error(errors, f"{path}.type", f"unsupported related type {related['type']!r}")

    # Logsource is mandatory but its standard members are individually optional.
    if "logsource" in rule:
        logsource = rule["logsource"]
        if not isinstance(logsource, dict):
            add_error(errors, "$.logsource", "must be a mapping")
        else:
            for field in ("category", "product", "service"):
                if field in logsource:
                    validate_string(logsource[field], f"$.logsource.{field}", errors)
                    if isinstance(logsource[field], str) and not LOGSOURCE_VALUE_RE.fullmatch(logsource[field]):
                        add_error(errors, f"$.logsource.{field}", "must use lowercase letters/digits plus '.', '-' or '_'")
            if "definition" in logsource:
                validate_string(logsource["definition"], "$.logsource.definition", errors)

    if "detection" in rule:
        detection = rule["detection"]
        if not isinstance(detection, dict):
            add_error(errors, "$.detection", "must be a mapping")
        else:
            if "condition" not in detection:
                add_error(errors, "$.detection.condition", "required Sigma field is missing")
            identifiers: set[str] = set()
            for key, value in detection.items():
                if not isinstance(key, str):
                    add_error(errors, "$.detection", "detection keys must be strings")
                    continue
                if key == "condition":
                    continue
                identifiers.add(key)
                if not isinstance(value, (dict, list)):
                    add_error(errors, f"$.detection.{key}", "search-identifier must be a mapping or list")
                else:
                    validate_recursive_detection_value(value, f"$.detection.{key}", errors)

            condition_values = normalize_condition(detection.get("condition"), "$.detection.condition", errors) if "condition" in detection else []
            if identifiers:
                for idx, condition in enumerate(condition_values):
                    validate_condition_references(condition, identifiers, f"$.detection.condition[{idx}]" if len(condition_values) > 1 else "$.detection.condition", errors)
            elif "condition" in detection:
                add_error(errors, "$.detection", "at least one search identifier is required alongside condition")

    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deterministic Sigma YAML validator")
    parser.add_argument("input", help="Sigma YAML file path or - for stdin")
    parser.add_argument("--max-bytes", type=int, default=MAX_BYTES_DEFAULT)
    parser.add_argument("--pretty", action="store_true", help="pretty-print a normalized success document")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.max_bytes <= 0:
        emit({"valid": False, "error": "invalid_configuration", "message": "--max-bytes must be > 0", "validator_version": VALIDATOR_VERSION})
        return 2

    try:
        if args.input == "-":
            data = sys.stdin.buffer.read(args.max_bytes + 1)
        else:
            path = Path(args.input)
            data = path.read_bytes()
    except OSError as exc:
        emit({"valid": False, "error": "input_error", "message": str(exc), "validator_version": VALIDATOR_VERSION})
        return 2

    if len(data) > args.max_bytes:
        emit({"valid": False, "error": "input_too_large", "max_bytes": args.max_bytes, "validator_version": VALIDATOR_VERSION})
        return 1

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        emit({"valid": False, "error": "invalid_utf8", "message": str(exc), "validator_version": VALIDATOR_VERSION})
        return 1

    try:
        rule = yaml.load(text, Loader=DuplicateKeyLoader)
    except yaml.YAMLError as exc:
        problem = getattr(exc, "problem", None) or str(exc)
        mark = getattr(exc, "problem_mark", None)
        location = None
        if mark is not None:
            location = {"line": mark.line + 1, "column": mark.column + 1}
        payload: dict[str, Any] = {
            "valid": False,
            "error": "yaml_parse_failed",
            "message": problem,
            "validator_version": VALIDATOR_VERSION,
        }
        if location:
            payload["location"] = location
        emit(payload)
        return 1

    errors = validate_rule(rule)
    if errors:
        emit({"valid": False, "error": "sigma_validation_failed", "validator_version": VALIDATOR_VERSION, "errors": errors})
        return 1

    payload: dict[str, Any] = {
        "valid": True,
        "format": "sigma",
        "validator_version": VALIDATOR_VERSION,
    }
    if args.pretty:
        payload["document"] = rule
    emit(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
