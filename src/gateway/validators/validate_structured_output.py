#!/usr/bin/env python3
"""
Jeffrey Toolkit — deterministic structured-output validator v1.

Validates the JSON envelope used by the structured-output Sigma contract.
This validator does NOT decide whether the Sigma YAML itself is
semantically/syntactically valid; that is a separate structured-output step.

Exit codes:
  0 = valid
  1 = validation failed
  2 = usage/input error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


DEFAULT_SCHEMA = Path(
    "/opt/jeffrey-gateway/schemas/sigma-output-v1.schema.json"
)


def load_json(source: str) -> object:
    if source == "-":
        return json.load(sys.stdin)
    with open(source, encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a Jeffrey structured-output JSON envelope."
    )
    parser.add_argument(
        "input",
        help="JSON file to validate, or '-' for stdin",
    )
    parser.add_argument(
        "--schema",
        default=str(DEFAULT_SCHEMA),
        help=f"JSON Schema path (default: {DEFAULT_SCHEMA})",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the validated JSON on success.",
    )
    args = parser.parse_args()

    schema_path = Path(args.schema)

    try:
        with schema_path.open(encoding="utf-8") as handle:
            schema = json.load(handle)
        Draft202012Validator.check_schema(schema)
    except (OSError, json.JSONDecodeError, Exception) as exc:
        print(
            json.dumps(
                {
                    "valid": False,
                    "error": "validator_configuration_error",
                    "detail": str(exc),
                },
                ensure_ascii=False,
            )
        )
        return 2

    try:
        instance = load_json(args.input)
    except (OSError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {
                    "valid": False,
                    "error": "input_error",
                    "detail": str(exc),
                },
                ensure_ascii=False,
            )
        )
        return 2

    validator = Draft202012Validator(schema)
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: [str(part) for part in error.path],
    )

    if errors:
        output = {
            "valid": False,
            "error": "schema_validation_failed",
            "errors": [
                {
                    "path": ".".join(str(part) for part in error.path) or "$",
                    "message": error.message,
                }
                for error in errors
            ],
        }
        print(json.dumps(output, ensure_ascii=False))
        return 1

    output = {
        "valid": True,
        "artifact_type": instance.get("artifact_type"),
        "schema_version": instance.get("schema_version"),
    }
    if args.pretty:
        output["document"] = instance

    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
