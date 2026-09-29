#!/usr/bin/env python3
# Jeffrey Toolkit — structured Suricata route.

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from structured_tool_common import (
    StructuredToolError,
    content_model_schema,
    emit_error,
    generate_model_object,
    load_schema,
    read_request_json,
    request_id,
    run_baseline_validator,
    validate_messages,
    validate_options,
    validate_schema,
)

SCHEMA_PATH = Path("/opt/jeffrey-gateway/schemas/suricata-output-v1.schema.json")
VALIDATOR_PATH = Path("/opt/jeffrey-gateway/validators/validate_suricata_baseline.py")
ALLOWED_REQUEST_KEYS = {"messages", "max_tokens", "temperature"}
HEADER_TOKEN_RE = re.compile(r"^[^\s\r\n()]+$")


def _normalize_options(options: Any) -> list[str]:
    if isinstance(options, str):
        raw = [item.strip() for item in options.split(";") if item.strip()]
    elif isinstance(options, list):
        raw = []
        for item in options:
            if not isinstance(item, str) or not item.strip():
                raise StructuredToolError(
                    422,
                    "structured_output_invalid",
                    "Suricata AST options must contain non-empty strings",
                )
            raw.append(item.strip().rstrip(";"))
    elif isinstance(options, dict):
        raw = []
        for key, value in options.items():
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
                raise StructuredToolError(
                    422,
                    "structured_output_invalid",
                    "Suricata AST option name is invalid",
                )
            if value is True or value is None:
                raw.append(key)
            elif isinstance(value, (str, int)) and not isinstance(value, bool):
                raw.append(f"{key}:{value}")
            elif isinstance(value, list):
                for sub in value:
                    if not isinstance(sub, (str, int)) or isinstance(sub, bool):
                        raise StructuredToolError(
                            422,
                            "structured_output_invalid",
                            "Suricata AST option list contains unsupported value",
                        )
                    raw.append(f"{key}:{sub}")
            else:
                raise StructuredToolError(
                    422,
                    "structured_output_invalid",
                    "Suricata AST option value is unsupported",
                )
    else:
        raise StructuredToolError(
            422,
            "structured_output_invalid",
            "Suricata AST options must be a string, list, or object",
        )

    for item in raw:
        if "\r" in item or "\n" in item or "(" in item or ")" in item:
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                "Suricata AST option contains forbidden control/delimiter characters",
            )
    return raw


def _normalize_model_output(obj: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if "content" in obj and set(obj).issubset({"content", "summary"}):
        if not isinstance(obj["content"], str):
            raise StructuredToolError(422, "structured_output_invalid", "content must be a string")
        if "summary" in obj and not isinstance(obj["summary"], str):
            raise StructuredToolError(422, "structured_output_invalid", "summary must be a string")
        return obj, "content_string"

    if "rule" in obj and set(obj).issubset({"rule", "summary"}):
        if not isinstance(obj["rule"], str):
            raise StructuredToolError(422, "structured_output_invalid", "rule must be a string")
        result: dict[str, Any] = {"content": obj["rule"]}
        if "summary" in obj:
            if not isinstance(obj["summary"], str):
                raise StructuredToolError(422, "structured_output_invalid", "summary must be a string")
            result["summary"] = obj["summary"]
        return result, "rule_alias"

    normalized = dict(obj)
    aliases = {
        "protocol": "proto",
        "source_address": "src_addr",
        "source_port": "src_port",
        "destination_address": "dst_addr",
        "destination_port": "dst_port",
    }
    for old, new in aliases.items():
        if old in normalized and new not in normalized:
            normalized[new] = normalized.pop(old)

    required = {
        "action", "proto", "src_addr", "src_port",
        "direction", "dst_addr", "dst_port", "options",
    }
    allowed = required | {"summary"}

    if required.issubset(normalized) and set(normalized).issubset(allowed):
        header: list[str] = []
        for key in (
            "action", "proto", "src_addr", "src_port",
            "direction", "dst_addr", "dst_port",
        ):
            value = normalized[key]
            if not isinstance(value, str) or not HEADER_TOKEN_RE.fullmatch(value):
                raise StructuredToolError(
                    422,
                    "structured_output_invalid",
                    f"Suricata AST field {key} is invalid",
                )
            header.append(value)

        options = _normalize_options(normalized["options"])
        if not options:
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                "Suricata AST options must not be empty",
            )

        rendered = " ".join(header) + " (" + "; ".join(options) + ";)"
        result = {"content": rendered}
        if "summary" in normalized:
            if not isinstance(normalized["summary"], str):
                raise StructuredToolError(422, "structured_output_invalid", "summary must be a string")
            result["summary"] = normalized["summary"]
        return result, "ast_normalized"

    raise StructuredToolError(
        422,
        "structured_output_invalid",
        "model did not return content or the supported conservative Suricata AST",
        {"keys": sorted(obj)},
    )


def handle_suricata_request(handler: Any) -> None:
    rid = request_id(handler)

    try:
        payload = read_request_json(handler, ALLOWED_REQUEST_KEYS)
        messages = validate_messages(payload, handler)
        max_tokens, temperature = validate_options(payload, handler)
        schema = load_schema(SCHEMA_PATH, "Suricata")

        model_obj = generate_model_object(
            handler,
            rid,
            messages,
            max_tokens,
            temperature,
            content_model_schema(schema),
            (
                "Generate exactly one conservative Suricata IDS rule. "
                "Return ONLY JSON matching the supplied JSON schema. "
                "The JSON field content must contain one complete rule. "
                "Use a local SID >= 1000000 and rev >= 1. Include a quoted msg. "
                "Prefer tcp/udp/icmp/ip and conservative content/flow keywords. "
                "Do not return markdown fences. Do not claim suricata -T or real "
                "engine validation succeeded. Use only facts supplied by the user."
            ),
        )

        if "artifact_type" in model_obj or "schema_version" in model_obj:
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                "model returned gateway-owned protocol metadata",
            )

        normalized, mode = _normalize_model_output(model_obj)

        envelope = {
            "artifact_type": "suricata",
            "schema_version": "1",
            **normalized,
        }

        validate_schema(envelope, schema, "Suricata")
        baseline = run_baseline_validator(
            VALIDATOR_PATH,
            envelope["content"],
            "Suricata",
        )

        response: dict[str, Any] = {
            "valid": True,
            "artifact_type": "suricata",
            "schema_version": "1",
            "content": envelope["content"],
            "request_id": rid,
            "validation": {
                "json_schema": True,
                "suricata_baseline": True,
                "validation_level": baseline.get("validation_level", "baseline_not_engine"),
                "validator_version": baseline.get("validator_version"),
                "engine_equivalent": False,
                "suricata_engine": "not_available",
                "model_output_mode": mode,
            },
        }

        if "summary" in envelope:
            response["summary"] = envelope["summary"]

        handler._send_json(200, rid, response)

    except StructuredToolError as exc:
        emit_error(handler, rid, exc)
