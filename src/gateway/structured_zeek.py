#!/usr/bin/env python3
"""
Jeffrey Toolkit — structured Zeek route.

Internal model contract:
    conservative Zeek AST
        -> deterministic renderer
        -> external zeek-output-v1 content envelope
        -> deterministic baseline validator

The public/external artifact contract remains unchanged.
No Zeek engine-equivalent claim is made.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from structured_tool_common import (
    StructuredToolError,
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

SCHEMA_PATH = Path("/opt/jeffrey-gateway/schemas/zeek-output-v1.schema.json")
VALIDATOR_PATH = Path("/opt/jeffrey-gateway/validators/validate_zeek_baseline.py")
ALLOWED_REQUEST_KEYS = {"messages", "max_tokens", "temperature"}

IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$")
RETURN_RE = re.compile(
    r"^(?:bool|count|int|string|double|time|interval|addr|port|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)$"
)
BLOCKED_BODY_RE = re.compile(
    r"(?i)(?:"
    r"^\s*@|"
    r"^\s*redef\b|"
    r"^\s*export\b|"
    r"\bsystem\s*\(|"
    r"\bExec::run(?:_shell)?\s*\(|"
    r"\bexecute_command\s*\(|"
    r"\bPipe::[A-Za-z_][A-Za-z0-9_]*"
    r")"
)


def _zeek_model_schema() -> dict[str, Any]:
    # This is intentionally narrower than arbitrary Zeek source. The model
    # proposes structured handler data; the gateway owns top-level rendering.
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["module", "handlers"],
        "properties": {
            "module": {
                "type": "string",
                "maxLength": 128,
            },
            "handlers": {
                "type": "array",
                "minItems": 1,
                "maxItems": 8,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "kind",
                        "name",
                        "parameters",
                        "return_type",
                        "body",
                    ],
                    "properties": {
                        "kind": {
                            "type": "string",
                            "enum": ["event", "hook", "function"],
                        },
                        "name": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 128,
                        },
                        "parameters": {
                            "type": "string",
                            "maxLength": 1000,
                        },
                        "return_type": {
                            "type": "string",
                            "maxLength": 128,
                        },
                        "body": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 64,
                            "items": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 1000,
                            },
                        },
                    },
                },
            },
            "summary": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1000,
            },
        },
    }


def _render_model_ast(obj: dict[str, Any]) -> dict[str, Any]:
    allowed_top = {"module", "handlers", "summary"}
    if not set(obj).issubset(allowed_top):
        raise StructuredToolError(
            422,
            "structured_output_invalid",
            "Zeek AST contains unsupported top-level keys",
            {"keys": sorted(obj)},
        )

    module = obj.get("module", "")
    handlers = obj.get("handlers")

    if not isinstance(module, str):
        raise StructuredToolError(
            422,
            "structured_output_invalid",
            "Zeek AST module must be a string",
        )
    module = module.strip()
    if module and not IDENT_RE.fullmatch(module):
        raise StructuredToolError(
            422,
            "structured_output_invalid",
            "Zeek AST module identifier is invalid",
        )

    if not isinstance(handlers, list) or not 1 <= len(handlers) <= 8:
        raise StructuredToolError(
            422,
            "structured_output_invalid",
            "Zeek AST handlers must contain 1..8 handlers",
        )

    rendered_handlers: list[str] = []

    for idx, handler in enumerate(handlers):
        if not isinstance(handler, dict):
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                f"Zeek AST handlers[{idx}] must be an object",
            )

        required = {"kind", "name", "parameters", "return_type", "body"}
        if set(handler) != required:
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                f"Zeek AST handlers[{idx}] requires exactly kind/name/parameters/return_type/body",
            )

        kind = handler["kind"]
        name = handler["name"]
        parameters = handler["parameters"]
        return_type = handler["return_type"]
        body = handler["body"]

        if kind not in {"event", "hook", "function"}:
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                f"Zeek AST handlers[{idx}].kind is invalid",
            )
        if not isinstance(name, str) or not IDENT_RE.fullmatch(name.strip()):
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                f"Zeek AST handlers[{idx}].name is invalid",
            )
        name = name.strip()

        if not isinstance(parameters, str):
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                f"Zeek AST handlers[{idx}].parameters must be a string",
            )
        parameters = parameters.strip()
        if any(ch in parameters for ch in "\r\n{};"):
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                f"Zeek AST handlers[{idx}].parameters contains forbidden syntax",
            )

        if not isinstance(return_type, str):
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                f"Zeek AST handlers[{idx}].return_type must be a string",
            )
        return_type = return_type.strip()

        if kind in {"event", "hook"} and return_type:
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                f"Zeek AST {kind} handler must have an empty return_type",
            )
        if kind == "function" and return_type and not RETURN_RE.fullmatch(return_type):
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                f"Zeek AST function return_type is unsupported",
            )

        if not isinstance(body, list) or not 1 <= len(body) <= 64:
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                f"Zeek AST handlers[{idx}].body must contain 1..64 lines",
            )

        rendered_body: list[str] = []
        for line_idx, line in enumerate(body):
            if not isinstance(line, str) or not line.strip():
                raise StructuredToolError(
                    422,
                    "structured_output_invalid",
                    f"Zeek AST handlers[{idx}].body[{line_idx}] must be a non-empty string",
                )
            if "\r" in line or "\n" in line:
                raise StructuredToolError(
                    422,
                    "structured_output_invalid",
                    f"Zeek AST handlers[{idx}].body[{line_idx}] must be a single logical line",
                )

            stripped = line.strip()
            blocked = BLOCKED_BODY_RE.search(stripped)
            if blocked:
                raise StructuredToolError(
                    422,
                    "structured_output_invalid",
                    f"Zeek AST body contains forbidden construct: {blocked.group(0)}",
                )

            rendered_body.append("    " + stripped)

        suffix = f": {return_type}" if return_type else ""
        rendered_handlers.append(
            f"{kind} {name}({parameters}){suffix}\n"
            "    {\n"
            + "\n".join(rendered_body)
            + "\n    }"
        )

    pieces: list[str] = []
    if module:
        pieces.append(f"module {module};")
    pieces.extend(rendered_handlers)

    result: dict[str, Any] = {
        "content": "\n\n".join(pieces) + "\n",
    }

    if "summary" in obj:
        summary = obj["summary"]
        if not isinstance(summary, str) or not summary.strip():
            raise StructuredToolError(
                422,
                "structured_output_invalid",
                "Zeek AST summary must be a non-empty string",
            )
        result["summary"] = summary.strip()

    return result


def _validator_messages(exc: StructuredToolError) -> str:
    detail = exc.details
    messages: list[str] = []

    if isinstance(detail, dict):
        for item in detail.get("errors", []):
            if isinstance(item, dict) and isinstance(item.get("message"), str):
                messages.append(item["message"])

    if messages:
        return "; ".join(messages[:10])

    return exc.message


def handle_zeek_request(handler: Any) -> None:
    rid = request_id(handler)

    try:
        payload = read_request_json(handler, ALLOWED_REQUEST_KEYS)
        messages = validate_messages(payload, handler)
        max_tokens, temperature = validate_options(payload, handler)
        external_schema = load_schema(SCHEMA_PATH, "Zeek")
        model_schema = _zeek_model_schema()

        guardrail = (
            "Generate a conservative Zeek script as structured handler data. "
            "Return ONLY JSON matching the supplied JSON schema. "
            "Do not write top-level Zeek source in JSON. "
            "Use module as a plain identifier or an empty string. "
            "Use handlers for event/hook/function declarations. "
            "Each body item is exactly one Zeek source line inside that handler. "
            "Do not use @load/package directives, redef, export blocks, module "
            "declarations inside body lines, system(), Exec::run, execute_command, "
            "Pipe process primitives, or external command execution. "
            "For simple requests, emit only the minimal requested handler and lines. "
            "Do not claim real Zeek parser/runtime validation succeeded. "
            "Use only facts supplied by the user."
        )

        attempts = 0
        last_error: StructuredToolError | None = None
        working_messages = list(messages)

        while attempts < 2:
            attempts += 1

            model_obj = generate_model_object(
                handler,
                rid,
                working_messages,
                max_tokens,
                0.0 if attempts > 1 else temperature,
                model_schema,
                guardrail,
            )

            try:
                normalized = _render_model_ast(model_obj)

                envelope = {
                    "artifact_type": "zeek",
                    "schema_version": "1",
                    **normalized,
                }

                validate_schema(envelope, external_schema, "Zeek")
                baseline = run_baseline_validator(
                    VALIDATOR_PATH,
                    envelope["content"],
                    "Zeek",
                )

                response: dict[str, Any] = {
                    "valid": True,
                    "artifact_type": "zeek",
                    "schema_version": "1",
                    "content": envelope["content"],
                    "request_id": rid,
                    "validation": {
                        "json_schema": True,
                        "zeek_baseline": True,
                        "validation_level": baseline.get(
                            "validation_level",
                            "baseline_not_engine",
                        ),
                        "validator_version": baseline.get("validator_version"),
                        "engine_equivalent": False,
                        "zeek_engine": "not_available",
                        "model_output_mode": "ast_rendered",
                        "generation_attempts": attempts,
                        "repair_used": attempts > 1,
                    },
                }

                if "summary" in envelope:
                    response["summary"] = envelope["summary"]

                handler._send_json(200, rid, response)
                return

            except StructuredToolError as exc:
                last_error = exc

            if attempts >= 2:
                break

            working_messages = [
                *messages,
                {
                    "role": "user",
                    "content": (
                        "The previous Zeek AST candidate was rejected. "
                        "Generate a complete replacement from scratch and keep it "
                        "strictly minimal. Do not use @load, redef, export, system, "
                        "Exec::run, execute_command, Pipe process primitives, or "
                        "top-level configuration constructs. Rejection: "
                        + _validator_messages(last_error)
                    ),
                },
            ]

        if last_error is None:
            last_error = StructuredToolError(
                422,
                "zeek_validation_failed",
                "Zeek generation failed deterministic validation",
            )

        raise last_error

    except StructuredToolError as exc:
        emit_error(handler, rid, exc)
