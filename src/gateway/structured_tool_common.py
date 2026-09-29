#!/usr/bin/env python3
# Jeffrey Toolkit — shared structured-generation utilities.

from __future__ import annotations

import http.client
import json
import subprocess
import uuid
from pathlib import Path
from typing import Any


class StructuredToolError(Exception):
    def __init__(self, status: int, code: str, message: str, details: Any | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details


def cfg(handler: Any, key: str, default: Any) -> Any:
    config = handler.server.gateway_config
    if isinstance(config, dict):
        return config.get(key, default)
    return getattr(config, key, default)


def request_id(handler: Any) -> str:
    return (handler.headers.get("X-Request-ID") or str(uuid.uuid4())).strip()


def emit_error(handler: Any, rid: str, exc: StructuredToolError) -> None:
    if exc.details is None:
        handler._send_error(exc.status, rid, exc.message, exc.code)
        return

    handler._send_json(
        exc.status,
        rid,
        {
            "error": {
                "code": exc.code,
                "message": exc.message,
                "request_id": rid,
                "details": exc.details,
            }
        },
    )


def read_request_json(handler: Any, allowed_keys: set[str]) -> dict[str, Any]:
    content_type = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        handler.close_connection = True
        raise StructuredToolError(415, "unsupported_media_type", "Content-Type must be application/json")

    transfer_encoding = (handler.headers.get("Transfer-Encoding") or "").strip()
    if transfer_encoding:
        handler.close_connection = True
        raise StructuredToolError(400, "invalid_request", "chunked request bodies are not supported")

    raw_length = handler.headers.get("Content-Length")
    if raw_length is None:
        handler.close_connection = True
        raise StructuredToolError(400, "invalid_request", "Content-Length is required")

    try:
        length = int(raw_length)
    except ValueError as exc:
        handler.close_connection = True
        raise StructuredToolError(400, "invalid_request", "invalid Content-Length") from exc

    max_request = int(cfg(handler, "max_request_bytes", 33554432))
    if length < 1:
        handler.close_connection = True
        raise StructuredToolError(400, "invalid_request", "empty request body")
    if length > max_request:
        handler.close_connection = True
        raise StructuredToolError(413, "request_too_large", "request body exceeds configured maximum")

    raw = handler.rfile.read(length)
    if len(raw) != length:
        raise StructuredToolError(400, "invalid_request", "incomplete request body")

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StructuredToolError(400, "invalid_json", "request body is not valid JSON") from exc

    if not isinstance(payload, dict):
        raise StructuredToolError(400, "invalid_request", "request body must be a JSON object")

    unknown = sorted(set(payload) - allowed_keys)
    if unknown:
        raise StructuredToolError(
            400,
            "unknown_request_keys",
            "request contains unsupported keys",
            {"keys": unknown},
        )

    return payload


def validate_messages(payload: dict[str, Any], handler: Any) -> list[dict[str, str]]:
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise StructuredToolError(400, "invalid_messages", "messages must be a non-empty array")

    max_messages = int(cfg(handler, "max_messages", 100))
    if len(messages) > max_messages:
        raise StructuredToolError(400, "too_many_messages", f"messages exceeds configured maximum of {max_messages}")

    allowed_roles = {"system", "user", "assistant"}
    clean: list[dict[str, str]] = []
    for idx, item in enumerate(messages):
        if not isinstance(item, dict) or set(item) != {"role", "content"}:
            raise StructuredToolError(
                400,
                "invalid_messages",
                f"messages[{idx}] requires exactly role and content",
            )
        role = item["role"]
        content = item["content"]
        if role not in allowed_roles:
            raise StructuredToolError(400, "invalid_messages", f"messages[{idx}].role is invalid")
        if not isinstance(content, str) or not content.strip():
            raise StructuredToolError(
                400,
                "invalid_messages",
                f"messages[{idx}].content must be a non-empty string",
            )
        clean.append({"role": role, "content": content})
    return clean


def validate_options(payload: dict[str, Any], handler: Any) -> tuple[int, float]:
    max_allowed = int(cfg(handler, "max_tokens", 8192))
    max_tokens = payload.get("max_tokens", min(2048, max_allowed))
    if not isinstance(max_tokens, int) or isinstance(max_tokens, bool):
        raise StructuredToolError(400, "invalid_max_tokens", "max_tokens must be an integer")
    if max_tokens < 64 or max_tokens > max_allowed:
        raise StructuredToolError(
            400,
            "invalid_max_tokens",
            f"max_tokens must be between 64 and {max_allowed}",
        )

    temperature = payload.get("temperature", 0)
    if not isinstance(temperature, (int, float)) or isinstance(temperature, bool):
        raise StructuredToolError(400, "invalid_temperature", "temperature must be numeric")
    temperature = float(temperature)
    if temperature < 0 or temperature > 1:
        raise StructuredToolError(400, "invalid_temperature", "temperature must be between 0 and 1")

    return max_tokens, temperature


def load_schema(path: Path, label: str) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise StructuredToolError(
            500,
            "schema_unavailable",
            f"{label} structured-output schema is unavailable",
        ) from exc


def content_model_schema(full_schema: dict[str, Any]) -> dict[str, Any]:
    props = full_schema["properties"]
    model_schema: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["content"],
        "properties": {
            "content": props["content"],
        },
    }
    if "summary" in props:
        model_schema["properties"]["summary"] = props["summary"]
    return model_schema


def post_json(
    host: str,
    port: int,
    timeout: int,
    path: str,
    payload: dict[str, Any],
    rid: str,
) -> tuple[int, bytes]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(
            "POST",
            path,
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-Request-ID": rid,
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        raw = response.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise StructuredToolError(502, "upstream_response_too_large", "model server response exceeded safety limit")
        return response.status, raw
    except StructuredToolError:
        raise
    except Exception as exc:
        raise StructuredToolError(502, "upstream_error", "could not communicate with model server") from exc
    finally:
        conn.close()


def generate_model_object(
    handler: Any,
    rid: str,
    messages: list[dict[str, str]],
    max_tokens: int,
    temperature: float,
    model_schema: dict[str, Any],
    guardrail: str,
) -> dict[str, Any]:
    host = str(cfg(handler, "upstream_host", "127.0.0.1"))
    port = int(cfg(handler, "upstream_port", 8081))
    timeout = int(cfg(handler, "upstream_timeout_seconds", 900))

    apply_payload = {
        "messages": [
            {"role": "system", "content": guardrail},
            *messages,
        ],
        "add_generation_prompt": True,
    }

    status, raw = post_json(host, port, timeout, "/apply-template", apply_payload, rid)
    if status != 200:
        raise StructuredToolError(
            502,
            "upstream_error",
            f"llama.cpp /apply-template returned HTTP {status}",
            {"upstream_body": raw[:4000].decode("utf-8", errors="replace")},
        )

    try:
        prompt = json.loads(raw)["prompt"]
        if not isinstance(prompt, str) or not prompt:
            raise ValueError
    except Exception as exc:
        raise StructuredToolError(
            502,
            "upstream_error",
            "llama.cpp /apply-template returned an invalid response",
        ) from exc

    prompt += "<think>\n\n</think>\n\n"

    completion_payload = {
        "prompt": prompt,
        "n_predict": max_tokens,
        "temperature": temperature,
        "stream": False,
        "json_schema": model_schema,
    }

    status, raw = post_json(host, port, timeout, "/completion", completion_payload, rid)
    if status != 200:
        raise StructuredToolError(
            502,
            "upstream_error",
            f"model server /completion returned HTTP {status}",
            {"upstream_body": raw[:4000].decode("utf-8", errors="replace")},
        )

    try:
        outer = json.loads(raw)
        generated = outer["content"]
        if not isinstance(generated, str) or not generated.strip():
            raise ValueError
        model_obj = json.loads(generated)
        if not isinstance(model_obj, dict):
            raise ValueError
        return model_obj
    except Exception as exc:
        raise StructuredToolError(
            502,
            "upstream_error",
            "model /completion response was not valid structured JSON",
            {"upstream_body": raw[:4000].decode("utf-8", errors="replace")},
        ) from exc


def validate_schema(envelope: dict[str, Any], schema: dict[str, Any], label: str) -> None:
    try:
        import jsonschema
        jsonschema.Draft202012Validator.check_schema(schema)
        issues = list(jsonschema.Draft202012Validator(schema).iter_errors(envelope))
    except Exception as exc:
        raise StructuredToolError(
            500,
            "validation_unavailable",
            f"{label} JSON Schema validation layer failed",
        ) from exc

    if not issues:
        return

    details: list[dict[str, str]] = []
    for issue in issues:
        path = "$"
        for item in issue.path:
            path += f"[{json.dumps(item)}]" if isinstance(item, str) else f"[{item}]"
        details.append({"path": path, "message": issue.message})

    raise StructuredToolError(
        422,
        "schema_validation_failed",
        f"model output failed {label} envelope JSON Schema validation",
        {"valid": False, "errors": details},
    )


def run_baseline_validator(path: Path, content: str, label: str) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            [str(path), "--content"],
            input=content,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        detail = json.loads(proc.stdout)
    except Exception as exc:
        raise StructuredToolError(
            500,
            "validation_unavailable",
            f"{label} baseline validator could not be executed",
        ) from exc

    if proc.returncode != 0 or detail.get("valid") is not True:
        raise StructuredToolError(
            422,
            f"{label.lower()}_validation_failed",
            f"generated {label} artifact failed deterministic baseline validation",
            detail,
        )

    return detail
