#!/usr/bin/env python3
"""
Jeffrey Toolkit — structured Sigma endpoint helper.

This module is intentionally narrow:
- accepts POST requests routed by the existing Jeffrey gateway
- supports only a structured Sigma generation operation
- calls the existing local llama.cpp upstream
- requires JSON-schema constrained model output
- independently validates the JSON envelope
- independently validates the Sigma YAML
- never executes model-generated shell commands

It is imported by jeffrey_gateway.py only for:
    POST /v1/structured/sigma
"""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

CONFIG_PATH = Path("/etc/jeffrey-gateway/gateway.json")
SCHEMA_PATH = Path("/opt/jeffrey-gateway/schemas/sigma-output-v1.schema.json")
STRUCTURED_VALIDATOR = Path(
    "/opt/jeffrey-gateway/validators/validate_structured_output.py"
)
SIGMA_VALIDATOR = Path("/opt/jeffrey-gateway/validators/validate_sigma.py")

MAX_STRUCTURED_REQUEST_BYTES = 1024 * 1024
MAX_STRUCTURED_MESSAGES = 20
DEFAULT_MAX_TOKENS = 2048
MAX_STRUCTURED_TOKENS = 4096

ALLOWED_INPUT_KEYS = {
    "messages",
    "max_tokens",
    "temperature",
}


class StructuredSigmaError(Exception):
    def __init__(self, status: int, code: str, message: str, details: Any = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details


def _request_id(handler) -> str:
    candidate = (handler.headers.get("X-Request-ID") or "").strip()
    if candidate and len(candidate) <= 128:
        return candidate
    return str(uuid.uuid4())


def _send_json(handler, status: int, request_id: str, obj: dict[str, Any]) -> None:
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Request-ID", request_id)
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    handler.wfile.write(body)


def _send_error(
    handler,
    request_id: str,
    status: int,
    code: str,
    message: str,
    details: Any = None,
) -> None:
    payload = {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
        }
    }
    if details is not None:
        payload["error"]["details"] = details
    _send_json(handler, status, request_id, payload)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise StructuredSigmaError(
            500, "configuration_error", f"{path} must contain a JSON object"
        )
    return data


def _read_request(handler, request_id: str) -> dict[str, Any]:
    content_type = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip()
    if content_type != "application/json":
        raise StructuredSigmaError(
            415,
            "unsupported_media_type",
            "Content-Type must be application/json",
        )

    if (handler.headers.get("Transfer-Encoding") or "").strip():
        raise StructuredSigmaError(
            411,
            "length_required",
            "chunked request bodies are not supported",
        )

    raw_length = handler.headers.get("Content-Length")
    if raw_length is None:
        raise StructuredSigmaError(
            411, "length_required", "Content-Length is required"
        )

    try:
        content_length = int(raw_length)
    except ValueError as exc:
        raise StructuredSigmaError(
            400, "invalid_content_length", "Content-Length must be an integer"
        ) from exc

    if content_length < 1:
        raise StructuredSigmaError(400, "empty_request", "request body is empty")

    if content_length > MAX_STRUCTURED_REQUEST_BYTES:
        raise StructuredSigmaError(
            413,
            "request_too_large",
            f"structured request exceeds {MAX_STRUCTURED_REQUEST_BYTES} bytes",
        )

    raw = handler.rfile.read(content_length)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise StructuredSigmaError(
            400, "invalid_utf8", "request body is not valid UTF-8"
        ) from exc
    except json.JSONDecodeError as exc:
        raise StructuredSigmaError(
            400, "invalid_json", "request body is not valid JSON"
        ) from exc

    if not isinstance(payload, dict):
        raise StructuredSigmaError(
            400, "invalid_request", "request body must be a JSON object"
        )

    unknown = sorted(set(payload) - ALLOWED_INPUT_KEYS)
    if unknown:
        raise StructuredSigmaError(
            400,
            "invalid_request",
            "unknown structured Sigma request fields",
            {"unknown_fields": unknown},
        )

    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise StructuredSigmaError(
            400, "invalid_request", "messages must be a non-empty array"
        )
    if len(messages) > MAX_STRUCTURED_MESSAGES:
        raise StructuredSigmaError(
            400,
            "invalid_request",
            f"messages may contain at most {MAX_STRUCTURED_MESSAGES} items",
        )

    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            raise StructuredSigmaError(
                400, "invalid_request", f"messages[{index}] must be an object"
            )
        if message.get("role") not in {"user", "assistant", "system"}:
            raise StructuredSigmaError(
                400,
                "invalid_request",
                f"messages[{index}].role is invalid",
            )
        if not isinstance(message.get("content"), str):
            raise StructuredSigmaError(
                400,
                "invalid_request",
                f"messages[{index}].content must be a string",
            )

    max_tokens = payload.get("max_tokens", DEFAULT_MAX_TOKENS)
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int):
        raise StructuredSigmaError(
            400, "invalid_request", "max_tokens must be an integer"
        )
    if not 64 <= max_tokens <= MAX_STRUCTURED_TOKENS:
        raise StructuredSigmaError(
            400,
            "invalid_request",
            f"max_tokens must be between 64 and {MAX_STRUCTURED_TOKENS}",
        )

    temperature = payload.get("temperature", 0)
    if isinstance(temperature, bool) or not isinstance(temperature, (int, float)):
        raise StructuredSigmaError(
            400, "invalid_request", "temperature must be numeric"
        )
    if not 0 <= float(temperature) <= 1:
        raise StructuredSigmaError(
            400, "invalid_request", "temperature must be between 0 and 1"
        )

    payload["max_tokens"] = max_tokens
    payload["temperature"] = float(temperature)
    return payload


def _run_validator(command: list[str]) -> tuple[bool, Any]:
    proc = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
        },
    )
    output = (proc.stdout or proc.stderr or "").strip()
    try:
        parsed = json.loads(output) if output else None
    except json.JSONDecodeError:
        parsed = {"raw": output}
    return proc.returncode == 0, parsed


def _validate_envelope(envelope: dict[str, Any]) -> tuple[bool, Any]:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".json",
        prefix="jeffrey-structured-",
        delete=False,
    ) as handle:
        json.dump(envelope, handle, ensure_ascii=False)
        temp_path = handle.name

    try:
        return _run_validator(
            [
                "/usr/bin/python3",
                str(STRUCTURED_VALIDATOR),
                "--schema",
                str(SCHEMA_PATH),
                temp_path,
            ]
        )
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def _validate_sigma_yaml(content: str) -> tuple[bool, Any]:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".yml",
        prefix="jeffrey-sigma-",
        delete=False,
    ) as handle:
        handle.write(content)
        temp_path = handle.name

    try:
        return _run_validator(
            ["/usr/bin/python3", str(SIGMA_VALIDATOR), temp_path]
        )
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def _extract_model_content(upstream_obj: dict[str, Any]) -> str:
    try:
        content = upstream_obj["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise StructuredSigmaError(
            502,
            "invalid_upstream_response",
            "model response did not contain choices[0].message.content",
        ) from exc

    if not isinstance(content, str) or not content.strip():
        raise StructuredSigmaError(
            502,
            "invalid_upstream_response",
            "model returned empty structured content",
        )
    return content


def _build_upstream_payload(
    request_payload: dict[str, Any], schema: dict[str, Any]
) -> dict[str, Any]:
    guardrail = {
        "role": "system",
        "content": (
            "You are generating a Sigma detection rule for deterministic validation. "
            "Return ONLY JSON matching the supplied JSON schema. "
            "The JSON field 'content' must contain one complete Sigma YAML rule. "
            "The Sigma YAML must include at least title, logsource, detection, and "
            "detection.condition. Use only information supported by the user request. "
            "Do not return markdown fences. Do not claim that validation proves "
            "detection effectiveness."
        ),
    }

    return {
        "messages": [guardrail, *request_payload["messages"]],
        "max_tokens": request_payload["max_tokens"],
        "temperature": request_payload["temperature"],
        "stream": False,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "jeffrey_sigma_output_v1",
                "strict": True,
                "schema": schema,
            },
        },
    }


def _call_upstream(
    cfg: dict[str, Any],
    request_id: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    host = cfg.get("upstream_host")
    port = cfg.get("upstream_port")
    timeout = cfg.get("upstream_timeout_seconds", 900)

    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise StructuredSigmaError(
            500, "configuration_error", "structured upstream must remain local"
        )
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise StructuredSigmaError(
            500, "configuration_error", "invalid structured upstream port"
        )

    encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(
            "POST",
            "/v1/chat/completions",
            body=encoded,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Content-Length": str(len(encoded)),
                "X-Request-ID": request_id,
            },
        )
        response = conn.getresponse()
        raw = response.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise StructuredSigmaError(
                502,
                "upstream_response_too_large",
                "structured upstream response exceeded 8 MiB",
            )
        if response.status != 200:
            detail = raw.decode("utf-8", "replace")[:2000]
            raise StructuredSigmaError(
                502,
                "upstream_error",
                f"model server returned HTTP {response.status}",
                {"upstream_body": detail},
            )
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StructuredSigmaError(
                502,
                "invalid_upstream_response",
                "model server returned invalid JSON",
            ) from exc
        if not isinstance(obj, dict):
            raise StructuredSigmaError(
                502,
                "invalid_upstream_response",
                "model server response was not a JSON object",
            )
        return obj
    except TimeoutError as exc:
        raise StructuredSigmaError(
            504, "upstream_timeout", "structured model request timed out"
        ) from exc
    except OSError as exc:
        raise StructuredSigmaError(
            502, "upstream_unavailable", "structured model upstream unavailable"
        ) from exc
    finally:
        conn.close()


def handle_sigma_request(handler) -> None:
    request_id = _request_id(handler)

    try:
        for required in (
            CONFIG_PATH,
            SCHEMA_PATH,
            STRUCTURED_VALIDATOR,
            SIGMA_VALIDATOR,
        ):
            if not required.is_file():
                raise StructuredSigmaError(
                    503,
                    "validator_unavailable",
                    f"required Phase-3 component missing: {required}",
                )

        cfg = _load_json(CONFIG_PATH)
        schema = _load_json(SCHEMA_PATH)
        request_payload = _read_request(handler, request_id)
        upstream_payload = _build_upstream_payload(request_payload, schema)
        upstream_obj = _call_upstream(cfg, request_id, upstream_payload)

        model_content = _extract_model_content(upstream_obj)
        try:
            envelope = json.loads(model_content)
        except json.JSONDecodeError as exc:
            raise StructuredSigmaError(
                422,
                "structured_output_invalid_json",
                "model output was not valid JSON",
            ) from exc

        if not isinstance(envelope, dict):
            raise StructuredSigmaError(
                422,
                "structured_output_invalid",
                "model structured output must be a JSON object",
            )

        envelope_ok, envelope_detail = _validate_envelope(envelope)
        if not envelope_ok:
            raise StructuredSigmaError(
                422,
                "schema_validation_failed",
                "model output failed JSON Schema validation",
                envelope_detail,
            )

        sigma_content = envelope.get("content")
        if not isinstance(sigma_content, str):
            raise StructuredSigmaError(
                422,
                "sigma_content_invalid",
                "validated envelope did not contain Sigma text",
            )

        sigma_ok, sigma_detail = _validate_sigma_yaml(sigma_content)
        if not sigma_ok:
            raise StructuredSigmaError(
                422,
                "sigma_validation_failed",
                "generated Sigma rule failed deterministic validation",
                sigma_detail,
            )

        result = {
            "valid": True,
            "artifact_type": "sigma",
            "schema_version": "1",
            "content": sigma_content,
            "summary": envelope.get("summary", ""),
            "validation": {
                "json_schema": True,
                "sigma_baseline": True,
                "detection_correctness": "not_evaluated",
                "backend_conversion": "not_evaluated",
            },
            "request_id": request_id,
        }
        _send_json(handler, 200, request_id, result)

    except StructuredSigmaError as exc:
        _send_error(
            handler,
            request_id,
            exc.status,
            exc.code,
            exc.message,
            exc.details,
        )
    except Exception:
        # Do not expose stack traces or filesystem/runtime details to clients.
        _send_error(
            handler,
            request_id,
            500,
            "structured_internal_error",
            "structured Sigma processing failed",
        )
