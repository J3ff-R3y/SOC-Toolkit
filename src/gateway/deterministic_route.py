#!/usr/bin/env python3
"""
Jeffrey Toolkit — local deterministic utility gateway route.

Route:
  POST /v1/utils/deterministic

Properties:
- session protected by the existing Jeffrey gateway auth layer;
- fixed JSON request/response schemas;
- calls the deterministic utility core in-process;
- no model call;
- no network access;
- no shell/subprocess execution;
- no user-controlled filesystem path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

from utilities import deterministic_utils as core

REQUEST_SCHEMA_PATH = Path(
    "/opt/jeffrey-gateway/schemas/deterministic-utility-request-v1.schema.json"
)
RESPONSE_SCHEMA_PATH = Path(
    "/opt/jeffrey-gateway/schemas/deterministic-utility-response-v1.schema.json"
)

MAX_ROUTE_BYTES = 262144


class DeterministicRouteError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        path: str = "$",
        details: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.path = path
        self.details = details


def _request_id(handler: Any) -> str:
    value = (handler.headers.get("X-Request-ID") or "").strip()
    if value:
        return value[:200]
    # Deterministic utility operation itself remains deterministic; request IDs
    # are transport metadata owned by the gateway.
    import uuid

    return str(uuid.uuid4())


def _send_route_error(
    handler: Any,
    rid: str,
    exc: DeterministicRouteError,
) -> None:
    payload: dict[str, Any] = {
        "error": {
            "code": exc.code,
            "message": exc.message,
            "path": exc.path,
            "request_id": rid,
        }
    }
    if exc.details is not None:
        payload["error"]["details"] = exc.details
    handler._send_json(exc.status, rid, payload)


def _load_schema(path: Path, label: str) -> dict[str, Any]:
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        return schema
    except Exception as exc:
        raise DeterministicRouteError(
            500,
            "schema_unavailable",
            f"{label} schema is unavailable",
        ) from exc


def _format_schema_errors(errors: list[Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in errors[:20]:
        path = "$"
        for part in item.path:
            if isinstance(part, int):
                path += f"[{part}]"
            else:
                path += f"[{json.dumps(part)}]"
        out.append({"path": path, "message": item.message})
    return out


def _read_json_request(handler: Any) -> dict[str, Any]:
    content_type = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        # Body has not been consumed; force backend connection close so Apache
        # cannot reuse a connection with unread bytes.
        handler.close_connection = True
        raise DeterministicRouteError(
            415,
            "unsupported_media_type",
            "Content-Type must be application/json",
        )

    transfer_encoding = (handler.headers.get("Transfer-Encoding") or "").strip()
    if transfer_encoding:
        handler.close_connection = True
        raise DeterministicRouteError(
            400,
            "invalid_request",
            "chunked request bodies are not supported",
        )

    raw_length = handler.headers.get("Content-Length")
    if raw_length is None:
        handler.close_connection = True
        raise DeterministicRouteError(
            400,
            "invalid_request",
            "Content-Length is required",
        )

    try:
        length = int(raw_length)
    except ValueError as exc:
        handler.close_connection = True
        raise DeterministicRouteError(
            400,
            "invalid_request",
            "invalid Content-Length",
        ) from exc

    if length < 1:
        handler.close_connection = True
        raise DeterministicRouteError(
            400,
            "invalid_request",
            "empty request body",
        )

    if length > MAX_ROUTE_BYTES:
        handler.close_connection = True
        raise DeterministicRouteError(
            413,
            "request_too_large",
            f"request exceeds {MAX_ROUTE_BYTES} bytes",
        )

    raw = handler.rfile.read(length)
    if len(raw) != length:
        raise DeterministicRouteError(
            400,
            "invalid_request",
            "incomplete request body",
        )

    try:
        obj = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise DeterministicRouteError(
            400,
            "invalid_json",
            "request body is not UTF-8",
        ) from exc
    except json.JSONDecodeError as exc:
        raise DeterministicRouteError(
            400,
            "invalid_json",
            "request body is not valid JSON",
        ) from exc

    if not isinstance(obj, dict):
        raise DeterministicRouteError(
            400,
            "invalid_request",
            "request body must be a JSON object",
        )

    return obj


def _validate_request(obj: dict[str, Any]) -> None:
    schema = _load_schema(REQUEST_SCHEMA_PATH, "deterministic utility request")
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(obj))
    if errors:
        raise DeterministicRouteError(
            400,
            "request_schema_failed",
            "request failed deterministic utility JSON Schema validation",
            details={"valid": False, "errors": _format_schema_errors(errors)},
        )


def _validate_response(obj: dict[str, Any]) -> None:
    schema = _load_schema(RESPONSE_SCHEMA_PATH, "deterministic utility response")
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(obj))
    if errors:
        raise DeterministicRouteError(
            500,
            "response_schema_failed",
            "deterministic utility response failed internal schema validation",
            details={"valid": False, "errors": _format_schema_errors(errors)},
        )


def _map_core_error(exc: core.UtilityError) -> DeterministicRouteError:
    if exc.code in {
        "invalid_ioc",
        "unsupported_ioc",
        "invalid_hex",
        "invalid_base64",
        "invalid_utf8",
        "output_too_large",
    }:
        status = 422
    elif exc.code in {
        "operation_not_allowed",
        "invalid_request",
        "input_too_large",
        "request_too_large",
    }:
        status = 400
    else:
        status = 422

    return DeterministicRouteError(
        status,
        exc.code,
        exc.message,
        exc.path,
    )


def handle_deterministic_utility_request(handler: Any) -> None:
    rid = _request_id(handler)

    try:
        request_obj = _read_json_request(handler)
        _validate_request(request_obj)

        try:
            result = core.execute(
                request_obj["operation"],
                request_obj["value"],
            )
        except core.UtilityError as exc:
            raise _map_core_error(exc) from exc

        response_obj = core.ok(request_obj["operation"], result)
        _validate_response(response_obj)

        handler._send_json(200, rid, response_obj)

    except DeterministicRouteError as exc:
        _send_route_error(handler, rid, exc)
