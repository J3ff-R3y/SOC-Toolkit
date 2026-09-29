#!/usr/bin/env python3
"""Jeffrey Gateway - local middleware for llama-server.

Core goals:
- request validation
- request/body size limits
- model/runtime parameter policy
- request IDs
- structured JSON logging
- timeout/error handling
- health checks
- streaming passthrough
- consistent error responses

The gateway binds to localhost by design and proxies only the OpenAI-compatible
chat-completions endpoint to the local llama.cpp server.
"""

from __future__ import annotations

import argparse
import http.client
import json
import logging
import re
import socket
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


DEFAULT_CONFIG = {
    "listen_host": "127.0.0.1",
    "listen_port": 8082,
    "upstream_host": "127.0.0.1",
    "upstream_port": 8081,
    "upstream_timeout_seconds": 900,
    "max_request_bytes": 33554432,
    "max_response_bytes": 8388608,
    "max_messages": 100,
    "max_tokens": 8192,
    "max_stop_items": 8,
    "reject_unknown_keys": False,
    "enforce_model": False,
    "model_id": "jeffrey",
}

ALLOWED_KEYS = {
    "messages",
    "model",
    "stream",
    "max_tokens",
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "typical_p",
    "stop",
    "seed",
    "presence_penalty",
    "frequency_penalty",
    "repeat_penalty",
    "response_format",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "user",
}

ROLE_VALUES = {"system", "user", "assistant", "tool"}
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class GatewayConfigError(RuntimeError):
    pass


def load_config(path: str) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.is_file():
        raise GatewayConfigError(f"config not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise GatewayConfigError("config root must be a JSON object")
    cfg = DEFAULT_CONFIG.copy()
    cfg.update(loaded)
    validate_config(cfg)
    return cfg


def validate_config(cfg: dict[str, Any]) -> None:
    required_ints = {
        "listen_port": (1, 65535),
        "upstream_port": (1, 65535),
        "upstream_timeout_seconds": (1, 3600),
        "max_request_bytes": (1024, 134217728),
        "max_response_bytes": (1024, 134217728),
        "max_messages": (1, 1000),
        "max_tokens": (1, 131072),
        "max_stop_items": (1, 32),
    }
    for key, (low, high) in required_ints.items():
        value = cfg.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not (low <= value <= high):
            raise GatewayConfigError(f"invalid {key}: {value!r}")
    for key in ("listen_host", "upstream_host", "model_id"):
        if not isinstance(cfg.get(key), str) or not cfg[key].strip():
            raise GatewayConfigError(f"invalid {key}")
    for key in ("reject_unknown_keys", "enforce_model"):
        if not isinstance(cfg.get(key), bool):
            raise GatewayConfigError(f"invalid {key}: {cfg[key]!r}")
    if cfg["listen_host"] != "127.0.0.1":
        raise GatewayConfigError("gateway must bind to 127.0.0.1")
    if cfg["upstream_host"] not in ("127.0.0.1", "::1", "localhost"):
        raise GatewayConfigError("upstream must remain local")


def json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def error_payload(request_id: str, message: str, code: str) -> bytes:
    return json_bytes(
        {
            "error": {
                "message": message,
                "type": "gateway_error",
                "code": code,
            },
            "request_id": request_id,
        }
    )


def log_json(logger: logging.Logger, **fields: Any) -> None:
    logger.info(json.dumps(fields, ensure_ascii=False, separators=(",", ":"), default=str))


def validate_request_payload(payload: Any, cfg: dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")

    unknown = sorted(set(payload) - ALLOWED_KEYS)
    if unknown and cfg["reject_unknown_keys"]:
        raise ValueError(f"unsupported request parameter(s): {', '.join(unknown)}")

    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty array")
    if len(messages) > cfg["max_messages"]:
        raise ValueError(f"too many messages; maximum is {cfg['max_messages']}")

    for idx, message in enumerate(messages):
        if not isinstance(message, dict):
            raise ValueError(f"messages[{idx}] must be an object")
        role = message.get("role")
        if role not in ROLE_VALUES:
            raise ValueError(f"messages[{idx}].role is invalid")
        if "content" not in message:
            raise ValueError(f"messages[{idx}].content is required")
        content = message["content"]
        if not isinstance(content, (str, list, type(None))):
            raise ValueError(f"messages[{idx}].content must be string, array, or null")

    if "stream" in payload and not isinstance(payload["stream"], bool):
        raise ValueError("stream must be boolean")

    bounded_numbers = {
        "temperature": (0.0, 2.0),
        "top_p": (0.0, 1.0),
        "min_p": (0.0, 1.0),
        "typical_p": (0.0, 1.0),
        "presence_penalty": (-2.0, 2.0),
        "frequency_penalty": (-2.0, 2.0),
        "repeat_penalty": (0.0, 3.0),
    }
    for key, (low, high) in bounded_numbers.items():
        if key in payload:
            value = payload[key]
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not (low <= float(value) <= high):
                raise ValueError(f"{key} is outside the allowed range {low}..{high}")

    integer_keys = {"top_k": (0, 1000), "seed": (-2147483648, 2147483647)}
    for key, (low, high) in integer_keys.items():
        if key in payload:
            value = payload[key]
            if not isinstance(value, int) or isinstance(value, bool) or not (low <= value <= high):
                raise ValueError(f"{key} is invalid")

    if "max_tokens" in payload:
        value = payload["max_tokens"]
        if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= cfg["max_tokens"]):
            raise ValueError(f"max_tokens must be between 1 and {cfg['max_tokens']}")

    if "stop" in payload:
        stop = payload["stop"]
        if isinstance(stop, str):
            if len(stop) > 4096:
                raise ValueError("stop string is too long")
        elif isinstance(stop, list):
            if len(stop) > cfg["max_stop_items"] or not all(isinstance(item, str) for item in stop):
                raise ValueError(f"stop must be a string or up to {cfg['max_stop_items']} strings")
        else:
            raise ValueError("stop must be a string or array of strings")

    if cfg["enforce_model"] and "model" in payload and payload["model"] != cfg["model_id"]:
        raise ValueError(f"model must be {cfg['model_id']!r}")


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "JeffreyGateway/1.0"
    protocol_version = "HTTP/1.1"

    def _config(self) -> dict[str, Any]:
        return self.server.gateway_config  # type: ignore[attr-defined]

    def _logger(self) -> logging.Logger:
        return self.server.gateway_logger  # type: ignore[attr-defined]

    def _request_id(self) -> str:
        candidate = self.headers.get("X-Request-ID", "").strip()
        if candidate and REQUEST_ID_RE.fullmatch(candidate):
            return candidate
        return str(uuid.uuid4())

    def _set_common_headers(self, request_id: str) -> None:
        self.send_header("X-Request-ID", request_id)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")

    def _send_json(self, status: int, request_id: str, payload: Any) -> None:
        body = json_bytes(payload)
        self.send_response(status)
        self._set_common_headers(request_id)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, request_id: str, message: str, code: str) -> None:
        self._send_json(status, request_id, json.loads(error_payload(request_id, message, code)))

    def do_GET(self) -> None:  # noqa: N802
        request_id = self._request_id()
        if self.path == "/health":
            self._send_json(200, request_id, {"status": "ok", "service": "jeffrey-gateway", "request_id": request_id})
            return
        self._send_error(404, request_id, "not found", "not_found")

    def do_HEAD(self) -> None:  # noqa: N802
        request_id = self._request_id()
        if self.path == "/health":
            body = json_bytes({"status": "ok", "service": "jeffrey-gateway", "request_id": request_id})
            self.send_response(200)
            self._set_common_headers(request_id)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
        self._send_error(404, request_id, "not found", "not_found")

    def do_POST(self) -> None:  # noqa: N802
        started = time.monotonic()
        request_id = self._request_id()
        cfg = self._config()
        path = self.path.split("?", 1)[0]

        # Session-based authentication for browser/API calls.
        from session_auth import handle_login, handle_logout, require_session

        if path == "/auth/login":
            return handle_login(self, request_id)
        if path == "/auth/logout":
            return handle_logout(self, request_id)

        if path in ("/v1/chat/completions", "/v1/structured/sigma", "/v1/structured/yara", "/v1/structured/suricata", "/v1/structured/zeek", "/v1/utils/deterministic"):
            if require_session(self, request_id) is None:
                return

        if path == "/v1/structured/sigma":
            from structured_sigma import handle_sigma_request
            return handle_sigma_request(self)

        if path == "/v1/structured/yara":
            from structured_yara import handle_yara_request
            return handle_yara_request(self)

        if path == "/v1/structured/suricata":
            from structured_suricata import handle_suricata_request
            return handle_suricata_request(self)

        if path == "/v1/structured/zeek":
            from structured_zeek import handle_zeek_request
            return handle_zeek_request(self)

        if path == "/v1/utils/deterministic":
            from deterministic_route import handle_deterministic_utility_request
            return handle_deterministic_utility_request(self)


        if path != "/v1/chat/completions":
            self._send_error(404, request_id, "not found", "not_found")
            return

        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            self._send_error(415, request_id, "Content-Type must be application/json", "unsupported_media_type")
            return

        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower()
        if transfer_encoding and transfer_encoding != "identity":
            self._send_error(411, request_id, "chunked request bodies are not supported", "length_required")
            return

        raw_length = self.headers.get("Content-Length")
        try:
            content_length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            content_length = -1
        if content_length < 0:
            self._send_error(411, request_id, "Content-Length is required", "length_required")
            return
        if content_length > cfg["max_request_bytes"]:
            self._send_error(413, request_id, f"request body exceeds {cfg['max_request_bytes']} bytes", "request_too_large")
            return

        try:
            self.connection.settimeout(min(60, cfg["upstream_timeout_seconds"]))
            body = self.rfile.read(content_length)
            if len(body) != content_length:
                raise ValueError("incomplete request body")
            payload = json.loads(body.decode("utf-8"))
            validate_request_payload(payload, cfg)
        except UnicodeDecodeError:
            self._send_error(400, request_id, "request body is not valid UTF-8", "invalid_utf8")
            return
        except json.JSONDecodeError:
            self._send_error(400, request_id, "request body is not valid JSON", "invalid_json")
            return
        except ValueError as exc:
            self._send_error(400, request_id, str(exc), "invalid_request")
            return
        except socket.timeout:
            self._send_error(408, request_id, "timed out while reading request body", "request_timeout")
            return

        stream_requested = bool(payload.get("stream", False))
        upstream = None
        status = 502
        response_bytes = 0
        try:
            conn = http.client.HTTPConnection(
                cfg["upstream_host"],
                cfg["upstream_port"],
                timeout=cfg["upstream_timeout_seconds"],
            )
            upstream_headers = {
                "Content-Type": "application/json",
                "Accept": "text/event-stream" if stream_requested else "application/json",
                "X-Request-ID": request_id,
                "Connection": "close",
            }
            conn.request("POST", "/v1/chat/completions", body=body, headers=upstream_headers)
            upstream = conn.getresponse()
            status = upstream.status

            response_content_type = upstream.getheader("Content-Type", "application/octet-stream")
            is_stream = response_content_type.lower().startswith("text/event-stream") or stream_requested

            if is_stream:
                self.send_response(status)
                self._set_common_headers(request_id)
                self.send_header("Content-Type", response_content_type)
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                while True:
                    chunk = upstream.read(8192)
                    if not chunk:
                        break
                    response_bytes += len(chunk)
                    self.wfile.write(f"{len(chunk):X}\r\n".encode("ascii"))
                    self.wfile.write(chunk)
                    self.wfile.write(b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            else:
                response_body = upstream.read(cfg["max_response_bytes"] + 1)
                if len(response_body) > cfg["max_response_bytes"]:
                    self.close_connection = True
                    self._send_error(502, request_id, "upstream response exceeds gateway limit", "response_too_large")
                    return
                response_bytes = len(response_body)
                self.send_response(status)
                self._set_common_headers(request_id)
                self.send_header("Content-Type", response_content_type)
                self.send_header("Content-Length", str(len(response_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response_body)

        except (socket.timeout, TimeoutError):
            self.close_connection = True
            self._send_error(504, request_id, "upstream request timed out", "upstream_timeout")
        except (ConnectionError, OSError, http.client.HTTPException) as exc:
            self.close_connection = True
            self._send_error(502, request_id, "upstream model server is unavailable", "upstream_unavailable")
            log_json(
                self._logger(),
                event="upstream_error",
                request_id=request_id,
                error=str(exc),
            )
        finally:
            try:
                if upstream is not None:
                    upstream.close()
            finally:
                try:
                    conn.close()  # type: ignore[possibly-undefined]
                except Exception:
                    pass
                log_json(
                    self._logger(),
                    event="request_complete",
                    request_id=request_id,
                    method="POST",
                    path=path,
                    status=status,
                    duration_ms=round((time.monotonic() - started) * 1000, 1),
                    request_bytes=content_length,
                    response_bytes=response_bytes,
                    stream=stream_requested,
                    remote=self.headers.get("X-Forwarded-For", self.client_address[0]),
                )

    def log_message(self, fmt: str, *args: Any) -> None:
        log_json(self._logger(), event="http_access", message=fmt % args)


def make_logger() -> logging.Logger:
    logger = logging.getLogger("jeffrey-gateway")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def build_server(cfg: dict[str, Any]) -> ThreadingHTTPServer:
    class GatewayServer(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = GatewayServer((cfg["listen_host"], cfg["listen_port"]), GatewayHandler)
    server.gateway_config = cfg  # type: ignore[attr-defined]
    server.gateway_logger = make_logger()  # type: ignore[attr-defined]
    from session_auth import init_server
    init_server(server)
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="Jeffrey Gateway")
    parser.add_argument("--config", default="/etc/jeffrey-gateway/gateway.json")
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
    except (GatewayConfigError, OSError, json.JSONDecodeError) as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    logger = make_logger()
    log_json(
        logger,
        event="startup",
        listen=f"{cfg['listen_host']}:{cfg['listen_port']}",
        upstream=f"{cfg['upstream_host']}:{cfg['upstream_port']}",
        max_request_bytes=cfg["max_request_bytes"],
        max_tokens=cfg["max_tokens"],
    )

    server = build_server(cfg)
    server.gateway_logger = logger  # type: ignore[attr-defined]
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
