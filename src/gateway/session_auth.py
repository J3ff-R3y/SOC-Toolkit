#!/usr/bin/env python3
from __future__ import annotations

import json
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

AUTH_FILE = Path("/etc/jeffrey-gateway/users.htpasswd")
HTPASSWD_CANDIDATES = (Path("/usr/bin/htpasswd"), Path("/bin/htpasswd"))


def _resolve_htpasswd() -> str | None:
    for candidate in HTPASSWD_CANDIDATES:
        if candidate.is_file():
            return str(candidate)
    return None
SESSION_TTL_SECONDS = 8 * 60 * 60
MAX_LOGIN_BODY = 16 * 1024
MAX_USERNAME_LEN = 255
MAX_PASSWORD_LEN = 1024


def init_server(server: Any) -> None:
    server.jeffrey_auth_sessions = {}
    server.jeffrey_auth_lock = threading.Lock()


def _read_json_body(handler: Any) -> dict[str, Any]:
    content_type = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise ValueError("Content-Type must be application/json")

    if (handler.headers.get("Transfer-Encoding") or "").strip():
        raise ValueError("chunked request bodies are not supported")

    raw_length = handler.headers.get("Content-Length")
    if raw_length is None:
        raise ValueError("Content-Length is required")

    try:
        content_length = int(raw_length)
    except ValueError as exc:
        raise ValueError("invalid Content-Length") from exc

    if content_length < 1 or content_length > MAX_LOGIN_BODY:
        raise ValueError("invalid login request size")

    raw = handler.rfile.read(content_length)
    if len(raw) != content_length:
        raise ValueError("incomplete request body")

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("request body is not valid JSON") from exc

    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")
    return payload


def _verify_credentials(username: str, password: str) -> bool:
    htpasswd_bin = _resolve_htpasswd()
    if not AUTH_FILE.is_file() or htpasswd_bin is None:
        return False

    try:
        proc = subprocess.run(
            [htpasswd_bin, "-iv", str(AUTH_FILE), username],
            input=password + "\n",
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError):
        return False

    return proc.returncode == 0


def _prune_locked(server: Any, now: float) -> None:
    expired = [
        token
        for token, record in server.jeffrey_auth_sessions.items()
        if record["expires_at"] <= now
    ]
    for token in expired:
        server.jeffrey_auth_sessions.pop(token, None)


def handle_login(handler: Any, request_id: str) -> None:
    try:
        payload = _read_json_body(handler)
    except ValueError as exc:
        handler._send_error(400, request_id, str(exc), "invalid_login_request")
        return

    if set(payload) != {"username", "password"}:
        handler._send_error(
            400,
            request_id,
            "login requires exactly username and password",
            "invalid_login_request",
        )
        return

    username = payload.get("username")
    password = payload.get("password")

    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not username
        or not password
        or len(username) > MAX_USERNAME_LEN
        or len(password) > MAX_PASSWORD_LEN
        or ":" in username
        or "\x00" in username
        or "\x00" in password
    ):
        handler._send_error(
            401,
            request_id,
            "invalid username or password",
            "invalid_credentials",
        )
        return

    if not _verify_credentials(username, password):
        handler._send_error(
            401,
            request_id,
            "invalid username or password",
            "invalid_credentials",
        )
        return

    token = secrets.token_urlsafe(32)
    now = time.time()

    with handler.server.jeffrey_auth_lock:
        _prune_locked(handler.server, now)
        handler.server.jeffrey_auth_sessions[token] = {
            "username": username,
            "expires_at": now + SESSION_TTL_SECONDS,
        }

    handler._send_json(
        200,
        request_id,
        {
            "status": "ok",
            "session_token": token,
            "expires_in": SESSION_TTL_SECONDS,
            "username": username,
        },
    )


def _token_from_request(handler: Any) -> str:
    return (handler.headers.get("X-Jeffrey-Session") or "").strip()


def require_session(handler: Any, request_id: str) -> str | None:
    token = _token_from_request(handler)
    if not token or len(token) > 256:
        # Close rejected POST requests before backend connection reuse so an
        # unread body cannot desynchronize the next HTTP/1.1 request.
        handler.close_connection = True
        handler._send_error(
            401,
            request_id,
            "login required",
            "authentication_required",
        )
        return None

    now = time.time()
    with handler.server.jeffrey_auth_lock:
        _prune_locked(handler.server, now)
        record = handler.server.jeffrey_auth_sessions.get(token)
        if record is None:
            handler.close_connection = True
            handler._send_error(
                401,
                request_id,
                "invalid or expired session",
                "authentication_required",
            )
            return None
        record["expires_at"] = now + SESSION_TTL_SECONDS
        return str(record["username"])


def handle_logout(handler: Any, request_id: str) -> None:
    token = _token_from_request(handler)
    if token:
        with handler.server.jeffrey_auth_lock:
            handler.server.jeffrey_auth_sessions.pop(token, None)

    handler._send_json(200, request_id, {"status": "logged_out"})
