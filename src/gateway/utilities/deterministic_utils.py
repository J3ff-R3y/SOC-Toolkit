#!/usr/bin/env python3
"""
Jeffrey Toolkit — deterministic utility core v1.

Security boundary:
- fixed operation allowlist;
- JSON stdin only;
- no network access;
- no filesystem path input;
- no subprocess/shell execution;
- bounded input/output;
- machine-readable JSON only.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import json
import re
import sys
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

VERSION = "deterministic-utils-v1"
SCHEMA_VERSION = "1"

MAX_REQUEST_BYTES = 262144
MAX_VALUE_CHARS = 131072
MAX_BINARY_BYTES = 65536

ALLOWED_OPERATIONS = {
    "normalize_ioc",
    "hex_encode",
    "hex_decode",
    "base64_encode",
    "base64_decode",
}

HASH_LENGTHS = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}

HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
EMAIL_LOCAL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")


class UtilityError(Exception):
    def __init__(self, code: str, message: str, path: str = "$") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.path = path


def ok(operation: str, result: Any) -> dict[str, Any]:
    return {
        "valid": True,
        "schema_version": SCHEMA_VERSION,
        "operation": operation,
        "result": result,
        "meta": {
            "deterministic": True,
            "network_access": False,
            "filesystem_access": False,
            "shell_execution": False,
        },
    }


def error(exc: UtilityError) -> dict[str, Any]:
    return {
        "valid": False,
        "error": exc.code,
        "message": exc.message,
        "path": exc.path,
        "utility_version": VERSION,
    }


def validate_domain(value: str) -> str:
    domain = value.rstrip(".")
    if not domain:
        raise UtilityError("invalid_ioc", "domain is empty", "$.value")

    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UtilityError("invalid_ioc", "domain is not valid IDNA", "$.value") from exc

    ascii_domain = ascii_domain.lower()
    if len(ascii_domain) > 253:
        raise UtilityError("invalid_ioc", "domain exceeds 253 characters", "$.value")

    labels = ascii_domain.split(".")
    if len(labels) < 2:
        raise UtilityError(
            "invalid_ioc",
            "domain IOC must contain at least one dot",
            "$.value",
        )

    for label in labels:
        if not DOMAIN_LABEL_RE.fullmatch(label):
            raise UtilityError(
                "invalid_ioc",
                f"invalid domain label: {label}",
                "$.value",
            )

    return ascii_domain


def normalize_ip_or_cidr(value: str) -> dict[str, Any] | None:
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            return {
                "type": "cidr",
                "ip_version": net.version,
                "normalized": str(net),
            }

        ip = ipaddress.ip_address(value)
        return {
            "type": "ip",
            "ip_version": ip.version,
            "normalized": str(ip),
        }
    except ValueError:
        return None


def normalize_hash(value: str) -> dict[str, Any] | None:
    if len(value) not in HASH_LENGTHS:
        return None
    if not HEX_RE.fullmatch(value):
        return None

    return {
        "type": "hash",
        "algorithm": HASH_LENGTHS[len(value)],
        "normalized": value.lower(),
    }


def normalize_email(value: str) -> dict[str, Any] | None:
    if value.count("@") != 1:
        return None

    local, domain = value.rsplit("@", 1)
    if not EMAIL_LOCAL_RE.fullmatch(local):
        raise UtilityError("invalid_ioc", "invalid email-like IOC local part", "$.value")

    normalized_domain = validate_domain(domain)
    return {
        "type": "email",
        "normalized": f"{local}@{normalized_domain}",
        "local_part_preserved": True,
    }


def normalized_url_netloc(parts: SplitResult) -> str:
    if parts.username is not None or parts.password is not None:
        raise UtilityError(
            "invalid_ioc",
            "URL userinfo/credentials are not accepted",
            "$.value",
        )

    host = parts.hostname
    if not host:
        raise UtilityError("invalid_ioc", "URL requires a host", "$.value")

    try:
        parsed_ip = ipaddress.ip_address(host)
        normalized_host = str(parsed_ip)
        if parsed_ip.version == 6:
            normalized_host = f"[{normalized_host}]"
    except ValueError:
        normalized_host = validate_domain(host)

    try:
        port = parts.port
    except ValueError as exc:
        raise UtilityError("invalid_ioc", "URL port is invalid", "$.value") from exc

    scheme = parts.scheme.lower()
    if port is None:
        return normalized_host

    if not 1 <= port <= 65535:
        raise UtilityError("invalid_ioc", "URL port is outside 1..65535", "$.value")

    # Remove only canonical default ports.
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return normalized_host

    return f"{normalized_host}:{port}"


def normalize_url(value: str) -> dict[str, Any] | None:
    if "://" not in value:
        return None

    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise UtilityError("invalid_ioc", "URL could not be parsed", "$.value") from exc

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise UtilityError(
            "invalid_ioc",
            "only http and https URL IOCs are supported",
            "$.value",
        )

    netloc = normalized_url_netloc(parts)
    normalized = urlunsplit(
        (
            scheme,
            netloc,
            parts.path or "",
            parts.query or "",
            parts.fragment or "",
        )
    )

    return {
        "type": "url",
        "scheme": scheme,
        "normalized": normalized,
    }


def normalize_domain(value: str) -> dict[str, Any] | None:
    if "." not in value:
        return None

    # Obvious URI/email separators should not fall through to domain parsing.
    if any(ch in value for ch in "/:@[]"):
        return None

    domain = validate_domain(value)
    return {
        "type": "domain",
        "normalized": domain,
    }


def normalize_ioc(value: str) -> dict[str, Any]:
    candidate = value.strip()
    if not candidate:
        raise UtilityError("invalid_ioc", "IOC value is empty", "$.value")

    result = normalize_hash(candidate)
    if result is not None:
        return result

    result = normalize_ip_or_cidr(candidate)
    if result is not None:
        return result

    result = normalize_email(candidate)
    if result is not None:
        return result

    result = normalize_url(candidate)
    if result is not None:
        return result

    result = normalize_domain(candidate)
    if result is not None:
        return result

    raise UtilityError(
        "unsupported_ioc",
        "value is not a supported hash, IP/CIDR, domain, URL, or email-like IOC",
        "$.value",
    )


def utf8_bytes(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > MAX_BINARY_BYTES:
        raise UtilityError(
            "output_too_large",
            f"UTF-8 value exceeds {MAX_BINARY_BYTES} bytes",
            "$.value",
        )
    return raw


def hex_encode(value: str) -> dict[str, Any]:
    raw = utf8_bytes(value)
    return {
        "encoding": "hex",
        "input_encoding": "utf-8",
        "decoded_bytes": len(raw),
        "value": raw.hex(),
    }


def hex_decode(value: str) -> dict[str, Any]:
    compact = value.strip()
    if not compact:
        raise UtilityError("invalid_hex", "hex input is empty", "$.value")
    if len(compact) % 2:
        raise UtilityError("invalid_hex", "hex input length must be even", "$.value")
    if len(compact) > MAX_BINARY_BYTES * 2:
        raise UtilityError("input_too_large", "hex decoded output would exceed limit", "$.value")
    if not HEX_RE.fullmatch(compact):
        raise UtilityError("invalid_hex", "hex input contains non-hex characters", "$.value")

    try:
        raw = bytes.fromhex(compact)
    except ValueError as exc:
        raise UtilityError("invalid_hex", "hex input could not be decoded", "$.value") from exc

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UtilityError(
            "invalid_utf8",
            "decoded hex bytes are not valid UTF-8",
            "$.value",
        ) from exc

    return {
        "encoding": "utf-8",
        "source_encoding": "hex",
        "decoded_bytes": len(raw),
        "value": text,
    }


def base64_encode(value: str) -> dict[str, Any]:
    raw = utf8_bytes(value)
    encoded = base64.b64encode(raw).decode("ascii")
    return {
        "encoding": "base64",
        "input_encoding": "utf-8",
        "decoded_bytes": len(raw),
        "value": encoded,
    }


def base64_decode(value: str) -> dict[str, Any]:
    compact = "".join(value.split())
    if not compact:
        raise UtilityError("invalid_base64", "base64 input is empty", "$.value")

    if len(compact) > ((MAX_BINARY_BYTES + 2) // 3) * 4 + 4:
        raise UtilityError(
            "input_too_large",
            "base64 decoded output would exceed limit",
            "$.value",
        )

    try:
        raw = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise UtilityError("invalid_base64", "invalid base64 input", "$.value") from exc

    if len(raw) > MAX_BINARY_BYTES:
        raise UtilityError(
            "output_too_large",
            "base64 decoded output exceeds limit",
            "$.value",
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UtilityError(
            "invalid_utf8",
            "decoded base64 bytes are not valid UTF-8",
            "$.value",
        ) from exc

    return {
        "encoding": "utf-8",
        "source_encoding": "base64",
        "decoded_bytes": len(raw),
        "value": text,
    }


def execute(operation: str, value: str) -> dict[str, Any]:
    if operation not in ALLOWED_OPERATIONS:
        raise UtilityError(
            "operation_not_allowed",
            "operation is not in the deterministic allowlist",
            "$.operation",
        )

    if len(value) > MAX_VALUE_CHARS:
        raise UtilityError(
            "input_too_large",
            f"value exceeds {MAX_VALUE_CHARS} characters",
            "$.value",
        )

    if operation == "normalize_ioc":
        return normalize_ioc(value)
    if operation == "hex_encode":
        return hex_encode(value)
    if operation == "hex_decode":
        return hex_decode(value)
    if operation == "base64_encode":
        return base64_encode(value)
    if operation == "base64_decode":
        return base64_decode(value)

    raise UtilityError("operation_not_allowed", "operation is not implemented", "$.operation")


def read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise UtilityError(
            "request_too_large",
            f"JSON request exceeds {MAX_REQUEST_BYTES} bytes",
            "$",
        )

    try:
        obj = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise UtilityError("invalid_json", "request is not UTF-8", "$") from exc
    except json.JSONDecodeError as exc:
        raise UtilityError("invalid_json", "request is not valid JSON", "$") from exc

    if not isinstance(obj, dict):
        raise UtilityError("invalid_request", "request must be a JSON object", "$")

    if set(obj) != {"operation", "value"}:
        extra = sorted(set(obj) - {"operation", "value"})
        missing = sorted({"operation", "value"} - set(obj))
        details = []
        if extra:
            details.append("unsupported keys: " + ", ".join(extra))
        if missing:
            details.append("missing keys: " + ", ".join(missing))
        raise UtilityError(
            "invalid_request",
            "; ".join(details) or "request shape is invalid",
            "$",
        )

    if not isinstance(obj["operation"], str):
        raise UtilityError("invalid_request", "operation must be a string", "$.operation")
    if not isinstance(obj["value"], str):
        raise UtilityError("invalid_request", "value must be a string", "$.value")

    return obj


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list-operations", action="store_true")
    args = parser.parse_args()

    if args.list_operations:
        print(
            json.dumps(
                {
                    "utility_version": VERSION,
                    "operations": sorted(ALLOWED_OPERATIONS),
                    "network_access": False,
                    "filesystem_access": False,
                    "shell_execution": False,
                },
                sort_keys=True,
            )
        )
        return 0

    try:
        req = read_request()
        result = execute(req["operation"], req["value"])
        print(json.dumps(ok(req["operation"], result), ensure_ascii=False, sort_keys=True))
        return 0
    except UtilityError as exc:
        print(json.dumps(error(exc), ensure_ascii=False, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
