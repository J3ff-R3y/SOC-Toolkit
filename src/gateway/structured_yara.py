#!/usr/bin/env python3
# Jeffrey Toolkit — structured YARA integration.
# Baseline validation only; NOT YARA compiler-equivalent.

from __future__ import annotations

import http.client
import json
import re
import subprocess
import uuid
from pathlib import Path
from typing import Any

SCHEMA_PATH = Path("/opt/jeffrey-gateway/schemas/yara-output-v1.schema.json")
VALIDATOR_PATH = Path("/opt/jeffrey-gateway/validators/validate_yara_baseline.py")
ALLOWED_KEYS = {"messages", "max_tokens", "temperature"}
ALLOWED_ROLES = {"system", "user", "assistant"}


class YaraRouteError(Exception):
    def __init__(self, status: int, code: str, message: str, details: Any = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details


def _cfg(handler: Any, key: str, default: Any) -> Any:
    cfg = handler.server.gateway_config
    if isinstance(cfg, dict):
        return cfg.get(key, default)
    return getattr(cfg, key, default)


def _request_id(handler: Any) -> str:
    return (handler.headers.get("X-Request-ID") or str(uuid.uuid4())).strip()


def _error(handler: Any, request_id: str, exc: YaraRouteError) -> None:
    if exc.details is None:
        handler._send_error(exc.status, request_id, exc.message, exc.code)
        return

    # GatewayHandler._send_error accepts only:
    #   status, request_id, message, code
    # Detailed errors therefore use the existing JSON response helper.
    handler._send_json(
        exc.status,
        request_id,
        {
            "error": {
                "code": exc.code,
                "message": exc.message,
                "request_id": request_id,
                "details": exc.details,
            }
        },
    )


def _read_json(handler: Any) -> dict[str, Any]:
    ctype = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if ctype != "application/json":
        raise YaraRouteError(415, "unsupported_media_type", "Content-Type must be application/json")

    if (handler.headers.get("Transfer-Encoding") or "").strip():
        raise YaraRouteError(400, "invalid_request", "chunked request bodies are not supported")

    raw_len = handler.headers.get("Content-Length")
    if raw_len is None:
        raise YaraRouteError(400, "invalid_request", "Content-Length is required")
    try:
        length = int(raw_len)
    except ValueError as exc:
        raise YaraRouteError(400, "invalid_request", "invalid Content-Length") from exc

    max_bytes = int(_cfg(handler, "max_request_bytes", 33554432))
    if length < 1:
        raise YaraRouteError(400, "invalid_request", "empty request body")
    if length > max_bytes:
        raise YaraRouteError(413, "request_too_large", "request body exceeds configured maximum")

    raw = handler.rfile.read(length)
    if len(raw) != length:
        raise YaraRouteError(400, "invalid_request", "incomplete request body")

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise YaraRouteError(400, "invalid_json", "request body is not valid JSON") from exc

    if not isinstance(payload, dict):
        raise YaraRouteError(400, "invalid_request", "request body must be a JSON object")

    unknown = sorted(set(payload) - ALLOWED_KEYS)
    if unknown:
        raise YaraRouteError(
            400,
            "unknown_request_keys",
            "request contains unsupported keys",
            {"keys": unknown},
        )
    return payload


def _messages(payload: dict[str, Any], handler: Any) -> list[dict[str, str]]:
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise YaraRouteError(400, "invalid_messages", "messages must be a non-empty array")

    max_messages = int(_cfg(handler, "max_messages", 100))
    if len(messages) > max_messages:
        raise YaraRouteError(400, "too_many_messages", "messages exceeds configured maximum")

    out: list[dict[str, str]] = []
    for idx, item in enumerate(messages):
        if not isinstance(item, dict) or set(item) != {"role", "content"}:
            raise YaraRouteError(
                400,
                "invalid_messages",
                f"messages[{idx}] requires exactly role and content",
            )
        role = item.get("role")
        content = item.get("content")
        if role not in ALLOWED_ROLES:
            raise YaraRouteError(400, "invalid_messages", f"messages[{idx}].role is invalid")
        if not isinstance(content, str) or not content.strip():
            raise YaraRouteError(
                400,
                "invalid_messages",
                f"messages[{idx}].content must be a non-empty string",
            )
        out.append({"role": role, "content": content})
    return out


def _options(payload: dict[str, Any], handler: Any) -> tuple[int, float]:
    max_allowed = int(_cfg(handler, "max_tokens", 8192))
    max_tokens = payload.get("max_tokens", min(2048, max_allowed))
    if not isinstance(max_tokens, int) or isinstance(max_tokens, bool):
        raise YaraRouteError(400, "invalid_max_tokens", "max_tokens must be an integer")
    if max_tokens < 64 or max_tokens > max_allowed:
        raise YaraRouteError(
            400,
            "invalid_max_tokens",
            f"max_tokens must be between 64 and {max_allowed}",
        )

    temperature = payload.get("temperature", 0)
    if not isinstance(temperature, (int, float)) or isinstance(temperature, bool):
        raise YaraRouteError(400, "invalid_temperature", "temperature must be numeric")
    temperature = float(temperature)
    if temperature < 0 or temperature > 1:
        raise YaraRouteError(
            400,
            "invalid_temperature",
            "temperature must be between 0 and 1",
        )
    return max_tokens, temperature


def _load_schema() -> dict[str, Any]:
    try:
        return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise YaraRouteError(500, "schema_unavailable", "YARA schema unavailable") from exc


def _model_schema(full_schema: dict[str, Any]) -> dict[str, Any]:
    props = full_schema["properties"]
    schema: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["content"],
        "properties": {"content": props["content"]},
    }
    if "summary" in props:
        schema["properties"]["summary"] = props["summary"]
    return schema



_RULE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_META_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_STRING_ID_RE = re.compile(r"^\$?[A-Za-z_][A-Za-z0-9_]*$")
_ALLOWED_AST_KEYS = {"rule", "meta", "strings", "condition", "summary"}


def _yara_quote(value: str) -> str:
    # JSON string escaping is compatible with the conservative YARA text
    # baseline for ordinary quoted strings.
    return json.dumps(value, ensure_ascii=False)


def _render_meta_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        return _yara_quote(value)
    raise YaraRouteError(
        422,
        "yara_model_shape_invalid",
        "YARA AST meta values must be strings, integers or booleans",
    )


def _normalize_modifiers(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        mods = value.split()
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        mods = list(value)
    else:
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "YARA AST modifiers must be a string or array of strings",
        )

    allowed = {
        "ascii", "wide", "nocase", "fullword",
        "base64", "base64wide",
    }
    out: list[str] = []
    for mod in mods:
        token = mod.strip()
        if not token:
            continue
        if token in allowed or re.fullmatch(r"xor(?:\([0-9]{1,3}(?:-[0-9]{1,3})?\))?", token):
            out.append(token)
        else:
            raise YaraRouteError(
                422,
                "yara_model_shape_invalid",
                f"unsupported YARA AST modifier: {token}",
            )
    return out


def _render_string_value(spec: Any) -> tuple[str, list[str]]:
    if isinstance(spec, str):
        return _yara_quote(spec), []

    if not isinstance(spec, dict):
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "YARA AST string entry must be a string or object",
        )

    allowed = {"value", "type", "modifiers"}
    unknown = sorted(set(spec) - allowed)
    if unknown:
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "YARA AST string entry contains unsupported keys",
            {"keys": unknown},
        )

    value = spec.get("value")
    if not isinstance(value, str) or not value:
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "YARA AST string entry requires a non-empty string value",
        )

    kind = spec.get("type", "text")
    if kind not in {"text", "regex", "hex"}:
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "YARA AST string type must be text, regex or hex",
        )

    if kind == "text":
        literal = _yara_quote(value)
    elif kind == "regex":
        literal = value if value.startswith("/") and value.count("/") >= 2 else "/" + value.replace("/", r"\/") + "/"
    else:
        clean = value.strip()
        literal = clean if clean.startswith("{") and clean.endswith("}") else "{ " + clean + " }"

    return literal, _normalize_modifiers(spec.get("modifiers"))


def _render_strings(value: Any) -> list[str]:
    if value is None:
        return []

    entries: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        entries = list(value.items())
    elif isinstance(value, list):
        for item in value:
            if not isinstance(item, dict):
                raise YaraRouteError(
                    422,
                    "yara_model_shape_invalid",
                    "YARA AST strings array entries must be objects",
                )
            allowed = {"id", "name", "value", "type", "modifiers"}
            unknown = sorted(set(item) - allowed)
            if unknown:
                raise YaraRouteError(
                    422,
                    "yara_model_shape_invalid",
                    "YARA AST strings array entry contains unsupported keys",
                    {"keys": unknown},
                )
            sid = item.get("id", item.get("name"))
            if not isinstance(sid, str):
                raise YaraRouteError(
                    422,
                    "yara_model_shape_invalid",
                    "YARA AST strings array entry requires id or name",
                )
            spec = {
                key: item[key]
                for key in ("value", "type", "modifiers")
                if key in item
            }
            entries.append((sid, spec))
    else:
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "YARA AST strings must be an object or array",
        )

    if len(entries) > 256:
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "YARA AST contains more than 256 strings",
        )

    seen: set[str] = set()
    lines: list[str] = []
    for sid, spec in entries:
        if not isinstance(sid, str) or not _STRING_ID_RE.fullmatch(sid):
            raise YaraRouteError(
                422,
                "yara_model_shape_invalid",
                f"invalid YARA AST string identifier: {sid!r}",
            )
        normalized = sid if sid.startswith("$") else "$" + sid
        if normalized in seen:
            raise YaraRouteError(
                422,
                "yara_model_shape_invalid",
                f"duplicate YARA AST string identifier: {normalized}",
            )
        seen.add(normalized)

        literal, modifiers = _render_string_value(spec)
        suffix = (" " + " ".join(modifiers)) if modifiers else ""
        lines.append(f"    {normalized} = {literal}{suffix}")
    return lines


def _normalize_model_output(model_obj: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Normalize the intended content envelope or the observed YARA AST shape."""
    if "artifact_type" in model_obj or "schema_version" in model_obj:
        raise YaraRouteError(
            422,
            "structured_output_invalid",
            "model returned gateway-owned protocol metadata",
        )

    # Preferred model form: content + optional summary.
    if "content" in model_obj:
        return model_obj, "content_string"

    unknown = sorted(set(model_obj) - _ALLOWED_AST_KEYS)
    required = {"rule", "condition"}
    if unknown or not required.issubset(model_obj):
        details: dict[str, Any] = {}
        if unknown:
            details["unknown_keys"] = unknown
        missing = sorted(required - set(model_obj))
        if missing:
            details["missing_keys"] = missing
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "model output was neither the YARA content envelope nor the supported YARA AST form",
            details or None,
        )

    rule_spec = model_obj["rule"]
    tags: list[str] = []
    modifier = ""

    if isinstance(rule_spec, str):
        rule_name = rule_spec
    elif isinstance(rule_spec, dict):
        allowed_rule = {"name", "tags", "modifier"}
        unknown_rule = sorted(set(rule_spec) - allowed_rule)
        if unknown_rule:
            raise YaraRouteError(
                422,
                "yara_model_shape_invalid",
                "YARA AST rule object contains unsupported keys",
                {"keys": unknown_rule},
            )
        rule_name = rule_spec.get("name")
        raw_tags = rule_spec.get("tags", [])
        modifier = rule_spec.get("modifier", "")
        if raw_tags is None:
            raw_tags = []
        if not isinstance(raw_tags, list) or not all(isinstance(tag, str) for tag in raw_tags):
            raise YaraRouteError(
                422,
                "yara_model_shape_invalid",
                "YARA AST rule tags must be an array of strings",
            )
        tags = raw_tags
        if modifier not in {"", "private", "global"}:
            raise YaraRouteError(
                422,
                "yara_model_shape_invalid",
                "YARA AST rule modifier must be private, global or empty",
            )
    else:
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "YARA AST rule must be a string or object",
        )

    if not isinstance(rule_name, str) or not _RULE_NAME_RE.fullmatch(rule_name):
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "YARA AST rule name is invalid",
        )

    for tag in tags:
        if not _RULE_NAME_RE.fullmatch(tag):
            raise YaraRouteError(
                422,
                "yara_model_shape_invalid",
                f"invalid YARA AST tag: {tag}",
            )

    condition = model_obj.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "YARA AST condition must be a non-empty string",
        )

    meta = model_obj.get("meta", {})
    if meta is None:
        meta = {}
    if not isinstance(meta, dict):
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "YARA AST meta must be an object",
        )
    if len(meta) > 64:
        raise YaraRouteError(
            422,
            "yara_model_shape_invalid",
            "YARA AST contains more than 64 meta fields",
        )

    header = ""
    if modifier:
        header += modifier + " "
    header += "rule " + rule_name
    if tags:
        header += " : " + " ".join(tags)
    header += " {"

    lines = [header]

    if meta:
        lines.append("  meta:")
        for key, value in meta.items():
            if not isinstance(key, str) or not _META_KEY_RE.fullmatch(key):
                raise YaraRouteError(
                    422,
                    "yara_model_shape_invalid",
                    f"invalid YARA AST meta key: {key!r}",
                )
            lines.append(f"    {key} = {_render_meta_value(value)}")

    string_lines = _render_strings(model_obj.get("strings"))
    if string_lines:
        lines.append("  strings:")
        lines.extend(string_lines)

    lines.append("  condition:")
    for condition_line in condition.strip().splitlines():
        lines.append("    " + condition_line.rstrip())
    lines.append("}")

    normalized: dict[str, Any] = {"content": "\n".join(lines) + "\n"}
    summary = model_obj.get("summary")
    if summary is not None:
        if not isinstance(summary, str) or not summary.strip():
            raise YaraRouteError(
                422,
                "yara_model_shape_invalid",
                "YARA AST summary must be a non-empty string when present",
            )
        normalized["summary"] = summary.strip()

    return normalized, "ast_normalized"


def _post_json(
    host: str,
    port: int,
    timeout: int,
    path: str,
    payload: dict[str, Any],
    request_id: str,
) -> tuple[int, bytes]:
    raw_body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(
            "POST",
            path,
            body=raw_body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(raw_body)),
                "X-Request-ID": request_id,
                "Connection": "close",
            },
        )
        resp = conn.getresponse()
        raw = resp.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise YaraRouteError(502, "upstream_response_too_large", "upstream response too large")
        return resp.status, raw
    except YaraRouteError:
        raise
    except Exception as exc:
        raise YaraRouteError(502, "upstream_error", "could not communicate with model server") from exc
    finally:
        conn.close()


def _generate(
    handler: Any,
    request_id: str,
    messages: list[dict[str, str]],
    max_tokens: int,
    temperature: float,
    model_schema: dict[str, Any],
    strict_retry: bool = False,
) -> dict[str, Any]:
    host = str(_cfg(handler, "upstream_host", "127.0.0.1"))
    port = int(_cfg(handler, "upstream_port", 8081))
    timeout = int(_cfg(handler, "upstream_timeout_seconds", 900))

    guardrail = {
        "role": "system",
        "content": (
            "Generate exactly one conservative YARA rule. Return ONLY one JSON object. "
            "The preferred and intended top-level form is exactly: "
            "{\"content\": \"<complete YARA rule text>\", \"summary\": \"<optional short summary>\"}. "
            "Do NOT return rule, meta, strings or condition as top-level JSON keys; those "
            "belong inside the YARA source string in content. Do not use markdown fences. "
            "Inside content, output exactly one complete YARA source rule and nothing else: "
            "no prose, no markdown, no JSON, and no explanation before or after the rule. "
            "The first non-whitespace token inside content must begin a YARA rule declaration "
            "(rule, private rule, or global rule), and the content must end after that one "
            "rule's closing brace. When the request asks for multiple strings, put each "
            "string in the YARA strings section and express the requested relationship in "
            "the condition. Do not use import or include statements because this host does "
            "not yet have an approved YARA engine/module set. Keep optional metadata minimal. "
            "Do not claim the rule was compiled, engine-validated, effective, or safe. Use "
            "only facts supported by the request."
        ),
    }

    if strict_retry:
        guardrail["content"] += (
            " FORMAT-REPAIR RETRY: the previous generated content did not contain a "
            "parsable YARA rule. Return the content string starting directly with exactly "
            "one complete YARA rule declaration and ending with its closing brace. Do not "
            "place JSON, YAML, markdown fences, commentary, labels, prefixes or suffixes "
            "inside content. Preserve the user's requested detection semantics."
        )

    apply_payload = {
        "messages": [guardrail, *messages],
        "add_generation_prompt": True,
    }

    status, raw = _post_json(host, port, timeout, "/apply-template", apply_payload, request_id)
    if status != 200:
        raise YaraRouteError(
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
        raise YaraRouteError(
            502,
            "upstream_error",
            "llama.cpp /apply-template returned an invalid response",
        ) from exc

    # Same deterministic Qwen workaround that proved successful for Sigma.
    prompt += "<think>\n\n</think>\n\n"

    completion_payload = {
        "prompt": prompt,
        "n_predict": max_tokens,
        "temperature": temperature,
        "stream": False,
        "json_schema": model_schema,
    }

    status, raw = _post_json(host, port, timeout, "/completion", completion_payload, request_id)
    if status != 200:
        raise YaraRouteError(
            502,
            "upstream_error",
            f"model server /completion returned HTTP {status}",
            {"upstream_body": raw[:4000].decode("utf-8", errors="replace")},
        )

    try:
        outer = json.loads(raw)
        generated = outer["content"]
        model_obj = json.loads(generated)
        if not isinstance(model_obj, dict):
            raise ValueError
    except Exception as exc:
        raise YaraRouteError(
            502,
            "upstream_error",
            "model /completion response was not valid structured JSON",
            {"upstream_body": raw[:4000].decode("utf-8", errors="replace")},
        ) from exc

    return model_obj


def _validate_schema(envelope: dict[str, Any], schema: dict[str, Any]) -> None:
    try:
        import jsonschema
        jsonschema.Draft202012Validator.check_schema(schema)
        issues = list(jsonschema.Draft202012Validator(schema).iter_errors(envelope))
    except Exception as exc:
        raise YaraRouteError(500, "validation_unavailable", "JSON Schema validator failed") from exc

    if issues:
        details: list[dict[str, str]] = []
        for issue in issues:
            path = "$"
            for item in issue.path:
                path += f"[{json.dumps(item)}]" if isinstance(item, str) else f"[{item}]"
            details.append({"path": path, "message": issue.message})
        raise YaraRouteError(
            422,
            "schema_validation_failed",
            "model output failed YARA envelope JSON Schema validation",
            {"valid": False, "errors": details},
        )


def _validate_baseline(content: str) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            [str(VALIDATOR_PATH), "--content"],
            input=content,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        detail = json.loads(proc.stdout)
    except Exception as exc:
        raise YaraRouteError(
            500,
            "validation_unavailable",
            "YARA baseline validator could not be executed",
        ) from exc

    if proc.returncode != 0 or detail.get("valid") is not True:
        raise YaraRouteError(
            422,
            "yara_validation_failed",
            "generated YARA rule failed deterministic baseline validation",
            detail,
        )
    return detail


def _retryable_zero_rule_failure(exc: YaraRouteError) -> bool:
    """Return true only for the specific prompt-sensitive zero-rule baseline failure."""
    if exc.code != "yara_validation_failed" or not isinstance(exc.details, dict):
        return False

    errors = exc.details.get("errors")
    if not isinstance(errors, list):
        return False

    for item in errors:
        if not isinstance(item, dict):
            continue
        message = item.get("message")
        if (
            isinstance(message, str)
            and "exactly one YARA rule is required; found 0" in message
        ):
            return True
    return False


def handle_yara_request(handler: Any) -> None:
    request_id = _request_id(handler)
    try:
        payload = _read_json(handler)
        messages = _messages(payload, handler)
        max_tokens, temperature = _options(payload, handler)
        schema = _load_schema()

        model_obj = _generate(
            handler,
            request_id,
            messages,
            max_tokens,
            temperature,
            _model_schema(schema),
            strict_retry=False,
        )

        normalized_model, model_output_mode = _normalize_model_output(model_obj)

        envelope = {
            "artifact_type": "yara",
            "schema_version": "1",
            **normalized_model,
        }

        _validate_schema(envelope, schema)

        generation_attempts = 1
        try:
            baseline = _validate_baseline(envelope["content"])
        except YaraRouteError as exc:
            if not _retryable_zero_rule_failure(exc):
                raise

            # One bounded repair retry for the prompt-sensitive case observed
            # observed in quality testing: model JSON can be valid while content contains zero
            # parsable YARA rules. The retry changes only the format guardrail.
            model_obj = _generate(
                handler,
                request_id,
                messages,
                max_tokens,
                temperature,
                _model_schema(schema),
                strict_retry=True,
            )
            normalized_model, model_output_mode = _normalize_model_output(model_obj)
            envelope = {
                "artifact_type": "yara",
                "schema_version": "1",
                **normalized_model,
            }
            _validate_schema(envelope, schema)
            baseline = _validate_baseline(envelope["content"])
            generation_attempts = 2

        response: dict[str, Any] = {
            "valid": True,
            "artifact_type": "yara",
            "schema_version": "1",
            "content": envelope["content"],
            "request_id": request_id,
            "validation": {
                "json_schema": True,
                "yara_baseline": True,
                "validation_level": baseline.get("validation_level", "baseline_not_compiler"),
                "validator_version": baseline.get("validator_version"),
                "compiler_equivalent": False,
                "yara_compiler": "not_available",
                "model_output_mode": model_output_mode,
                "generation_attempts": generation_attempts,
            },
        }
        if "summary" in envelope:
            response["summary"] = envelope["summary"]

        handler._send_json(200, request_id, response)

    except YaraRouteError as exc:
        _error(handler, request_id, exc)
