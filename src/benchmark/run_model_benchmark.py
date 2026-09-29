#!/usr/bin/env python3
"""
Jeffrey Toolkit — benchmark reproducible benchmark harness v1.

Properties:
- local loopback HTTP only;
- interactive password input; credentials/session token are never written;
- fixed corpus + fixed sampling parameters;
- warmups and measured runs recorded separately;
- raw per-run JSON evidence + summary JSON;
- no production configuration change;
- no model switch/restart;
- no internet access.

benchmark uses --smoke to verify the harness. baseline analysis will perform the actual
multi-workload baseline.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import http.client
import ipaddress
import json
import os
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

RUNNER_VERSION = "benchmark-harness-v1"

DEFAULT_CORPUS = Path("/opt/jeffrey-benchmark/corpus/baseline-v1.json")
DEFAULT_RESULTS = Path("/var/lib/jeffrey-benchmark/results")
DEFAULT_BASE_URL = "http://127.0.0.1:8080"

ALLOWED_KINDS = {"stream_chat", "structured"}
ALLOWED_ROUTES = {
    "/api/chat",
    "/api/structured/sigma",
    "/api/structured/yara",
    "/api/structured/suricata",
    "/api/structured/zeek",
}


class BenchError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_base_url(url: str) -> tuple[str, int]:
    p = urlparse(url)
    if p.scheme != "http":
        raise BenchError("benchmark base URL must use http for current local compatibility mode")
    if not p.hostname or not is_loopback_host(p.hostname):
        raise BenchError("benchmark base URL must resolve syntactically to localhost/loopback only")
    if p.path not in ("", "/") or p.query or p.fragment or p.username or p.password:
        raise BenchError("benchmark base URL must contain only scheme/host/port")
    return p.hostname, p.port or 80


def load_corpus(path: Path) -> dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise BenchError(f"could not load corpus: {path}") from exc

    if not isinstance(obj, dict):
        raise BenchError("corpus root must be an object")

    if obj.get("corpus_version") != "baseline-v1":
        raise BenchError("unsupported corpus version")

    defaults = obj.get("defaults")
    if not isinstance(defaults, dict):
        raise BenchError("corpus defaults missing")

    workloads = obj.get("workloads")
    if not isinstance(workloads, list) or not workloads:
        raise BenchError("corpus workloads missing")

    seen: set[str] = set()

    for item in workloads:
        if not isinstance(item, dict):
            raise BenchError("workload must be an object")

        wid = item.get("id")
        if not isinstance(wid, str) or not wid:
            raise BenchError("workload id missing")
        if wid in seen:
            raise BenchError(f"duplicate workload id: {wid}")
        seen.add(wid)

        if item.get("kind") not in ALLOWED_KINDS:
            raise BenchError(f"unsupported workload kind: {wid}")

        if item.get("route") not in ALLOWED_ROUTES:
            raise BenchError(f"route not allowlisted: {wid}")

        if item["kind"] == "stream_chat" and item["route"] != "/api/chat":
            raise BenchError(f"stream_chat route mismatch: {wid}")

        if item["kind"] == "structured" and item["route"] == "/api/chat":
            raise BenchError(f"structured workload route mismatch: {wid}")

        max_tokens = item.get("max_tokens")
        if not isinstance(max_tokens, int) or max_tokens < 1 or max_tokens > 8192:
            raise BenchError(f"invalid max_tokens: {wid}")

        messages = item.get("messages")
        if not isinstance(messages, list) or not messages:
            raise BenchError(f"messages missing: {wid}")

        for message in messages:
            if not isinstance(message, dict):
                raise BenchError(f"invalid message: {wid}")
            if set(message) != {"role", "content"}:
                raise BenchError(f"message keys must be role/content only: {wid}")
            if message["role"] not in {"system", "user", "assistant"}:
                raise BenchError(f"invalid role: {wid}")
            if not isinstance(message["content"], str) or not message["content"]:
                raise BenchError(f"invalid message content: {wid}")

    return obj


def conn_for(host: str, port: int, timeout: float) -> http.client.HTTPConnection:
    return http.client.HTTPConnection(host, port, timeout=timeout)


def json_request(
    host: str,
    port: int,
    path: str,
    body: dict[str, Any],
    headers: dict[str, str] | None,
    timeout: float,
) -> tuple[int, dict[str, str], bytes, float]:
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    request_headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(raw)),
        "Connection": "close",
    }
    if headers:
        request_headers.update(headers)

    conn = conn_for(host, port, timeout)
    started = time.perf_counter()
    try:
        conn.request("POST", path, body=raw, headers=request_headers)
        resp = conn.getresponse()
        payload = resp.read()
        wall_ms = (time.perf_counter() - started) * 1000.0
        return (
            resp.status,
            {k.lower(): v for k, v in resp.getheaders()},
            payload,
            wall_ms,
        )
    finally:
        conn.close()


def login(host: str, port: int, username: str, password: str, timeout: float) -> str:
    status, _, body, _ = json_request(
        host,
        port,
        "/api/login",
        {"username": username, "password": password},
        None,
        timeout,
    )
    if status != 200:
        raise BenchError(f"login failed HTTP={status}")

    try:
        obj = json.loads(body)
    except json.JSONDecodeError as exc:
        raise BenchError("login did not return JSON") from exc

    token = obj.get("session_token")
    if not isinstance(token, str) or not token:
        raise BenchError("login did not return session_token")
    return token


def logout(host: str, port: int, token: str, timeout: float) -> None:
    conn = conn_for(host, port, timeout)
    try:
        conn.request(
            "POST",
            "/api/logout",
            body=b"",
            headers={
                "X-Jeffrey-Session": token,
                "Content-Length": "0",
                "Connection": "close",
            },
        )
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()


def extract_usage(obj: Any) -> int | None:
    if isinstance(obj, dict):
        usage = obj.get("usage")
        if isinstance(usage, dict):
            value = usage.get("completion_tokens")
            if isinstance(value, int) and value >= 0:
                return value
    return None


def stream_chat(
    host: str,
    port: int,
    route: str,
    body: dict[str, Any],
    token: str,
    timeout: float,
    request_id: str,
) -> dict[str, Any]:
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    conn = conn_for(host, port, timeout)
    started = time.perf_counter()
    first_data_at: float | None = None
    text_parts: list[str] = []
    completion_tokens: int | None = None
    raw_bytes = 0

    try:
        conn.request(
            "POST",
            route,
            body=raw,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(raw)),
                "X-Jeffrey-Session": token,
                "X-Request-ID": request_id,
                "Connection": "close",
            },
        )

        resp = conn.getresponse()
        status = resp.status
        response_headers = {k.lower(): v for k, v in resp.getheaders()}

        while True:
            line = resp.readline()
            if not line:
                break
            raw_bytes += len(line)

            if not line.startswith(b"data:"):
                continue

            data = line[5:].strip()
            if not data or data == b"[DONE]":
                continue

            if first_data_at is None:
                first_data_at = time.perf_counter()

            try:
                obj = json.loads(data)
            except json.JSONDecodeError:
                continue

            maybe_usage = extract_usage(obj)
            if maybe_usage is not None:
                completion_tokens = maybe_usage

            try:
                choices = obj.get("choices", [])
                if choices:
                    delta = choices[0].get("delta", {})
                    content = delta.get("content")
                    if isinstance(content, str):
                        text_parts.append(content)
            except Exception:
                pass

        finished = time.perf_counter()

    finally:
        conn.close()

    text = "".join(text_parts)
    wall_ms = (finished - started) * 1000.0
    ttft_ms = None
    if first_data_at is not None:
        ttft_ms = (first_data_at - started) * 1000.0

    tok_s = None
    if completion_tokens is not None and wall_ms > 0:
        tok_s = completion_tokens / (wall_ms / 1000.0)

    return {
        "http_status": status,
        "response_headers": {
            "x-request-id": response_headers.get("x-request-id"),
            "content-type": response_headers.get("content-type"),
        },
        "wall_ms": round(wall_ms, 3),
        "ttft_ms": round(ttft_ms, 3) if ttft_ms is not None else None,
        "completion_tokens": completion_tokens,
        "tokens_per_second_wall": round(tok_s, 3) if tok_s is not None else None,
        "response_text": text,
        "response_chars": len(text),
        "raw_response_bytes": raw_bytes,
        "response_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def structured_request(
    host: str,
    port: int,
    route: str,
    body: dict[str, Any],
    token: str,
    timeout: float,
    request_id: str,
) -> dict[str, Any]:
    status, headers, raw, wall_ms = json_request(
        host,
        port,
        route,
        body,
        {
            "X-Jeffrey-Session": token,
            "X-Request-ID": request_id,
        },
        timeout,
    )

    text = raw.decode("utf-8", "replace")
    parsed: Any = None
    completion_tokens: int | None = None
    try:
        parsed = json.loads(text)
        completion_tokens = extract_usage(parsed)
    except json.JSONDecodeError:
        pass

    tok_s = None
    if completion_tokens is not None and wall_ms > 0:
        tok_s = completion_tokens / (wall_ms / 1000.0)

    return {
        "http_status": status,
        "response_headers": {
            "x-request-id": headers.get("x-request-id"),
            "content-type": headers.get("content-type"),
        },
        "wall_ms": round(wall_ms, 3),
        "ttft_ms": None,
        "completion_tokens": completion_tokens,
        "tokens_per_second_wall": round(tok_s, 3) if tok_s is not None else None,
        "response_text": text,
        "response_chars": len(text),
        "raw_response_bytes": len(raw),
        "response_sha256": hashlib.sha256(raw).hexdigest(),
        "response_json_valid": parsed is not None,
    }


def select_workloads(corpus: dict[str, Any], requested: list[str] | None) -> list[dict[str, Any]]:
    workloads = corpus["workloads"]
    if not requested:
        return workloads

    wanted = set(requested)
    by_id = {x["id"]: x for x in workloads}
    missing = sorted(wanted - set(by_id))
    if missing:
        raise BenchError("unknown workload(s): " + ", ".join(missing))
    return [by_id[x] for x in requested]


def summarize(measured: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in measured:
        grouped.setdefault(row["workload_id"], []).append(row)

    workloads: dict[str, Any] = {}

    for wid, rows in grouped.items():
        walls = [float(x["wall_ms"]) for x in rows]
        ttfts = [float(x["ttft_ms"]) for x in rows if x.get("ttft_ms") is not None]
        tok_s = [
            float(x["tokens_per_second_wall"])
            for x in rows
            if x.get("tokens_per_second_wall") is not None
        ]

        workloads[wid] = {
            "runs": len(rows),
            "successes": sum(1 for x in rows if x["success"]),
            "http_200": sum(1 for x in rows if x["http_status"] == 200),
            "wall_ms_median": round(statistics.median(walls), 3),
            "wall_ms_min": round(min(walls), 3),
            "wall_ms_max": round(max(walls), 3),
            "ttft_ms_median": round(statistics.median(ttfts), 3) if ttfts else None,
            "tokens_per_second_wall_median": (
                round(statistics.median(tok_s), 3) if tok_s else None
            ),
        }

    return {
        "measured_runs": len(measured),
        "successful_runs": sum(1 for x in measured if x["success"]),
        "workloads": workloads,
    }


def build_request(workload: dict[str, Any], defaults: dict[str, Any]) -> dict[str, Any]:
    body = {
        "messages": workload["messages"],
        "temperature": defaults.get("temperature", 0),
        "max_tokens": workload["max_tokens"],
    }
    if workload["kind"] == "stream_chat":
        body["stream"] = True
    return body


def run_benchmark(
    host: str,
    port: int,
    corpus: dict[str, Any],
    workloads: list[dict[str, Any]],
    token: str,
    results_dir: Path,
    repeats: int,
    warmups: int,
    timeout: float,
    mode: str,
) -> Path:
    if repeats < 1 or repeats > 20:
        raise BenchError("repeats must be between 1 and 20")
    if warmups < 0 or warmups > 5:
        raise BenchError("warmups must be between 0 and 5")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    run_dir = results_dir / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    os.chmod(run_dir, 0o700)

    metadata = {
        "runner_version": RUNNER_VERSION,
        "corpus_version": corpus["corpus_version"],
        "mode": mode,
        "started_at_utc": utc_now(),
        "base_url": f"http://{host}:{port}",
        "loopback_only": True,
        "repeats": repeats,
        "warmups": warmups,
        "workloads": [w["id"] for w in workloads],
        "credentials_written": False,
        "session_token_written": False,
        "internet_access_performed": False,
        "model_switch_performed": False,
        "service_restart_performed": False,
    }

    (run_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    raw_path = run_dir / "runs.jsonl"
    measured: list[dict[str, Any]] = []

    with raw_path.open("w", encoding="utf-8") as raw_out:
        os.chmod(raw_path, 0o600)

        for workload in workloads:
            total = warmups + repeats
            for idx in range(total):
                warmup = idx < warmups
                iteration = idx + 1 if not warmup else idx + 1
                request_id = f"benchmark-{workload['id']}-{uuid.uuid4().hex[:12]}"
                body = build_request(workload, corpus["defaults"])

                started_at = utc_now()
                if workload["kind"] == "stream_chat":
                    result = stream_chat(
                        host, port, workload["route"], body, token, timeout, request_id
                    )
                else:
                    result = structured_request(
                        host, port, workload["route"], body, token, timeout, request_id
                    )

                row = {
                    "runner_version": RUNNER_VERSION,
                    "corpus_version": corpus["corpus_version"],
                    "workload_id": workload["id"],
                    "kind": workload["kind"],
                    "route": workload["route"],
                    "warmup": warmup,
                    "iteration": iteration,
                    "request_id": request_id,
                    "started_at_utc": started_at,
                    **result,
                }
                row["success"] = row["http_status"] == 200

                raw_out.write(json.dumps(row, sort_keys=True) + "\n")
                raw_out.flush()

                if not warmup:
                    measured.append(row)

    summary = {
        "runner_version": RUNNER_VERSION,
        "corpus_version": corpus["corpus_version"],
        "mode": mode,
        "completed_at_utc": utc_now(),
        "base_url": f"http://{host}:{port}",
        "loopback_only": True,
        "internet_access_performed": False,
        "model_switch_performed": False,
        "service_restart_performed": False,
        **summarize(measured),
    }

    (run_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if any(not x["success"] for x in measured):
        raise BenchError(f"one or more measured benchmark requests failed; evidence: {run_dir}")

    return run_dir


def self_check(corpus_path: Path) -> dict[str, Any]:
    corpus = load_corpus(corpus_path)
    return {
        "valid": True,
        "runner_version": RUNNER_VERSION,
        "corpus_version": corpus["corpus_version"],
        "workload_ids": [x["id"] for x in corpus["workloads"]],
        "allowed_routes": sorted(ALLOWED_ROUTES),
        "loopback_only": True,
        "credentials_written": False,
        "session_token_written": False,
        "model_switch_supported": False,
        "service_restart_supported": False,
        "internet_access_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--username")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--workloads")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--validate-corpus", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()

    try:
        corpus = load_corpus(args.corpus)

        if args.self_check:
            print(json.dumps(self_check(args.corpus), sort_keys=True))
            return 0

        if args.validate_corpus:
            print(json.dumps({
                "valid": True,
                "corpus_version": corpus["corpus_version"],
                "workload_count": len(corpus["workloads"]),
                "workload_ids": [x["id"] for x in corpus["workloads"]],
            }, sort_keys=True))
            return 0

        host, port = parse_base_url(args.base_url)

        if os.geteuid() != 0:
            raise BenchError("benchmark harness must run as root so results remain root-only")

        username = args.username or input("Toolkit username: ").strip()
        if not username:
            raise BenchError("username is required")
        password = getpass.getpass("Password: ")

        token = login(host, port, username, password, args.timeout)
        del password

        try:
            requested = None
            repeats = args.repeats
            warmups = args.warmups
            mode = "baseline"

            if args.smoke:
                requested = ["short_chat"]
                repeats = 1
                warmups = 0
                mode = "smoke_not_baseline"
            elif args.workloads:
                requested = [x.strip() for x in args.workloads.split(",") if x.strip()]

            workloads = select_workloads(corpus, requested)
            args.results_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(args.results_dir, 0o700)

            run_dir = run_benchmark(
                host,
                port,
                corpus,
                workloads,
                token,
                args.results_dir,
                repeats,
                warmups,
                args.timeout,
                mode,
            )
        finally:
            try:
                logout(host, port, token, args.timeout)
            except Exception:
                pass

        print(json.dumps({
            "valid": True,
            "mode": mode,
            "run_dir": str(run_dir),
            "summary": str(run_dir / "summary.json"),
            "raw_runs": str(run_dir / "runs.jsonl"),
        }, sort_keys=True))
        return 0

    except BenchError as exc:
        print(json.dumps({
            "valid": False,
            "error": "benchmark_error",
            "message": str(exc),
            "runner_version": RUNNER_VERSION,
        }, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
