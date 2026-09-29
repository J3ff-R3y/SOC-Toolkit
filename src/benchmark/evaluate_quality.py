#!/usr/bin/env python3
"""
Jeffrey Toolkit — quality gate deterministic quality/acceptance evaluator.

Consumes the already captured baseline analysis benchmark evidence. No model request is
performed here.

This evaluator intentionally separates:
- transport/validator reliability;
- prompt-specific deterministic semantic checks;
- human review for SOC reasoning quality.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

EXPECTED = [
    "short_chat",
    "soc_reasoning",
    "sigma_generation",
    "yara_generation",
    "suricata_generation",
    "zeek_generation",
]


class EvalError(Exception):
    pass


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise EvalError("non-object JSONL row")
            rows.append(obj)
    return rows


def extract_content(response_text: str) -> str:
    """
    Structured endpoints usually return a JSON envelope. Extract a useful
    content string conservatively. If no known content string exists, return
    the full response text.
    """
    try:
        obj = json.loads(response_text)
    except Exception:
        return response_text

    def walk(v: Any) -> str | None:
        if isinstance(v, dict):
            # Prefer exact artifact content fields.
            for key in ("content", "rule", "script", "yaml", "text"):
                value = v.get(key)
                if isinstance(value, str) and value.strip():
                    return value

            for key in ("artifact", "result", "data", "output"):
                if key in v:
                    found = walk(v[key])
                    if found:
                        return found

            # Fall back to recursive search, but avoid error messages.
            for key, value in v.items():
                if key in {"error", "message", "details", "summary"}:
                    continue
                found = walk(value)
                if found:
                    return found

        elif isinstance(v, list):
            for value in v:
                found = walk(value)
                if found:
                    return found
        return None

    found = walk(obj)
    return found if found is not None else response_text


def contains_all(text: str, needles: list[str]) -> tuple[bool, list[str]]:
    low = text.lower()
    missing = [n for n in needles if n.lower() not in low]
    return (not missing, missing)


def measured_by_workload(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out = {x: [] for x in EXPECTED}
    for row in rows:
        if row.get("warmup") is True:
            continue
        wid = row.get("workload_id")
        if wid not in out:
            raise EvalError(f"unexpected workload: {wid}")
        out[wid].append(row)

    for wid in EXPECTED:
        if len(out[wid]) != 3:
            raise EvalError(f"{wid}: expected 3 measured rows, got {len(out[wid])}")
    return out


def result_item(passed: bool, details: dict[str, Any]) -> dict[str, Any]:
    return {"pass": passed, **details}


def evaluate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    groups = measured_by_workload(rows)
    gates: dict[str, Any] = {}

    # short_chat: prompt explicitly requires exact output.
    short_results = []
    for row in groups["short_chat"]:
        text = (row.get("response_text") or "").strip()
        ok = row.get("http_status") == 200 and text == "benchmark-ok"
        short_results.append({
            "request_id": row.get("request_id"),
            "http_status": row.get("http_status"),
            "text": text,
            "pass": ok,
        })
    gates["short_chat"] = result_item(
        all(x["pass"] for x in short_results),
        {
            "required": "3/3 HTTP 200 and exact text benchmark-ok",
            "runs": short_results,
        },
    )

    # SOC reasoning: require transport success; semantic quality remains human
    # reviewed because keyword scoring would overclaim reasoning quality.
    soc_runs = []
    for row in groups["soc_reasoning"]:
        soc_runs.append({
            "request_id": row.get("request_id"),
            "http_status": row.get("http_status"),
            "response_text": row.get("response_text") or "",
            "transport_pass": row.get("http_status") == 200,
        })
    gates["soc_reasoning_transport"] = result_item(
        all(x["transport_pass"] for x in soc_runs),
        {
            "required": "3/3 HTTP 200",
            "runs": soc_runs,
        },
    )

    # Sigma prompt-specific semantics.
    sigma_runs = []
    sigma_needles = [
        "4688",
        "powershell.exe",
        "-enc",
        "status: test",
        "level: medium",
        "product: windows",
        "service: security",
        "selection",
        "condition",
    ]
    for row in groups["sigma_generation"]:
        content = extract_content(row.get("response_text") or "")
        sem_ok, missing = contains_all(content, sigma_needles)
        ok = row.get("http_status") == 200 and sem_ok
        sigma_runs.append({
            "request_id": row.get("request_id"),
            "http_status": row.get("http_status"),
            "missing": missing,
            "pass": ok,
        })
    gates["sigma_generation"] = result_item(
        all(x["pass"] for x in sigma_runs),
        {
            "required": "3/3 validator success + requested benchmark semantics",
            "runs": sigma_runs,
        },
    )

    # YARA: the existing endpoint validator is authoritative for structural
    # acceptance. baseline analysis already showed 0/3; preserve that as a hard gate.
    yara_runs = []
    for row in groups["yara_generation"]:
        ok = row.get("http_status") == 200
        yara_runs.append({
            "request_id": row.get("request_id"),
            "http_status": row.get("http_status"),
            "pass": ok,
            "response_text": row.get("response_text") or "",
        })
    gates["yara_generation"] = result_item(
        all(x["pass"] for x in yara_runs),
        {
            "required": "3/3 HTTP 200 from model -> schema -> YARA baseline validator",
            "runs": yara_runs,
        },
    )

    # Suricata prompt-specific semantics.
    suri_runs = []
    suri_needles = [
        "alert tcp",
        "$home_net",
        "$external_net",
        "powershell.exe",
        "-enc",
        "sid:1000700",
        "rev:1",
    ]
    for row in groups["suricata_generation"]:
        content = extract_content(row.get("response_text") or "")
        sem_ok, missing = contains_all(content, suri_needles)
        ok = row.get("http_status") == 200 and sem_ok
        suri_runs.append({
            "request_id": row.get("request_id"),
            "http_status": row.get("http_status"),
            "missing": missing,
            "pass": ok,
        })
    gates["suricata_generation"] = result_item(
        all(x["pass"] for x in suri_runs),
        {
            "required": "3/3 validator success + requested benchmark semantics",
            "runs": suri_runs,
        },
    )

    # Zeek prompt-specific semantics.
    zeek_runs = []
    zeek_needles = [
        "module jeffreybenchmark",
        "event zeek_init",
        "jeffrey f7 benchmark",
    ]
    forbidden = ["@load", "redef ", "export {"]
    for row in groups["zeek_generation"]:
        content = extract_content(row.get("response_text") or "")
        sem_ok, missing = contains_all(content, zeek_needles)
        low = content.lower()
        present_forbidden = [x for x in forbidden if x in low]
        ok = row.get("http_status") == 200 and sem_ok and not present_forbidden
        zeek_runs.append({
            "request_id": row.get("request_id"),
            "http_status": row.get("http_status"),
            "missing": missing,
            "forbidden_present": present_forbidden,
            "pass": ok,
        })
    gates["zeek_generation"] = result_item(
        all(x["pass"] for x in zeek_runs),
        {
            "required": "3/3 validator success + requested benchmark semantics",
            "runs": zeek_runs,
        },
    )

    hard_gate_names = [
        "short_chat",
        "soc_reasoning_transport",
        "sigma_generation",
        "yara_generation",
        "suricata_generation",
        "zeek_generation",
    ]
    hard_pass = all(gates[x]["pass"] for x in hard_gate_names)

    return {
        "evaluation_version": "quality-gate-v1",
        "hard_gate_pass": hard_pass,
        "manual_soc_review_required": True,
        "gates": gates,
        "acceptance_policy": {
            "short_chat": "3/3 exact",
            "soc_reasoning_transport": "3/3 HTTP 200",
            "sigma_generation": "3/3 validator + prompt semantics",
            "yara_generation": "3/3 validator success",
            "suricata_generation": "3/3 validator + prompt semantics",
            "zeek_generation": "3/3 validator + prompt semantics",
            "soc_reasoning_semantic": "manual review of all 3 saved responses",
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--soc-review", type=Path, required=True)
    args = ap.parse_args()

    rows = load_jsonl(args.runs)
    result = evaluate(rows)

    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    soc = result["gates"]["soc_reasoning_transport"]["runs"]
    lines = [
        "# quality gate — SOC reasoning manual review",
        "",
        "Review only the three saved synthetic benchmark responses below.",
        "",
        "Prompt intent:",
        "",
        "- infer the likely attack path from encoded PowerShell -> new external IP -> scheduled task;",
        "- give two important follow-up actions;",
        "- give one plausible false-positive possibility;",
        "- maximum four short bullets; no introduction.",
        "",
        "Mark PASS only when all three responses are materially useful and satisfy the requested structure.",
        "",
    ]

    for i, run in enumerate(soc, 1):
        lines += [
            f"## Response {i}",
            "",
            f"Request ID: `{run['request_id']}`",
            "",
            "```text",
            run["response_text"],
            "```",
            "",
            "- [ ] likely attack path is coherent",
            "- [ ] two useful follow-up actions are present",
            "- [ ] one plausible false-positive possibility is present",
            "- [ ] maximum four short bullets / no unnecessary introduction",
            "",
        ]

    args.soc_review.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({
        "valid": True,
        "hard_gate_pass": result["hard_gate_pass"],
        "manual_soc_review_required": True,
        "failed_hard_gates": [
            name for name, value in result["gates"].items()
            if not value["pass"]
        ],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvalError as exc:
        print(json.dumps({
            "valid": False,
            "error": "evaluation_error",
            "message": str(exc),
        }, sort_keys=True))
        raise SystemExit(1)
