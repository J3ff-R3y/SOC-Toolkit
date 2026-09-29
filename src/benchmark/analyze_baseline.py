#!/usr/bin/env python3
"""
Jeffrey Toolkit — baseline current-model baseline analyzer.

Consumes one benchmark runner benchmark run directory and produces a factual performance
summary. It does not grade semantic answer quality; that belongs to quality evaluation.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
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


class AnalyzeError(Exception):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AnalyzeError(f"could not parse {path}") from exc


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise AnalyzeError(f"non-object row in {path}")
                rows.append(obj)
    except AnalyzeError:
        raise
    except Exception as exc:
        raise AnalyzeError(f"could not parse {path}") from exc
    return rows


def pct(v: float) -> str:
    return f"{v * 100.0:.1f}%"


def cv(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    mean = statistics.mean(values)
    if mean == 0:
        return None
    return statistics.pstdev(values) / mean


def median_or_none(values: list[float]) -> float | None:
    return round(statistics.median(values), 3) if values else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--runtime-before", type=Path, required=True)
    ap.add_argument("--runtime-after", type=Path, required=True)
    args = ap.parse_args()

    run_dir = args.run_dir
    summary = load_json(run_dir / "summary.json")
    metadata = load_json(run_dir / "metadata.json")
    rows = load_jsonl(run_dir / "runs.jsonl")
    before = load_json(args.runtime_before)
    after = load_json(args.runtime_after)

    if summary.get("mode") != "baseline":
        raise AnalyzeError("run is not labelled baseline")
    if metadata.get("corpus_version") != "baseline-v1":
        raise AnalyzeError("unexpected corpus version")
    if metadata.get("repeats") != 3:
        raise AnalyzeError("baseline expects exactly 3 measured repeats")
    if metadata.get("warmups") != 1:
        raise AnalyzeError("baseline expects exactly 1 warmup")
    if metadata.get("workloads") != EXPECTED:
        raise AnalyzeError("baseline workload order/set mismatch")

    expected_total = len(EXPECTED) * 4
    expected_measured = len(EXPECTED) * 3

    if len(rows) != expected_total:
        raise AnalyzeError(
            f"raw row count mismatch: expected {expected_total}, got {len(rows)}"
        )

    measured = [r for r in rows if not r.get("warmup")]
    warmups = [r for r in rows if r.get("warmup")]

    if len(measured) != expected_measured:
        raise AnalyzeError(
            f"measured row count mismatch: expected {expected_measured}, got {len(measured)}"
        )
    if len(warmups) != len(EXPECTED):
        raise AnalyzeError("warmup row count mismatch")

    all_http_200 = all(r.get("http_status") == 200 for r in rows)
    all_success = all(r.get("success") is True for r in rows)

    groups: dict[str, list[dict[str, Any]]] = {x: [] for x in EXPECTED}
    for row in measured:
        wid = row.get("workload_id")
        if wid not in groups:
            raise AnalyzeError(f"unexpected workload in raw rows: {wid}")
        groups[wid].append(row)

    workload_stats: dict[str, Any] = {}
    throughput_available = False

    for wid in EXPECTED:
        wr = groups[wid]
        if len(wr) != 3:
            raise AnalyzeError(f"{wid}: expected 3 measured rows, got {len(wr)}")

        walls = [float(r["wall_ms"]) for r in wr]
        ttft = [
            float(r["ttft_ms"])
            for r in wr
            if isinstance(r.get("ttft_ms"), (int, float))
        ]
        toks = [
            float(r["tokens_per_second_wall"])
            for r in wr
            if isinstance(r.get("tokens_per_second_wall"), (int, float))
        ]
        if toks:
            throughput_available = True

        workload_stats[wid] = {
            "runs": len(wr),
            "successes": sum(1 for r in wr if r.get("success") is True),
            "wall_ms": {
                "median": round(statistics.median(walls), 3),
                "min": round(min(walls), 3),
                "max": round(max(walls), 3),
                "cv": round(cv(walls), 4) if cv(walls) is not None else None,
            },
            # The benchmark runner runner field is named ttft_ms, but it is measured at the
            # first non-[DONE] SSE data event. Report it precisely as first-data.
            "stream_first_data_ms_median": median_or_none(ttft),
            "tokens_per_second_wall_median": median_or_none(toks),
            "completion_token_usage_available_runs": sum(
                1 for r in wr if isinstance(r.get("completion_tokens"), int)
            ),
        }

    runtime_stable = (
        before.get("pid") == after.get("pid")
        and before.get("binary") == after.get("binary")
        and before.get("model_path") == after.get("model_path")
        and before.get("argv_sha256") == after.get("argv_sha256")
    )

    out = {
        "analysis_version": "baseline-analysis-v1",
        "run_dir": str(run_dir),
        "corpus_version": metadata["corpus_version"],
        "expected_workloads": EXPECTED,
        "warmup_runs": len(warmups),
        "measured_runs": len(measured),
        "all_runs_http_200": all_http_200,
        "all_runs_success": all_success,
        "runtime_stable_during_baseline": runtime_stable,
        "runtime_before": before,
        "runtime_after": after,
        "completion_token_throughput_available": throughput_available,
        "timing_note": (
            "stream_first_data_ms is the first non-[DONE] SSE data event; "
            "it is an approximation of time-to-first-token and is not claimed "
            "as first-content-token latency"
        ),
        "quality_scope": (
            "HTTP/validator success is measured here; semantic response quality "
            "is intentionally deferred to quality evaluation"
        ),
        "workloads": workload_stats,
    }

    args.output.write_text(
        json.dumps(out, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AnalyzeError as exc:
        print(json.dumps({
            "valid": False,
            "error": "analysis_error",
            "message": str(exc),
        }, sort_keys=True))
        raise SystemExit(1)
