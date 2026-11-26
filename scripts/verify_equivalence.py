#!/usr/bin/env python3
"""
verify_equivalence.py: Controlled A/B benchmark and output-equivalence receipt
runner for sabotage-audit.

Runs a baseline command vs. a clean candidate command with warmup and alternating
trials, computes robust timing stats (median, IQR, p95, speedup ratio), and checks
output parity via SHA-256 bit-exactness, canonical JSON equality, or float
tolerances.

Python 3.8+ standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shlex
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


def percentile(sorted_vals: Sequence[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    return sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f)


def summarize_ms(samples_ms: Sequence[float]) -> Dict[str, float]:
    s = sorted(samples_ms)
    med = statistics.median(s)
    q1 = percentile(s, 0.25)
    q3 = percentile(s, 0.75)
    iqr = q3 - q1
    return {
        "n": len(s),
        "min_ms": round(s[0], 4),
        "median_ms": round(med, 4),
        "mean_ms": round(statistics.fmean(s), 4),
        "p95_ms": round(percentile(s, 0.95), 4),
        "iqr_ms": round(iqr, 4),
        "cv_iqr": round(iqr / med, 4) if med > 0 else 0.0,
    }


def run_once(cmd: str, cwd: Optional[str], timeout: float) -> Tuple[float, bytes, bytes, int]:
    t0 = time.perf_counter_ns()
    proc = subprocess.run(
        cmd,
        shell=True,
        cwd=cwd,
        capture_output=True,
        timeout=timeout,
    )
    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    return elapsed_ms, proc.stdout, proc.stderr, proc.returncode


def flatten_floats(obj: Any, prefix: str = "") -> List[Tuple[str, float]]:
    out: List[Tuple[str, float]] = []
    if isinstance(obj, bool):
        return out
    if isinstance(obj, (int, float)):
        out.append((prefix or "$", float(obj)))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            out.extend(flatten_floats(item, f"{prefix}[{i}]"))
    elif isinstance(obj, dict):
        for k in sorted(obj.keys()):
            out.extend(flatten_floats(obj[k], f"{prefix}.{k}" if prefix else str(k)))
    return out


def verify_outputs(
    base_bytes: bytes,
    cand_bytes: bytes,
    mode: str,
    atol: float,
    rtol: float,
) -> Dict[str, Any]:
    base_sha = hashlib.sha256(base_bytes).hexdigest()
    cand_sha = hashlib.sha256(cand_bytes).hexdigest()
    result: Dict[str, Any] = {
        "mode": mode,
        "baseline_sha256": base_sha,
        "candidate_sha256": cand_sha,
        "bit_exact": base_sha == cand_sha,
    }

    if mode == "exact":
        result["passed"] = base_sha == cand_sha
        return result

    if mode == "json":
        try:
            a = json.loads(base_bytes.decode("utf-8"))
            b = json.loads(cand_bytes.decode("utf-8"))
            ca = json.dumps(a, sort_keys=True, separators=(",", ":"))
            cb = json.dumps(b, sort_keys=True, separators=(",", ":"))
            result["canonical_json_equal"] = ca == cb
            result["passed"] = ca == cb
        except Exception as exc:
            result["passed"] = False
            result["error"] = f"JSON parse failed: {exc}"
        return result

    if mode == "float":
        try:
            a = json.loads(base_bytes.decode("utf-8"))
            b = json.loads(cand_bytes.decode("utf-8"))
            fa = flatten_floats(a)
            fb = flatten_floats(b)
            if len(fa) != len(fb) or [k for k, _ in fa] != [k for k, _ in fb]:
                result["passed"] = False
                result["error"] = f"Numeric structure mismatch ({len(fa)} vs {len(fb)} elements)"
                return result
            if not fa:
                result["passed"] = False
                result["error"] = "No numeric values found in JSON output"
                return result
            abs_diffs: List[float] = []
            rel_diffs: List[float] = []
            all_close = True
            for (_, va), (_, vb) in zip(fa, fb):
                if math.isnan(va) or math.isnan(vb):
                    all_close = False
                    abs_diffs.append(float("inf"))
                    rel_diffs.append(float("inf"))
                    continue
                ad = abs(va - vb)
                rd = ad / max(abs(va), abs(vb), 1e-12)
                abs_diffs.append(ad)
                rel_diffs.append(rd)
                if ad > (atol + rtol * abs(va)):
                    all_close = False
            result["elements_compared"] = len(fa)
            result["atol"] = atol
            result["rtol"] = rtol
            result["max_abs_diff"] = max(abs_diffs)
            result["mean_abs_diff"] = statistics.fmean(abs_diffs)
            result["max_rel_diff"] = max(rel_diffs)
            result["passed"] = all_close
        except Exception as exc:
            result["passed"] = False
            result["error"] = f"Float JSON verification failed: {exc}"
        return result

    result["passed"] = False
    result["error"] = f"Unknown mode: {mode}"
    return result


def get_git_head(cwd: Optional[str]) -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return proc.stdout.strip() if proc.returncode == 0 else "N/A"
    except (OSError, subprocess.SubprocessError):
        return "N/A"


def render_receipt_md(receipt: Dict[str, Any]) -> str:
    b = receipt["baseline_stats"]
    c = receipt["candidate_stats"]
    eq = receipt["equivalence"]
    sp = receipt["comparison"]
    status = "PASS" if eq["passed"] else "FAIL"
    lines = [
        "### A/B Benchmark & Equivalence Receipt",
        "",
        f"- **UTC Timestamp:** `{receipt['utc_timestamp']}`",
        f"- **Git HEAD:** `{receipt['environment']['git_head']}`",
        f"- **Environment:** `{receipt['environment']['platform']}` | Python `{receipt['environment']['python']}` | CPUs: `{receipt['environment']['cpu_count']}`",
        f"- **Warmup / Trials:** `{receipt['warmup']}` warmup, `{receipt['runs']}` alternating measured pairs",
        "",
        "| Variant | Median (ms) | Mean (ms) | IQR (ms) | P95 (ms) | Min (ms) |",
        "| :--- | ---: | ---: | ---: | ---: | ---: |",
        f"| Baseline | {b['median_ms']:.4f} | {b['mean_ms']:.4f} | {b['iqr_ms']:.4f} | {b['p95_ms']:.4f} | {b['min_ms']:.4f} |",
        f"| Clean Candidate | {c['median_ms']:.4f} | {c['mean_ms']:.4f} | {c['iqr_ms']:.4f} | {c['p95_ms']:.4f} | {c['min_ms']:.4f} |",
        "",
        f"- **Speedup (median):** `{sp['speedup_x']:.3f}x` (`{sp['latency_reduction_pct']:.2f}%` latency reduction)",
        f"- **Noise warning (`IQR/median > 0.15`):** `{sp['noisy_warning']}`",
        f"- **Equivalence (`{eq['mode']}`):** `{status}` (bit-exact: `{eq['bit_exact']}`)",
        f"  - Baseline SHA-256:  `{eq['baseline_sha256']}`",
        f"  - Candidate SHA-256: `{eq['candidate_sha256']}`",
    ]
    if eq["mode"] == "float" and "max_abs_diff" in eq:
        lines.append(
            f"  - Float Diff: `max_abs_diff={eq['max_abs_diff']:.3e}`, "
            f"`max_rel_diff={eq['max_rel_diff']:.3e}` (atol={eq['atol']}, rtol={eq['rtol']})"
        )
    if "error" in eq:
        lines.append(f"  - Error: `{eq['error']}`")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run controlled A/B benchmark and output-equivalence verification."
    )
    parser.add_argument("--baseline", required=True, help="Shell command for baseline (current) path")
    parser.add_argument("--candidate", required=True, help="Shell command for clean candidate path")
    parser.add_argument("--warmup", type=int, default=3, help="Warmup runs per variant (default: 3)")
    parser.add_argument("--runs", type=int, default=10, help="Measured runs per variant (default: 10)")
    parser.add_argument(
        "--mode",
        choices=["exact", "json", "float"],
        default="exact",
        help="Output equivalence check mode (default: exact SHA-256)",
    )
    parser.add_argument("--atol", type=float, default=1e-5, help="Absolute tolerance for float mode")
    parser.add_argument("--rtol", type=float, default=1e-4, help="Relative tolerance for float mode")
    parser.add_argument("--cwd", default=None, help="Working directory for both commands")
    parser.add_argument("--timeout", type=float, default=300.0, help="Per-run timeout in seconds")
    parser.add_argument("--json-out", help="Write full JSON receipt to path")
    parser.add_argument("--md-out", help="Write Markdown receipt to path")
    args = parser.parse_args(argv)

    # Warmup
    for _ in range(max(0, args.warmup)):
        _, _, berr, brc = run_once(args.baseline, args.cwd, args.timeout)
        if brc != 0:
            print(f"Baseline warmup failed (rc={brc}): {berr.decode('utf-8', 'replace')}", file=sys.stderr)
            return 1
        _, _, cerr, crc = run_once(args.candidate, args.cwd, args.timeout)
        if crc != 0:
            print(f"Candidate warmup failed (rc={crc}): {cerr.decode('utf-8', 'replace')}", file=sys.stderr)
            return 1

    base_times: List[float] = []
    cand_times: List[float] = []
    base_out: Optional[bytes] = None
    cand_out: Optional[bytes] = None

    # Alternating order (AB, BA, AB, BA...) reduces thermal/background drift bias
    for i in range(max(1, args.runs)):
        if i % 2 == 0:
            bt, bout, berr, brc = run_once(args.baseline, args.cwd, args.timeout)
            ct, cout, cerr, crc = run_once(args.candidate, args.cwd, args.timeout)
        else:
            ct, cout, cerr, crc = run_once(args.candidate, args.cwd, args.timeout)
            bt, bout, berr, brc = run_once(args.baseline, args.cwd, args.timeout)

        if brc != 0:
            print(f"Baseline run {i} failed (rc={brc}): {berr.decode('utf-8', 'replace')}", file=sys.stderr)
            return 1
        if crc != 0:
            print(f"Candidate run {i} failed (rc={crc}): {cerr.decode('utf-8', 'replace')}", file=sys.stderr)
            return 1

        base_times.append(bt)
        cand_times.append(ct)
        if base_out is None:
            base_out = bout
            cand_out = cout

    assert base_out is not None and cand_out is not None
    b_stats = summarize_ms(base_times)
    c_stats = summarize_ms(cand_times)
    eq = verify_outputs(base_out, cand_out, args.mode, args.atol, args.rtol)

    speedup = (b_stats["median_ms"] / c_stats["median_ms"]) if c_stats["median_ms"] > 0 else 0.0
    reduction = ((b_stats["median_ms"] - c_stats["median_ms"]) / b_stats["median_ms"] * 100.0) if b_stats["median_ms"] > 0 else 0.0

    receipt: Dict[str, Any] = {
        "tool": "sabotage-audit/verify_equivalence.py",
        "utc_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
            "git_head": get_git_head(args.cwd),
        },
        "commands": {
            "baseline": args.baseline,
            "candidate": args.candidate,
        },
        "warmup": args.warmup,
        "runs": args.runs,
        "baseline_stats": b_stats,
        "candidate_stats": c_stats,
        "comparison": {
            "speedup_x": round(speedup, 4),
            "latency_reduction_pct": round(reduction, 2),
            "noisy_warning": (b_stats["cv_iqr"] > 0.15) or (c_stats["cv_iqr"] > 0.15),
        },
        "equivalence": eq,
    }

    md = render_receipt_md(receipt)
    if args.json_out:
        p = Path(args.json_out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    if args.md_out:
        p = Path(args.md_out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(md, encoding="utf-8")

    print(md)
    return 0 if eq["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
