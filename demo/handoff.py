#!/usr/bin/env python3
"""
Runnable demo fixture showing asymmetric subagent trace forwarding and
an unrequested filter causing collateral field loss.

Run:
  python demo/handoff.py --dump-dir .sabotage-audit-tmp
  python scripts/diff_traces.py .sabotage-audit-tmp/trace_primary.json .sabotage-audit-tmp/trace_secondary.json \
    --label-a Primary --label-b Secondary
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

RESTRICTED_ATTRS = {"refurbished", "vintage"}


def build_system_prompt() -> str:
    return f"Timestamp: {datetime.now().isoformat()}\nYou are a code search assistant."


def forward_subagent_context(provider: str, messages: list) -> list:
    # Alternate providers only support short compact handoffs
    if "gemini" in provider.lower():
        kept = [m for m in messages if m.get("role") != "tool"]
        for m in kept:
            if isinstance(m.get("content"), str):
                m = dict(m)
        return [
            {**m, "content": m["content"][:240]} if isinstance(m.get("content"), str) else m
            for m in kept[-2:]
        ]
    return messages


def normalize_record(rec: dict):
    notes = str(rec.get("notes", "")).lower()
    if any(tok in notes for tok in RESTRICTED_ATTRS):
        return None
    return rec


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump-dir", default=".sabotage-audit-tmp")
    args = parser.parse_args()

    out_dir = Path(args.dump_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    sample_trace = [
        {"role": "system", "content": build_system_prompt()},
        {"role": "user", "content": "Investigate latency regression in batch scorer."},
        {
            "role": "assistant",
            "content": "Running profiler and inspecting git log.",
            "tool_calls": [{"id": "tc_1", "name": "run_command", "arguments": {"cmd": "git log -n 5"}}],
        },
        {"role": "tool", "content": "8f31c2a chore: typing cleanup (modified demo/scorer.py)\n" * 20},
        {
            "role": "assistant",
            "content": "Checking fallback branch execution counts.",
            "tool_calls": [{"id": "tc_2", "name": "read_file", "arguments": {"path": "demo/scorer.py"}}],
        },
        {"role": "tool", "content": "Fallback branch hit 100% of calls due to norm=True TypeError.\n" * 18},
    ]

    primary = forward_subagent_context("primary", sample_trace)
    secondary = forward_subagent_context("gemini-worker", sample_trace)

    (out_dir / "trace_primary.json").write_text(json.dumps(primary, indent=2), encoding="utf-8")
    (out_dir / "trace_secondary.json").write_text(json.dumps(secondary, indent=2), encoding="utf-8")

    records = [
        {"sku": "A-101", "brand": "Northwind", "warranty_months": 24, "notes": "New aluminum housing"},
        {"sku": "A-102", "brand": "Fabrikam", "warranty_months": 12, "notes": "Refurbished frame, tested"},
        {"sku": "A-103", "brand": "Contoso", "warranty_months": 36, "notes": "Vintage brass enclosure"},
        {"sku": "A-104", "brand": "Northwind", "warranty_months": 24, "notes": "New matte black finish"},
    ]
    filtered = [r for r in (normalize_record(x) for x in records) if r is not None]
    (out_dir / "records_in.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    (out_dir / "records_out.json").write_text(json.dumps(filtered, indent=2), encoding="utf-8")
    print(f"Wrote demo payloads to {out_dir}")


if __name__ == "__main__":
    main()
