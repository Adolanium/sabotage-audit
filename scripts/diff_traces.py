#!/usr/bin/env python3
"""
diff_traces.py: Zero-dependency payload, subagent-trace, and record-retention
diff tool for sabotage-audit.

Compares two JSON or JSONL payloads (for example: Model A vs. Model B subagent
handoff context, pre- vs. post-compaction history, or input vs. filtered dataset
records) and prints a structured retention receipt proving exact message drops,
tool-trace stripping, truncation, or collateral field loss.

Python 3.8+ standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


def load_json_or_jsonl(path: Path) -> Any:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        rows = []
        for line in raw.splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
        return rows


def extract_messages(data: Any) -> Optional[List[Dict[str, Any]]]:
    if isinstance(data, dict):
        for key in ("messages", "history", "turns", "trace", "traces", "events"):
            val = data.get(key)
            if isinstance(val, list) and all(isinstance(x, dict) for x in val):
                return val
        return None
    if isinstance(data, list) and all(isinstance(x, dict) for x in data):
        if any("role" in x or "content" in x or "tool_calls" in x for x in data):
            return data
    return None


def measure_messages(msgs: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_chars = 0
    tool_messages = 0
    tool_call_blocks = 0
    reasoning_blocks = 0
    roles: Dict[str, int] = {}

    for m in msgs:
        role = str(m.get("role", "unknown")).lower()
        roles[role] = roles.get(role, 0) + 1
        if role in {"tool", "tool_result", "function"}:
            tool_messages += 1
        if m.get("tool_calls"):
            tc = m["tool_calls"]
            tool_call_blocks += len(tc) if isinstance(tc, list) else 1
        if m.get("reasoning") or m.get("thinking"):
            reasoning_blocks += 1

        content = m.get("content", "")
        if isinstance(content, str):
            total_chars += len(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict):
                    ptype = str(part.get("type", "")).lower()
                    if ptype in {"tool_use", "tool_call"}:
                        tool_call_blocks += 1
                    elif ptype in {"tool_result", "function_response"}:
                        tool_messages += 1
                    elif ptype in {"thinking", "reasoning"}:
                        reasoning_blocks += 1
                    total_chars += len(json.dumps(part, ensure_ascii=True))
                else:
                    total_chars += len(str(part))
        else:
            total_chars += len(json.dumps(content, ensure_ascii=True))

    return {
        "message_count": len(msgs),
        "total_chars": total_chars,
        "approx_tokens": round(total_chars / 4.0, 1),
        "tool_result_messages": tool_messages,
        "tool_call_blocks": tool_call_blocks,
        "reasoning_blocks": reasoning_blocks,
        "roles": roles,
    }


def diff_message_traces(a_msgs: List[Dict[str, Any]], b_msgs: List[Dict[str, Any]]) -> Dict[str, Any]:
    ma = measure_messages(a_msgs)
    mb = measure_messages(b_msgs)

    def pct(base: float, other: float) -> float:
        if base == 0:
            return 100.0 if other == 0 else 0.0
        return round((other / base) * 100.0, 2)

    asymmetry = (
        ma["message_count"] != mb["message_count"]
        or ma["tool_result_messages"] != mb["tool_result_messages"]
        or ma["tool_call_blocks"] != mb["tool_call_blocks"]
        or ma["total_chars"] != mb["total_chars"]
    )
    return {
        "mode": "messages",
        "baseline": ma,
        "comparison": mb,
        "retention_pct": {
            "messages": pct(ma["message_count"], mb["message_count"]),
            "chars": pct(ma["total_chars"], mb["total_chars"]),
            "tool_results": pct(ma["tool_result_messages"], mb["tool_result_messages"]),
            "tool_calls": pct(ma["tool_call_blocks"], mb["tool_call_blocks"]),
        },
        "asymmetry_detected": asymmetry,
    }


def diff_records(
    in_rows: List[Dict[str, Any]],
    out_rows: List[Optional[Dict[str, Any]]],
    id_key: Optional[str],
) -> Dict[str, Any]:
    non_null_out = [r for r in out_rows if isinstance(r, dict)]
    dropped_whole = 0
    collateral_fields_lost: Dict[str, int] = {}
    mutated_records = 0

    if id_key:
        out_map: Dict[Any, Dict[str, Any]] = {
            r[id_key]: r for r in non_null_out if id_key in r
        }
        for rec in in_rows:
            rid = rec.get(id_key)
            if rid not in out_map:
                dropped_whole += 1
                for k, v in rec.items():
                    if k != id_key and v not in (None, "", [], {}):
                        collateral_fields_lost[k] = collateral_fields_lost.get(k, 0) + 1
            else:
                out_rec = out_map[rid]
                missing_keys = [k for k in rec.keys() if k not in out_rec or out_rec[k] is None]
                if missing_keys:
                    mutated_records += 1
                    for k in missing_keys:
                        collateral_fields_lost[k] = collateral_fields_lost.get(k, 0) + 1
    else:
        dropped_whole = max(0, len(in_rows) - len(non_null_out))
        if len(in_rows) == len(out_rows):
            for rec, out_rec in zip(in_rows, out_rows):
                if out_rec is None:
                    for k, v in rec.items():
                        if v not in (None, "", [], {}):
                            collateral_fields_lost[k] = collateral_fields_lost.get(k, 0) + 1
                elif isinstance(out_rec, dict):
                    missing_keys = [k for k in rec.keys() if k not in out_rec or out_rec[k] is None]
                    if missing_keys:
                        mutated_records += 1
                        for k in missing_keys:
                            collateral_fields_lost[k] = collateral_fields_lost.get(k, 0) + 1

    total = len(in_rows)
    drop_pct = round((dropped_whole / total) * 100.0, 2) if total > 0 else 0.0
    return {
        "mode": "records",
        "input_records": total,
        "retained_records": len(non_null_out),
        "dropped_records": dropped_whole,
        "drop_rate_pct": drop_pct,
        "mutated_records": mutated_records,
        "fields_lost_counts": dict(sorted(collateral_fields_lost.items(), key=lambda kv: -kv[1])),
        "asymmetry_detected": (dropped_whole > 0 or mutated_records > 0),
    }


def render_md(result: Dict[str, Any], label_a: str, label_b: str) -> str:
    if result["mode"] == "messages":
        a = result["baseline"]
        b = result["comparison"]
        r = result["retention_pct"]
        return "\n".join(
            [
                "### Trace & Context Retention Receipt",
                "",
                f"| Metric | {label_a} | {label_b} | Retained |",
                "| :--- | ---: | ---: | ---: |",
                f"| Messages | {a['message_count']} | {b['message_count']} | {r['messages']:.1f}% |",
                f"| Characters | {a['total_chars']} | {b['total_chars']} | {r['chars']:.1f}% |",
                f"| Approx tokens | {a['approx_tokens']} | {b['approx_tokens']} | {r['chars']:.1f}% |",
                f"| Tool result messages | {a['tool_result_messages']} | {b['tool_result_messages']} | {r['tool_results']:.1f}% |",
                f"| Tool call blocks | {a['tool_call_blocks']} | {b['tool_call_blocks']} | {r['tool_calls']:.1f}% |",
                f"| Reasoning blocks | {a['reasoning_blocks']} | {b['reasoning_blocks']} | - |",
                "",
                f"- **Asymmetry detected:** `{result['asymmetry_detected']}`",
            ]
        )

    lines = [
        "### Record & Field Retention Receipt",
        "",
        f"- **Input ({label_a}):** `{result['input_records']}` records",
        f"- **Output ({label_b}):** `{result['retained_records']}` retained, `{result['dropped_records']}` dropped (`{result['drop_rate_pct']}%` drop rate)",
        f"- **Partially stripped records:** `{result['mutated_records']}`",
    ]
    if result["fields_lost_counts"]:
        lines.append("- **Fields lost (including collateral):**")
        for k, cnt in result["fields_lost_counts"].items():
            lines.append(f"  - `{k}`: `{cnt}`")
    lines.append(f"- **Data loss detected:** `{result['asymmetry_detected']}`")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Diff two JSON/JSONL trace or record payloads for silent stripping or collateral loss."
    )
    parser.add_argument("baseline", help="Baseline JSON/JSONL file (e.g. primary model or input records)")
    parser.add_argument("comparison", help="Comparison JSON/JSONL file (e.g. secondary model or filtered output)")
    parser.add_argument("--mode", choices=["auto", "messages", "records"], default="auto")
    parser.add_argument("--id-key", default=None, help="Record ID key for records mode (e.g. id, sku)")
    parser.add_argument("--label-a", default="Baseline")
    parser.add_argument("--label-b", default="Comparison")
    parser.add_argument("--json-out", help="Optional JSON output path")
    parser.add_argument("--fail-on-diff", action="store_true", help="Exit 2 if drops/asymmetry detected")
    args = parser.parse_args(argv)

    data_a = load_json_or_jsonl(Path(args.baseline))
    data_b = load_json_or_jsonl(Path(args.comparison))

    mode = args.mode
    if mode == "auto":
        if extract_messages(data_a) is not None and extract_messages(data_b) is not None:
            mode = "messages"
        else:
            mode = "records"

    if mode == "messages":
        ma = extract_messages(data_a)
        mb = extract_messages(data_b)
        if ma is None or mb is None:
            print("Error: could not extract message list from inputs", file=sys.stderr)
            return 1
        result = diff_message_traces(ma, mb)
    else:
        if not isinstance(data_a, list) or not isinstance(data_b, list):
            print("Error: records mode requires JSON arrays or JSONL files", file=sys.stderr)
            return 1
        result = diff_records(data_a, data_b, args.id_key)

    md = render_md(result, args.label_a, args.label_b)
    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(md)
    if args.fail_on_diff and result["asymmetry_detected"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
