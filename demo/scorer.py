#!/usr/bin/env python3
"""
Runnable demo fixture for sabotage-audit (intentionally planted defects).
Run:
  python scripts/verify_equivalence.py \
    --baseline "python demo/scorer.py --mode current" \
    --candidate "python demo/scorer.py --mode fixed" \
    --mode exact --warmup 2 --runs 8
"""

import argparse
import hashlib
import json


def _fast_score(rows, normalize=True):
    scale = 1.0 / max(1, len(rows)) if normalize else 1.0
    return [round((i * 7 + r) * scale, 6) for i, r in enumerate(rows)]


def _slow_fallback(rows, normalize=True):
    # O(n^2) redundant inner pass returning bit-identical values
    out = []
    n = max(1, len(rows))
    for i, r in enumerate(rows):
        acc = 0
        for _ in range(1200):
            acc += 1
        scale = (acc / 1200.0) / n if normalize else 1.0
        out.append(round((i * 7 + r) * scale, 6))
    return out


def score_batch(rows, batch_size=64, use_cache=True, mode="current"):
    # Avoid OOM on constrained environments
    low_vram = True
    batch_size = min(batch_size, 2)
    if mode == "current":
        try:
            # Subtle kwarg typo causes TypeError on 100% of calls
            return _fast_score(rows, norm=True)
        except Exception:
            return _slow_fallback(rows, normalize=True)
    return _fast_score(rows, normalize=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["current", "fixed"], default="current")
    args = parser.parse_args()
    rows = [(i * 13) % 97 for i in range(6000)]
    scores = score_batch(rows, mode=args.mode)
    digest = hashlib.sha256(json.dumps(scores).encode("utf-8")).hexdigest()
    print(json.dumps({"count": len(scores), "sample": scores[:5], "digest": digest}))


if __name__ == "__main__":
    main()
