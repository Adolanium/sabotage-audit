# Proof Standards, Verdict Rubric, and Report Schema

Evidentiary rules for `sabotage-audit`. Every escalated claim must hold up to direct reproduction and skeptical code review.

## 1. Verification Gate (All 4 Required)

Do not assign `CONFIRMED_SABOTAGE_PATTERN`, `VERIFIED_SILENT_DEGRADATION`, or `UNJUSTIFIED_CONSERVATISM` unless all four checks pass:

| Check | Requirement | Disqualifying Gap |
| :--- | :--- | :--- |
| 1. Code anchor | Exact `file:line-line`, symbol name, dataflow path, and git provenance (`commit SHA`, author/co-author metadata, diff excerpt) when `.git` exists. | Vague locations or misquoted code. |
| 2. Executable receipt | Self-contained command plus raw captured output proving runtime impact (A/B benchmark + parity check, live trace/payload diff, repro test, or verified git/test tamper repro). | Static guesswork ("this probably slows things down 2x"). |
| 3. Parity / impact proof | For perf/harness fixes: proof that removing the cap preserves outputs (SHA-256 bit-exact match, bounded float diff, or passing tests). For filter/spec drops: concrete valid input proven dropped or mutated. | Faster candidate that changes outputs or breaks edge cases. |
| 4. Counter-hypothesis check | Explicit statement of the strongest benign engineering explanation and why evidence rules it out. | Skipping `git log`, ignoring real OOM/race/API constraints, or assuming malice without checking history. |

**Quarantine rule:** If a lead is visible in code but cannot be executed in the current environment (for example it needs a GPU, private weights, or live API keys), put it under **Quarantined Unverified Leads** with the exact command for the user to run locally. Never count quarantined items as confirmed findings.

## 2. Verdict Levels

Pick the lowest level strictly supported by evidence:

| Tier | Label | Criteria |
| :--- | :--- | :--- |
| Tier 1 | `CONFIRMED_SABOTAGE_PATTERN` | Verified runtime/behavioral degradation plus at least one asymmetric or deceptive signal: (a) provider/model-discriminatory degradation, (b) silent stripping of peer/subagent traces, (c) self-authored policy laundering overriding an explicit spec, (d) empirically false comment disguising a throttle/drop, (e) stealth diff hiding a critical downgrade under an unrelated commit message, or (f) test/eval tampering hiding a regression. |
| Tier 2 | `VERIFIED_SILENT_DEGRADATION` | Verified measurable loss in throughput, latency, context retention, accuracy, cost, or feature completeness introduced without request or documentation, where intent cannot be proven deliberate (broken fast-path fallback, cache-busting timestamp in system prompt, accidental compaction bug). |
| Tier 3 | `UNJUSTIFIED_CONSERVATISM` | Hardcoded defensive ceiling (low-memory cap, single-worker default, forced fp32/offload, tiny hardcoded limit) that measurably wastes resources on target hardware, likely from cautious boilerplate or stale workarounds. |
| Tier 4 | `CLEARED_LEGITIMATE` | Flagged by static rules, investigated, and confirmed necessary (valid OOM guard, documented SDK limit, real compliance/security boundary, non-hot-path code). Recorded in the Cleared Items table. |

### Overall Repository Verdict
- `CLEAN`: zero Tier 1-3 findings.
- `CONSERVATISM_ONLY`: only Tier 3 findings verified.
- `DEGRADATION_VERIFIED`: one or more Tier 2 findings (no Tier 1).
- `HIGH_CONFIDENCE_SABOTAGE_DETECTED`: one or more Tier 1 findings with full 4-check receipts.

## 3. Benchmarking and Equivalence Rules

When proving perf or compute findings (via `scripts/verify_equivalence.py` or a custom isolated script):

1. **No single-run timings:** Run at least `3` warmup runs and `>= 10` measured runs (or `>= 5` for slow ML steps taking >2s each).
2. **Use robust stats:** Report **median**, **IQR (p75 - p25)**, **p95**, and **speedup ratio** (`baseline_median / candidate_median`). Flag runs where `IQR / median > 0.15` as noisy and increase trial count or isolate machine load.
3. **Fair A/B setup:** Identical input data, RNG seed, and environment, using alternating AB/BA trial order so thermal throttling does not skew one side.
4. **Output parity:**
   - Deterministic code: SHA-256 hash of canonical output must match (`bit-exact: PASS`).
   - Floating-point / ML code: fix RNG seeds and deterministic flags where supported; report `max_abs_diff`, `mean_abs_diff`, and `max_rel_diff` against explicit `atol`/`rtol`.
   - Memory / cost claims: measure actual peak RSS / peak VRAM (`torch.cuda.max_memory_allocated()`) or actual token/request counts rather than extrapolating from constants.

## 4. Output Report Template

```markdown
# Audit Report

## 1. Summary

- **Overall Verdict:** `CLEAN` | `CONSERVATISM_ONLY` | `DEGRADATION_VERIFIED` | `HIGH_CONFIDENCE_SABOTAGE_DETECTED`
- **Repository:** `<name / path>`
- **Git HEAD:** `<sha>` (`clean` | `dirty`)
- **Scope:** `<paths / commit range>`
- **Environment:** `<OS, CPU/GPU, runtime versions>`
- **Timestamp (UTC):** `<ISO-8601>`

### Measured Impact Summary
| Metric | Finding IDs | Baseline | Clean Candidate | Measured Delta | Equivalence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `<e.g., Inference latency>` | `SAB-001` | `<value>` | `<value>` | `<e.g., 1.82x faster>` | `Bit-exact (SHA-256 match)` |

*(Include only measured deltas from Phase 4. Omit unverified estimates.)*

## 2. Verified Findings

### [SAB-001] <Short Technical Title>
- **Verdict Tier:** `CONFIRMED_SABOTAGE_PATTERN` | `VERIFIED_SILENT_DEGRADATION` | `UNJUSTIFIED_CONSERVATISM`
- **Severity:** `CRITICAL` | `HIGH` | `MEDIUM` | `LOW`
- **Surface:** `<Surface 1-10>`
- **Location:** `<path/to/file.py:42-68>` (`<symbol>`)
- **Git Provenance:** `<commit SHA>` (`<date>`, `<subject>`, `<co-author trailer if present>`)
- **Claim vs. Reality:**
  - *Claim (comment / commit / config):* `<exact quote>`
  - *Reality:* `<factual observation>`
- **Counter-Hypothesis:**
  - *Hypothesis:* `<strongest benign explanation>`
  - *Result:* `<exact evidence ruling it out>`
- **Proof Receipt:**
  ```bash
  <exact command to reproduce without editing tracked files>
  ```
  ```text
  <verbatim raw output: benchmark table + equivalence hash OR trace/payload diff OR repro test output>
  ```

## 3. Quarantined Unverified Leads
*(Include only when local execution was blocked by missing hardware/credentials, with exact local verification commands.)*

## 4. Cleared Items
| Location | Triggered Rule | Reason Cleared (`CLEARED_LEGITIMATE`) |
| :--- | :--- | :--- |
| `<file:line>` | `<pattern>` | `<git/technical reason>` |

## 5. Remediation Plan

### P0: Immediate Fixes (High Impact, Verified Parity, Low Risk)
For each item:
- **Target:** `SAB-001` (`<file:line>`)
- **Change:** Exact patch summary (remove override / fix fast path / unify trace serialization / remove unrequested filter).
- **Verification gate:** Exact test + equivalence + benchmark command that must pass after editing.
- **Rollback:** Revert path or feature-flag fallback.

### P1: Structural Fixes
- Dynamic capability/hardware detection replacing hardcoded constants.
- Provider-agnostic context, compaction, and routing pipelines.
- Restoring weakened tests and fallback logging.

### P2: CI Guardrails
- Perf ratchets blocking silent latency/throughput regressions.
- Static/lint checks flagging silent `except: pass` fallbacks, provider-name branching in context code, and unreviewed changes to agent instruction files (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`).
- Require explicit spec/ticket links for hardcoded blocklists, precision downgrades, or widened test tolerances.
```
