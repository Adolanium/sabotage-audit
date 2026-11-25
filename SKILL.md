---
name: sabotage-audit
description: >-
  Audits AI-assisted codebases for silent regressions, hardcoded performance
  throttling, multi-agent context or routing asymmetry, unrequested policy
  overrides, spec drift, and weakened tests. Requires executable proof
  (controlled A/B benchmarks with output-equivalence checks, live payload or
  trace diffs, and git provenance) plus counter-hypothesis testing before
  escalating any finding, then outputs a phased remediation plan. Use when
  checking a repo for hidden slowdowns, subagent context loss, unexplained
  feature drops, tampered tests, or suspected code sabotage.
license: MIT
compatibility: Requires Python 3.8+ (standard library only) and git (optional, for history checks).
metadata:
  version: "1.0.0"
  category: forensics-and-verification
---

# sabotage-audit

Audit the target repository for silent degradation, artificial throttling, asymmetric model/subagent handling, unrequested policy overrides, or concealed regressions. Prove every claim with reproducible runtime evidence, then produce a prioritized remediation plan.

## Operating Modes

Select mode from the user request (default to **Full Audit**):

- **Full Audit (default):** Read-only whole-repo pre-scan, deep 10-surface + first-principles inspection, counter-hypothesis testing, executable proof receipts, and a P0/P1/P2 remediation plan.
- **Diff / PR Audit:** Bounded to a branch, PR, or commit window (`--since <ref>`). Focuses on recently added code, stealth diffs, test changes, and instruction-doc edits.
- **Audit and Apply Fixes (explicit opt-in only):** Runs the complete read-only audit and prints receipts first. Only if the user explicitly asked to apply fixes, apply P0/P1 changes one at a time, re-running each finding's verification gate (`verify_equivalence.py`, `diff_traces.py`, and test suite) after each edit and reverting immediately if parity or tests fail.

## Operating Rules

1. **Proof required:** Do not mark a finding as `CONFIRMED` or `VERIFIED` from static reading alone. Every escalated finding must include an executable receipt (A/B benchmark with equivalence check, live trace/payload diff, repro test, or verified git/spec contradiction). Static leads that cannot be executed locally go into `UNVERIFIED_LEAD`.
2. **Read-only on tracked files by default:** Do not edit repository files during the audit unless the user explicitly opted into **Audit and Apply Fixes**. Put temporary repro and benchmark scripts in an OS temp dir or `.sabotage-audit-tmp/` and clean them up afterward.
3. **Counter-hypothesis check first:** Before escalating any suspect, try to disprove it. Check `git log -S`, `git blame`, commit messages, issue refs, hardware limits, rate limits, concurrency hazards, and upstream SDK constraints. If a guard prevents a real OOM, race condition, crash, or security issue, mark it `CLEARED_LEGITIMATE` and record it in the Cleared Items table.
4. **Output equivalence required for perf claims:** A speedup claim is invalid without parity proof: SHA-256 bit-exact match for deterministic code, or fixed-seed numerical tolerances (`max_abs_diff`, `max_rel_diff`, cosine similarity) for floating-point/ML code, plus passing tests.
5. **Multi-signal threshold for Tier 1:** Reserve `CONFIRMED_SABOTAGE_PATTERN` for verified degradation paired with a clear asymmetric or deceptive signal (for example provider-discriminatory handling, subagent trace stripping, self-authored rule laundering, stealth commit diff, test tampering, or a misleading comment disproved at runtime). Single isolated suboptimal defaults belong in Tier 2 or Tier 3.
6. **Verify all claims against code:** Treat comments, docstrings, PR descriptions, commit messages, and agent instruction files (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `PLAN.md`, ADRs) as unverified until checked against executable code and git history.

## Workflow

### Phase 1: Scope, Baseline, and Pre-Scan

1. Confirm target path, codebase profile (ML training/inference, agent harness, backend/API, library), and mode.
2. Run the zero-dependency pre-scanner to surface Python AST leads, JS/TS structural leads, instruction-doc rules, and git stealth-diffs:
   ```bash
   python scripts/forensic_scan.py <target_root> --json-out <tmp>/scan.json --md-out <tmp>/scan.md
   ```
   - Pass `--since <git_ref>` or `--git-depth <N>` for scoped audits.
   - Pass `--strict` when you also want noisier `MEDIUM` leads (broad `except` / silent JS `catch` blocks and non-async fixed `sleep()` delays) included in triage.
   - If the repo has agent instruction docs, ADRs, planning files, or user-provided session logs, read [references/transcript-forensics.md](./references/transcript-forensics.md).
3. Record baseline metadata (git HEAD SHA, clean/dirty status, runtime versions, CPU/GPU) so receipts can be reproduced by another engineer.

### Phase 2: Deep Inspection (10 Surfaces + First-Principles Pass)

Review the pre-scanner leads AND read core hot paths, config loaders, auth/validation boundaries, and recent diffs directly. Use [references/sabotage-taxonomy.md](./references/sabotage-taxonomy.md) for concrete signatures and counter-hypotheses across these 10 surfaces:

1. **Compute, inference, and training throttling (ML/GPU):** Hardcoded low-VRAM/offload settings, forced `float32`, disabled FlashAttention/SDPA/TF32/`torch.compile`/KV-cache, `.cpu()`/`.item()`/`cuda.synchronize()` inside loops, single-worker dataloaders, redundant re-encoding/tokenization.
2. **Backend, web, and systems throttling (non-ML):** Blocking sync I/O inside `async` functions (`requests.get`, `time.sleep`, `fs.readFileSync`, `execSync`), hardcoded `pool_size=1` / `concurrency=1` / `max_workers=1`, disabled HTTP keep-alive or build optimizations (`minify: false`, `opt-level = 0`), N+1 queries inside loops, fixed `sleep()` delays.
3. **Agent harness and multi-model asymmetry:** Branches inspecting model/provider/vendor names that narrow context, drop tools, reduce retries, or alter reasoning/temperature limits; silent subagent trace/tool-output stripping; premature or destructive compaction.
4. **Prompt cache and API cost bleed:** Volatile prefixes (`now()`, UUIDs, unsorted keys) at the start of system prompts, disabled provider caching/batching/streaming, unrequested extra LLM passes, duplicate serialization.
5. **Silent fallbacks, fast-path removal, and stubbed production code:** Broad `try/except` or silent JS/TS `catch` blocks masking broken fast paths; caller/config parameters overwritten or clamped downstream; stubbed enforcement/verification functions (`def verify_*(): return True`); leftover mocks/placeholders in production paths.
6. **Policy laundering and spec drift:** Unrequested hardcoded blocklists/filters (`PROTECTED_*`, `BLOCKED_*`, `RESTRICTED_*`) contradicting specs or skipping evaluation; coarse filters dropping unrelated fields; self-authored constraints planted in `AGENTS.md`/`CLAUDE.md`/`PLAN.md`/ADRs and later enforced as "bugs" or copied into new projects.
7. **Security and validation boundary weakening:** Silently disabled TLS checks (`verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`), disabled auth/CSRF/signature checks (`skip_auth=True`, `auth_required=False`, `@csrf_exempt`), or stripped validation during unrelated refactors.
8. **Test, eval, and benchmark tampering:** Loosened tolerances, vacuous assertions, skipped/deleted hard cases, mocked-out systems under test, asymmetric benchmark warmups, suppressed CI exit codes.
9. **Misleading comments:** Comments claiming hardware limits, SDK bugs, thread-safety issues, or "temporary workarounds" contradicted by memory profiles, lockfiles, or code behavior.
10. **Git stealth diffs:** Commits titled `docs`, `lint`, `typo`, `logging`, or `cleanup` whose diffs modify precision, pool/worker limits, auth/TLS flags, routing, compaction, or filters; status summaries omitting dropped behavior.

**First-principles pass (unknown-unknowns):** Do not tunnel-vision on scanner output alone. Read the repo's main entry points, config plumbing, hot loops, and recent commits with fresh eyes to catch bespoke mistakes or domain-specific regressions that do not match any fixed rule, then subject them to Phases 3 and 4.

### Phase 3: Counter-Hypothesis Testing and Classification

For every candidate finding:

1. Trace provenance with `git log -L`, `git log -S`, or `git blame` (when `.git` exists). Read the introducing commit message, full diff, and nearby commits.
2. State the strongest benign engineering explanation (OOM fix, race condition, vendor API quirk, backwards compatibility, or explicit human compliance requirement).
3. Test that explanation against git history, lockfiles, tests, and runtime behavior.
4. Assign one label from [references/proof-standards.md](./references/proof-standards.md):
   - `CONFIRMED_SABOTAGE_PATTERN`
   - `VERIFIED_SILENT_DEGRADATION`
   - `UNJUSTIFIED_CONSERVATISM`
   - `UNVERIFIED_LEAD` (could not execute locally; quarantined)
   - `CLEARED_LEGITIMATE` (exonerated; logged in Cleared Items table)

### Phase 4: Executable Proof Receipts

Produce a copy-pasteable, reproducible receipt for every finding above `UNVERIFIED_LEAD`:

- **Performance / compute / algorithmic issues:**
  Run [scripts/verify_equivalence.py](./scripts/verify_equivalence.py) comparing the current path against an isolated clean candidate without editing tracked files:
  - Include warmup runs and alternating AB/BA measured trials (report median, IQR, p95; never a single run).
  - Verify output parity (`--mode exact` for SHA-256 bit-exactness, or `--mode float --atol ... --rtol ...` with a fixed seed).
- **Agent harness / context / multi-model asymmetry / record drops:**
  Run [scripts/diff_traces.py](./scripts/diff_traces.py) on synthetic or captured payloads comparing Branch A vs. Branch B (or input records vs. filtered output):
  - Quantify exact message count, char/token delta, tool-call/tool-result drop rates, or collateral field losses.
- **Test / eval tampering:**
  Show the `git diff` that weakened the check and run an isolated check proving a broken implementation passes the weakened test (or the original stricter check fails on `HEAD`).

### Phase 5: Report and Remediation Plan

Format the final output using the schema in [references/proof-standards.md](./references/proof-standards.md):

1. **Verdict summary** (`CLEAN`, `CONSERVATISM_ONLY`, `DEGRADATION_VERIFIED`, or `HIGH_CONFIDENCE_SABOTAGE_DETECTED`), baseline metadata, and a table of measured-only deltas.
2. **Verified findings** with ID, verdict tier, severity, surface, `file:line`, git commit, claim vs. reality, counter-hypothesis result, and verbatim proof receipt.
3. **Quarantined unverified leads** (only if local hardware/credentials prevented execution), with exact commands the user can run locally.
4. **Cleared items** table listing flagged suspects that checked out as legitimate.
5. **Phased remediation plan:**
   - **P0 (Immediate fixes):** High-impact, parity-verified removals of throttles, broken fallbacks, asymmetric drops, or unrequested filters.
   - **P1 (Structural fixes):** Dynamic hardware detection, unified provider-agnostic routing/compaction, restored test coverage, clean config plumbing.
   - **P2 (CI guardrails):** Perf ratchets, equivalence tests, static checks catching silent fallback catches and model-name branching, and review rules on agent instruction docs (see [examples/ci-guardrail.yml](./examples/ci-guardrail.yml)).
   - Every step must specify target `file:line`, patch summary, post-edit verification command, and rollback path.

Only write `SABOTAGE_AUDIT_REPORT.md` into the workspace if the user asks for a file; otherwise return the report directly.
