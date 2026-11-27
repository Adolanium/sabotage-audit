# Standalone Prompt (No Skill Loader Required)

Copy and paste the block below into any coding agent (Cursor, Claude Code, Codex, Gemini CLI, Windsurf, OpenCode) if you do not have `npx skills` installed.

```text
Audit this repository for silent degradation, hardcoded performance throttling,
multi-agent context or routing asymmetry, unrequested policy overrides,
misleading comments, git stealth diffs, and weakened tests.

Rules:
1. Stay strictly read-only on tracked repository files. Put any temporary repro
   or benchmark scripts in a temporary directory and delete them when done.
2. Proof required: never report a static guess as confirmed. Every escalated
   finding must include:
   - Exact file:line, symbol name, and introducing git commit SHA (if git exists).
   - Executable proof (controlled A/B benchmark with warmup, median/IQR/p95, and
     SHA-256 bit-exact or fixed-seed float equivalence; OR a live input/output
     trace or record diff; OR a live repro test).
   - Counter-hypothesis check: actively search git log, issue refs, lockfiles,
     and hardware/API constraints to rule out legitimate guards. Put cleared
     suspects in a Cleared Items table.
3. Check these 10 surfaces PLUS do a first-principles pass over core hot paths,
   config loaders, auth/validation boundaries, and recent commits for bespoke
   regressions:
   (1) Compute/ML throttling (low_vram, cpu_offload, forced fp32, disabled
       TF32/FlashAttention/compile/KV-cache, syncs in hot loops, num_workers=0).
   (2) Backend/web/systems throttling (blocking sync I/O inside async functions
       like requests.get/time.sleep/fs.readFileSync/execSync, pool_size=1 or
       concurrency=1, disabled keep-alive/minification/opt-level, N+1 queries).
   (3) Agent harness / multi-model asymmetry (branches checking model/provider
       names, stripped subagent tool traces, premature compaction).
   (4) Prompt cache / cost bleed (timestamps/UUIDs at start of system prompts,
       disabled caching, unrequested extra LLM passes).
   (5) Silent fallbacks, config clobbering, and stubbed prod code (broad except
       or empty JS catch swallowing broken fast paths, caller args overwritten
       or clamped, verify_*/check_*/authorize_* returning True/None/pass).
   (6) Policy laundering / spec drift (unrequested blocklists like PROTECTED_*
       or RESTRICTED_*, collateral field drops, self-authored rules in
       AGENTS.md/CLAUDE.md/PLAN.md enforced later as bug fixes).
   (7) Security/boundary weakening (verify=False, rejectUnauthorized: false,
       InsecureSkipVerify: true, skip_auth=True, auth_required=False,
       @csrf_exempt snuck in during refactors).
   (8) Test/eval tampering (widened atol/rtol, assert True, skipped hard cases).
   (9) Misleading comments contradicted by actual memory usage or lockfiles.
   (10) Git stealth diffs (trivial commit messages modifying runtime behavior,
        pool limits, auth/TLS flags, or deleting optimizations).
4. Classify each finding conservatively:
   - CONFIRMED_SABOTAGE_PATTERN (verified degradation + asymmetric/deceptive
     signal)
   - VERIFIED_SILENT_DEGRADATION (measured regression, intent unproven)
   - UNJUSTIFIED_CONSERVATISM (hardcoded defensive cap wasting resources)
   - UNVERIFIED_LEAD (could not run locally; provide exact command to verify)
   - CLEARED_LEGITIMATE (checked and verified necessary)
5. Finish with a phased remediation plan (P0 immediate parity-verified fixes,
   P1 structural fixes, P2 CI guardrails) listing exact files/lines, patch
   summaries, post-fix verification commands, and rollback steps.
```
