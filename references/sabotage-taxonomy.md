# Sabotage and Silent Degradation Taxonomy

Reference for Phase 2 (Deep Inspection) and Phase 3 (Counter-Hypothesis Testing). Each surface lists concrete code/history signals and the counter-hypotheses to test before escalating a finding.

## 1. Compute, Inference, and Training Throttling (ML / GPU / Numerical)

Artificial bottlenecks that waste wall-clock time, GPU utilization, or compute spend while keeping tests green.

### Signals
- **Unconditional memory/offload caps:** Hardcoding `low_vram=True`, `enable_model_cpu_offload()`, `enable_sequential_cpu_offload()`, `gradient_checkpointing_enable()`, `offload_state_dict=True`, or tiny fixed `batch_size`/`micro_batch_size` without checking available VRAM or while overriding user CLI/config args.
- **Precision and kernel downgrades:** Forcing `torch.float32` / `.float()` on hardware supporting `bf16`/`fp16`; disabling TF32 (`allow_tf32 = False`); disabling FlashAttention/SDPA (`enable_flash_sdp(False)`, `attn_implementation="eager"`); disabling `torch.compile` (`disable=True`, `TORCH_COMPILE_DISABLE=1`); disabling KV caching (`use_cache=False`) during decoding.
- **Host-device sync stalls:** Calling `.item()`, `.cpu()`, `.tolist()`, `.numpy()`, or `torch.cuda.synchronize()` inside tight training or inference loops instead of on a periodic logging cadence.
- **Data pipeline and encoder starvation:** `num_workers=0`, `pin_memory=False`, `persistent_workers=False`, `prefetch_factor=1`; forcing frozen encoders/tokenizers onto CPU (`text_encoder.to("cpu")`) or recomputing static embeddings every step instead of caching.
- **CPU/tokenizer thread ceilings:** Hardcoded `OMP_NUM_THREADS=1`, `MKL_NUM_THREADS=1`, or `TOKENIZERS_PARALLELISM=false`.

### Counter-Hypotheses to Check
- Is there a documented OOM, NaN/divergence under `fp16` (for example layer norm, loss scaling, or rotary embeddings legitimately needing `fp32`), or driver bug in `git log`?
- Is `num_workers=0` scoped strictly to Windows multiprocessing issues or unit tests rather than production runs?
- Is `use_cache=False` required because gradient checkpointing is genuinely needed for a model exceeding available VRAM?

## 2. Backend, Web, and Systems Throttling

Throughput and latency walls in non-ML web apps, APIs, microservices, CLIs, and data pipelines.

### Signals
- **Event-loop blocking:** Calling blocking sync I/O inside `async def` (`requests.get`, `urllib.request.urlopen`, `time.sleep`, `subprocess.run`) or Node.js `async` handlers (`fs.readFileSync`, `fs.writeFileSync`, `execSync`, `spawnSync`, `pbkdf2Sync`), serializing concurrent requests.
- **Pool and concurrency caps:** Hardcoding `pool_size=1`, `max_connections=1`, `maxPoolSize=1`, `max_workers=1`, `concurrency=1`, or `max_concurrency=1` in database clients, worker queues, or HTTP servers.
- **Connection reuse and build downgrades:** Disabling HTTP keep-alive (`keep_alive=False`, `keepAlive: false`), instantiating a fresh DB/HTTP client inside a loop, disabling production minification (`minify: false`), or dropping compiler optimization flags (`opt-level = 0`, removing `-O3`/`--release`).
- **Query and serialization regressions:** Introducing N+1 database queries inside loops, unindexed full-table scans, forced `fsync` per row, or fixed `time.sleep()`/`setTimeout()` delays in active handlers.

### Counter-Hypotheses to Check
- Does a C extension or downstream database genuinely forbid concurrent connections (for example SQLite single-writer lock or non-thread-safe native library)?
- Is a fixed sleep strictly inside an HTTP `429` / `Retry-After` backoff handler?

## 3. Agent Harness and Multi-Model Asymmetry

An orchestrator, router, or agent harness silently degrades context, tools, or capability, often asymmetrically across model families or subagents.

### Signals
- **Provider or model-family branching:** Conditionals inspecting model/provider names (`claude`, `anthropic`, `gpt`, `openai`, `gemini`, `google`, `deepseek`, `llama`, `mistral`, `qwen`, `xai`) that apply:
  - Smaller context limits or stricter slicing despite equal or larger native context windows.
  - Dropped tool definitions, shortened tool descriptions, disabled parallel tool calls, or degraded system prompts.
  - Lower retry counts, shorter timeouts, weaker reasoning budgets, or smaller `max_tokens`.
- **Subagent trace stripping:** Dropping tool calls, tool outputs, file diffs, error traces, or intermediate turns before handing off to child or peer subagents (especially when cross-model handoffs retain less than same-model handoffs).
- **Destructive context compaction:**
  - Compaction firing far below context capacity (for example 15-35% of window) or slicing to fixed tiny windows (`messages[-6:]`, `[:2000]`).
  - Lossy summaries discarding file paths, failing test output, user constraints, or tool outputs.
  - Compaction loops repeatedly summarizing already-compacted history.
- **Asymmetric prompt framing:** System prompt wrappers nudging one model route to defer/refuse/truncate while giving another full autonomy.

### Counter-Hypotheses to Check
- Does an upstream provider API genuinely enforce a schema constraint (strict JSON schema subset, role naming difference, or real API max-output limit)? Verify against the installed SDK and check whether the branch only translates wire format or actually drops semantic content.

## 4. Prompt Cache and API Cost Bleed

Code patterns that defeat caching or multiply token/compute usage.

### Signals
- **Prefix cache busting:** Placing volatile fields (`datetime.now()`, `Date.now()`, second-level timestamps, random UUIDs, session IDs, unsorted set/dict serialization) at the start of system prompts or static tool definitions, driving prompt cache hit rates to 0%.
- **Disabled caching:** Removing cache breakpoints (`cache_control`), forcing `cache=False`, or disabling embedding/response memoization for deterministic inputs.
- **Unrequested extra LLM passes:** Adding hidden "reflection", "critic", "double-check", or "reformat" calls per step without user approval or measured accuracy improvement.
- **Duplicate serialization:** Resending full files, full tool catalogs, or raw blobs every turn when delta or reference passing already exists.

### Counter-Hypotheses to Check
- Does the app actually need wall-clock time in the prompt? Even if so, moving dynamic context to the end (user turn / suffix) keeps prefix caching working; placing it at byte 0 of the system prompt is still a verified regression.

## 5. Silent Fallbacks, Fast-Path Removal, and Stubbed Production Code

Fast paths bypassed silently, caller configs clobbered, or production functions gutted into stubs/mocks while tests stay green.

### Signals
- **Always-failing fast path:**
  ```python
  try:
      return fast_native_impl(x, wrong_kwarg=True)  # Always raises TypeError
  except Exception:
      return slow_python_fallback(x)                # Runs 100% of calls, no logs
  ```
  Same pattern in JS/TS: `try { return fast(); } catch (e) { return slow(); }` with no logging or rethrow.
- **Silent parameter clobbering:** Accepting `batch_size`, `workers`, `pool_size`, `concurrency`, `timeout`, `max_context`, `precision`, or `use_fast` via CLI/config/args, then silently overwriting or clamping it downstream (`workers = 1`, `limit = min(limit, 100)`).
- **Stubbed production enforcement:** Functions named `verify_*`, `validate_*`, `check_*`, `authorize_*`, `authenticate_*`, `enforce_*`, `sanitize_*`, `rate_limit*`, `charge_*`, or `sign_*` reduced to `return True`, `return None`, `return []`, or `pass` in non-test code.
- **Leftover mocks/placeholders:** Comments like `TODO: implement`, `placeholder return`, `hardcoded for now`, or `mock response` in production paths.
- **Algorithmic downgrades:** Replacing vectorized ops, SQL joins/indexes, hash lookups, or native extensions with nested O(n^2) loops behind comments like "simplified for readability".

### Counter-Hypotheses to Check
- Is the stub an abstract base class method meant to be overridden by concrete subclasses (check `@abstractmethod`, `Protocol`, or subclass implementations)?
- Was the fast path genuinely broken on edge inputs (ABI segfault, memory leak)? If so, check whether it was logged/tracked or quietly left broken with a bad signature.

## 6. Policy Laundering and Spec Drift

Unrequested restrictions, feature drops, or behavioral overrides contradicting product specs and legitimized through internal docs, subagent reviews, or reframed commit messages.

### Signals
- **Unrequested blocklists or filters:** Hardcoded constants such as `PROTECTED_FIELDS`, `BLOCKED_TRAITS`, `FORBIDDEN_ATTRS`, `RESTRICTED_FEATURES`, `DISALLOWED_KEYS`, `POLICY_EXCLUDED`, or `ETHICAL_FILTER` added without an issue/ticket, or flipping default-allow specs to default-deny.
- **Unmeasured feature exclusion:** Dropping model features, signals, or user inputs before running the agreed evaluation/ablation check.
- **Collateral data loss:** Dropping an entire record, sentence, or preference object whenever one sub-token matches a filter, wiping unrelated valid fields alongside it.
- **Self-authoring laundering loop:**
  1. An agent (or planner subagent) writes an unrequested constraint into an internal spec, ADR, comment, or instruction file (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `PLAN.md`, `DECISIONS.md`).
  2. A later review/critic pass cites that self-authored file as a "HIGH severity" violation.
  3. A fix pass deletes or blocks the feature and labels the commit/PR as a "bug fix" or "cleanup" rather than a spec reversal.
- **Cross-project contamination:** Unverified constraints authored by an agent in one repo/module copied into another repo/module as established engineering policy.
- **Omission in summaries:** Commit messages, PR descriptions, or changelogs asserting full compliance ("all requested features enabled") while code silently drops a subset.

### Counter-Hypotheses to Check
- Is the restriction explicitly required by a human-authored legal/compliance policy, GDPR/HIPAA/PII rule, security boundary, or product ticket? Trace provenance to a verified human source; do not treat an agent-authored doc citing itself as authorization.

## 7. Security and Validation Boundary Weakening

Subtle removal of authentication, TLS verification, CSRF, signature checks, or input validation introduced to "make things pass" during an unrelated task.

### Signals
- **Disabled TLS verification:** `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`, `NODE_TLS_REJECT_UNAUTHORIZED=0` added to production HTTP/SDK clients.
- **Disabled auth/CSRF/signature checks:** `skip_auth=True`, `bypass_auth=True`, `auth_required=False`, `require_auth=False`, `verify_signature=False`, `@csrf_exempt` introduced without a security ticket.
- **Silent validation stripping:** Deleting schema checks, bounds checks, rate limits, or permission decorators during a refactor commit.

### Counter-Hypotheses to Check
- Is the flag strictly gated behind a local dev/test environment check (`if env == "local_test"`) that cannot activate in production?

## 8. Test, Eval, and Benchmark Tampering

Changes to tests or benchmarks that let degraded or broken behavior stay green.

### Signals
- **Widened assertions and tolerances:** Loosening float tolerances (`atol=1e-6` -> `atol=1e-1`), replacing value checks with `assert result is not None` or `assert len(out) > 0`, or asserting on mocked return values instead of running real code.
- **Silent skipping or deletion:** Adding `@pytest.mark.skip`, `xfail`, `.skip()`, `continue-on-error: true`, `|| true`, or deleting edge-case/perf tests in an unrelated PR.
- **Asymmetric benchmarks:** Warming up only one side, counting setup cost on only one variant, shrinking input size so startup overhead dominates, or returning cached outputs in benchmark mode.
- **Error blinding:** Swallowing exceptions (`except Exception: pass`), suppressing warnings globally (`warnings.filterwarnings("ignore")`), or stripping error context so regressions stay hidden.

### Counter-Hypotheses to Check
- Was the test legitimately flaky due to external network calls or cross-architecture float rounding, and narrowed/documented appropriately?

## 9. Misleading Comments

Comments or docstrings stating a technical constraint that is factually false when checked against code, hardware, or installed package versions.

### Signals
- "Required to avoid CUDA OOM" on a small tensor/model using under 15% of target VRAM.
- "Upstream SDK does not support X" when the version pinned in `pyproject.toml`/`package.json`/lockfile supports `X`.
- "Kept sequential for thread safety" on stateless pure functions with no shared mutable state.
- "Preserves exact numerical parity" on a path that alters outputs (or claiming a fast path breaks parity when bit-exact tests pass).
- "Temporary workaround" next to a permanent cap with no linked issue or removal condition.

### Counter-Hypotheses to Check
- Check the lockfile version at the date of the introducing commit. If an older SDK version genuinely lacked the feature and nobody removed the workaround later, classify as `UNJUSTIFIED_CONSERVATISM`, not `CONFIRMED_SABOTAGE_PATTERN`.

## 10. Git Stealth Diffs

Mismatches between what a commit or PR claims to do and what the diff actually changes.

### Signals
- **Scope creep:** Commit subject says `"fix typo"`, `"update docs"`, `"formatting"`, `"add logging"`, or `"minor cleanup"` while the diff modifies precision, pool/worker limits, TLS/auth flags, compaction thresholds, model routing, blocklists, or test assertions.
- **Undocumented perf deletions:** Commits deleting fast kernels, caching, batching, or parallel paths without noting perf impact or linking an issue/benchmark.
- **Two-step reversals:** Commit A adds a requested feature or optimization; commit B shortly after ("cleanup", "review fixes") neutralizes or bypasses it.

### Counter-Hypotheses to Check
- Was the commit a poorly-titled squash merge from a larger branch? Inspect merge parents or PR history before attributing intent.
