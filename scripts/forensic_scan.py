#!/usr/bin/env python3
"""
forensic_scan.py: Zero-dependency static, AST, instruction-file, and git-history
pre-scanner for sabotage-audit.

Outputs triage leads for Phase 2-4 verification. Static leads alone are not
proof of sabotage; each lead must pass counter-hypothesis checks and runtime
verification per SKILL.md.

Python 3.8+ standard library only. Read-only on target repository.
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import fnmatch
import json
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

DEFAULT_EXCLUDES: Tuple[str, ...] = (
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    "out",
    "target",
    ".next",
    ".nuxt",
    ".output",
    ".cache",
    "*-build",
    ".*-build",
    ".tox",
    "vendor",
    "coverage",
    ".sabotage-audit-tmp",
    "*.min.js",
    "*.min.css",
    "*.bundle.js",
    "*.chunk.js",
    "*.gen.*",
    "*.generated.*",
    "*.map",
    "*.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Cargo.lock",
)

CODE_EXTS: Set[str] = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs",
    ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".java", ".kt", ".rb", ".php", ".sh", ".bash",
    ".yaml", ".yml", ".toml", ".json",
}

JS_TS_EXTS: Set[str] = {".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"}

INSTRUCTION_FILENAMES: Set[str] = {
    "agents.md",
    "claude.md",
    "gemini.md",
    "copilot.md",
    "copilot-instructions.md",
    ".cursorrules",
    ".windsurfrules",
    "plan.md",
    "decisions.md",
    "architecture.md",
    "policies.md",
}

MODEL_TOKENS_RE = re.compile(
    r"\b(claude|anthropic|gemini|google|vertex|gpt[-_]?[345]|openai|chatgpt|"
    r"deepseek|llama|mistral|qwen|grok|xai|opus|sonnet|haiku|codex|o[134]-?mini)\b",
    re.IGNORECASE,
)

CONTEXT_KEYWORDS_RE = re.compile(
    r"\b(context|prompt|message|messages|history|trace|traces|subagent|agent|"
    r"tool_result|tool_output|tool_call|observation|compaction|compact|summary|"
    r"window|tokens?|truncate|truncat|slice|handoff|transcript|system_prompt)\b",
    re.IGNORECASE,
)

THROTTLE_ADJACENCY_RE = re.compile(
    r"(low_vram|cpu_offload|float32|fp32|num_workers\s*=\s*0|max_workers\s*=\s*1|"
    r"pin_memory\s*=\s*False|use_cache\s*=\s*False|allow_tf32\s*=\s*False|"
    r"flash_sdp\s*\(\s*False|disable\s*=\s*True|eager|sleep\(|gradient_checkpoint|"
    r"batch_size\s*=\s*[12]\b|concurrency\s*=\s*1\b|sequential)",
    re.IGNORECASE,
)

CLOBBERABLE_PARAMS: Set[str] = {
    "batch_size", "micro_batch_size", "workers", "num_workers", "max_workers",
    "concurrency", "max_concurrency", "pool_size", "max_connections",
    "max_tokens", "max_context", "context_limit", "context_window", "max_chars",
    "timeout", "precision", "dtype", "use_cache", "enable_cache", "low_vram",
    "cpu_offload", "use_flash_attn", "compile_model", "pin_memory", "parallel",
    "threads",
}

CRITICAL_ENFORCEMENT_FN_RE = re.compile(
    r"^(verify|validate|check|authorize|authenticate|enforce|sanitize|encrypt|sign|rate_limit|charge|deduct)_",
    re.IGNORECASE,
)

BLOCKING_IN_ASYNC_CALLS: Tuple[str, ...] = (
    "time.sleep",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.request",
    "urllib.request.urlopen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_output",
)

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass
class Finding:
    id: str
    category: str
    severity: str
    file: str
    line: int
    end_line: int
    signal: str
    snippet: str
    rationale: str
    verify_hint: str


def is_excluded(rel_path: str, parts: Sequence[str], extra_excludes: Sequence[str]) -> bool:
    patterns = list(DEFAULT_EXCLUDES) + list(extra_excludes)
    for part in parts:
        for pat in patterns:
            if fnmatch.fnmatch(part, pat):
                return True
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat):
            return True
    return False


def is_test_path(rel_path: str) -> bool:
    lower = rel_path.replace("\\", "/").lower()
    parts = lower.split("/")
    name = parts[-1]
    if any(p in {"test", "tests", "__tests__", "spec", "specs", "e2e", "eval", "evals", "bench", "benchmarks"} for p in parts[:-1]):
        return True
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
        or name.startswith("bench_")
        or name.startswith("eval_")
    )


def is_instruction_doc(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/").lower()
    name = norm.rsplit("/", 1)[-1]
    if name in INSTRUCTION_FILENAMES:
        return True
    if ("/adr/" in f"/{norm}" or "/adrs/" in f"/{norm}") and name.endswith(".md"):
        return True
    return False


def is_build_script_path(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").lower().split("/")
    return any(p in {"scripts", "plugins", "tools", "bin", "migrations"} for p in parts[:-1])


def is_minified_text(lines: List[str]) -> bool:
    sample = [l for l in lines[:30] if l.strip()]
    if not sample:
        return False
    if any(len(l) > 2000 for l in sample):
        return True
    avg_len = sum(len(l) for l in sample) / len(sample)
    return avg_len > 300


def safe_read_text(path: Path, max_bytes: int = 2_000_000) -> Optional[str]:
    try:
        if path.stat().st_size > max_bytes:
            return None
        raw = path.read_bytes()
        if b"\x00" in raw[:4096]:
            return None
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return None


def excerpt(lines: List[str], line_no: int, radius: int = 1) -> str:
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    chunk = [f"{i + 1}: {lines[i].rstrip()}" for i in range(start, end)]
    text = "\n".join(chunk)
    return text[:400] + ("..." if len(text) > 400 else "")


def _get_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _handler_has_observability(body: List[ast.stmt]) -> bool:
    for stmt in body:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Raise):
                return True
            if isinstance(sub, ast.Call):
                cname = _get_call_name(sub.func).lower()
                if any(
                    tok in cname
                    for tok in (
                        "log", "warn", "error", "exception", "critical",
                        "print", "capture_exception", "telemetry", "metric",
                        "record_error", "audit",
                    )
                ):
                    return True
            if isinstance(sub, ast.Subscript) and isinstance(sub.slice, ast.Constant):
                if isinstance(sub.slice.value, str) and sub.slice.value.lower() in {"error", "err", "exception", "stderr"}:
                    return True
    return False


PY_AST_TEST_PREFILTER_RE = re.compile(r"(skip|skipif|xfail|assert\s+True\b|is\s+not\s+None)", re.I)
PY_AST_PROD_PREFILTER_RE = re.compile(
    r"(except\b|synchronize|\.(?:item|cpu|numpy|tolist)\(|async\s+def\b|"
    r"datetime\.(?:now|utcnow)|time\.time|uuid[14]|"
    r"claude|anthropic|gemini|google|vertex|gpt|openai|chatgpt|deepseek|llama|mistral|qwen|grok|xai|"
    r"batch_size|micro_batch_size|workers|concurrency|pool_size|max_connections|use_cache|enable_cache|low_vram|cpu_offload|"
    r"def\s+(?:verify|validate|check|authorize|authenticate|enforce|sanitize|encrypt|sign|rate_limit|charge|deduct)_)",
    re.I,
)


def _node_lines(lines: List[str], node: ast.AST) -> str:
    start = max(0, getattr(node, "lineno", 1) - 1)
    end = getattr(node, "end_lineno", start + 1)
    return "\n".join(lines[start:end])


def _is_trivial_probe_except_body(body: List[ast.stmt]) -> bool:
    if len(body) != 1:
        return False
    stmt = body[0]
    if isinstance(stmt, ast.Return):
        val = stmt.value
        if val is None:
            return True
        if isinstance(val, ast.Constant) and val.value in {None, False, "", 0}:
            return True
        if isinstance(val, (ast.List, ast.Dict, ast.Tuple, ast.Set)):
            items = val.keys if isinstance(val, ast.Dict) else val.elts
            if len(items) == 0:
                return True
    return False


# Single-pass Python AST forensics

class _PythonForensicVisitor(ast.NodeVisitor):
    def __init__(
        self,
        rel_path: str,
        lines: List[str],
        in_test: bool,
        findings: List[Finding],
        has_model_tokens: bool,
        strict: bool = False,
    ) -> None:
        self.rel_path = rel_path
        self.lines = lines
        self.in_test = in_test
        self.findings = findings
        self.has_model_tokens = has_model_tokens
        self.strict = strict
        self.loop_depth = 0
        self.async_depth = 0
        self.prompt_builder_name: Optional[str] = None
        self.in_abstract_class = False

    def add(self, cat: str, sev: str, node: ast.AST, signal: str, rationale: str, hint: str) -> None:
        ln = getattr(node, "lineno", 1)
        end_ln = getattr(node, "end_lineno", ln)
        self.findings.append(
            Finding(
                id="",
                category=cat,
                severity=sev,
                file=self.rel_path,
                line=ln,
                end_line=end_ln,
                signal=signal,
                snippet=excerpt(self.lines, ln, radius=1),
                rationale=rationale,
                verify_hint=hint,
            )
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        base_names = {_get_call_name(b).split(".")[-1] for b in node.bases}
        prev = self.in_abstract_class
        if base_names.intersection({"Protocol", "ABC", "ABCMeta", "Interface"}):
            self.in_abstract_class = True
        self.generic_visit(node)
        self.in_abstract_class = prev

    def _visit_func(self, node: ast.AST, is_async: bool) -> None:
        assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        if self.in_test:
            if node.name.startswith("test_"):
                for dec in node.decorator_list:
                    dsrc = _node_lines(self.lines, dec)
                    if re.search(r"\b(skip|skipif|xfail)\b", dsrc, re.I):
                        self.add(
                            "TEST_AND_EVAL_TAMPERING",
                            "MEDIUM",
                            dec,
                            f"Skipped/xfailed test '{node.name}'",
                            "Disabled test can hide silent regressions or dropped behavior.",
                            "Check git blame on decorator and run the test unskipped.",
                        )
                asserts = [n for n in ast.walk(node) if isinstance(n, ast.Assert)]
                if len(asserts) == 1:
                    a = asserts[0]
                    if isinstance(a.test, ast.Constant) and a.test.value is True:
                        self.add(
                            "TEST_AND_EVAL_TAMPERING",
                            "HIGH",
                            a,
                            f"Vacuous 'assert True' in '{node.name}'",
                            "Test passes trivially without checking behavior.",
                            "Run git log -L on this test to see if real assertions were removed.",
                        )
                    elif (
                        isinstance(a.test, ast.Compare)
                        and len(a.test.ops) == 1
                        and isinstance(a.test.ops[0], ast.IsNot)
                        and len(a.test.comparators) == 1
                        and isinstance(a.test.comparators[0], ast.Constant)
                        and a.test.comparators[0].value is None
                    ):
                        self.add(
                            "TEST_AND_EVAL_TAMPERING",
                            "LOW",
                            a,
                            f"Sole assertion in '{node.name}' is 'is not None'",
                            "Weak check can pass even when outputs are truncated or degraded.",
                            "Check git history to see if stronger checks were weakened.",
                        )
            return

        # Parameter / config clobbering
        param_names = {a.arg for a in node.args.args + node.args.kwonlyargs}
        watched = param_names.intersection(CLOBBERABLE_PARAMS)
        if watched:
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    target = stmt.targets[0].id
                    if target not in watched:
                        continue
                    val = stmt.value
                    if isinstance(val, ast.Constant) and (
                        val.value in {False, True, 0, 1, 2}
                        or (isinstance(val.value, str) and val.value.lower() in {"fp32", "float32", "cpu", "eager"})
                    ):
                        self.add(
                            "SILENT_FALLBACK_AND_OVERRIDE",
                            "HIGH",
                            stmt,
                            f"Unconditional override of parameter '{target}'",
                            f"Caller-supplied parameter '{target}' is silently overwritten with constant {val.value!r}.",
                            f"Trace callers passing '{target}' and compare A/B runtime behavior when honoring it.",
                        )
                    elif (
                        isinstance(val, ast.Call)
                        and isinstance(val.func, ast.Name)
                        and val.func.id == "min"
                        and any(isinstance(a, ast.Name) and a.id == target for a in val.args)
                    ):
                        self.add(
                            "SILENT_FALLBACK_AND_OVERRIDE",
                            "HIGH",
                            stmt,
                            f"Silent downward clamp on parameter '{target}'",
                            f"Caller-supplied parameter '{target}' is clamped via min(...) inside '{node.name}'.",
                            "Check if the cap matches a real hardware/API limit or silently throttles callers.",
                        )

        # Stubbed enforcement/verification functions in production code
        if CRITICAL_ENFORCEMENT_FN_RE.match(node.name) and not self.in_abstract_class:
            is_abs_dec = any("abstract" in _get_call_name(d).lower() for d in node.decorator_list)
            non_self_args = [
                a for a in (node.args.args + node.args.kwonlyargs)
                if a.arg not in {"self", "cls"}
            ]
            has_params = bool(non_self_args or node.args.vararg or node.args.kwarg)
            if not is_abs_dec and has_params:
                stmts = [
                    s for s in node.body
                    if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str))
                ]
                if len(stmts) == 1:
                    s = stmts[0]
                    is_auth_or_verify = bool(re.match(r"^(verify|authorize|authenticate|check)_", node.name, re.I))
                    is_stub = (
                        isinstance(s, ast.Pass)
                        or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is Ellipsis)
                        or (
                            isinstance(s, ast.Return)
                            and (
                                (not is_auth_or_verify and s.value is None)
                                or (isinstance(s.value, ast.Constant) and s.value.value is True)
                                or (not is_auth_or_verify and isinstance(s.value, ast.Constant) and s.value.value in {None, "", 0})
                                or (not is_auth_or_verify and isinstance(s.value, (ast.List, ast.Dict)) and len(s.value.elts if isinstance(s.value, ast.List) else s.value.keys) == 0)
                            )
                        )
                    )
                    if is_stub:
                        self.add(
                            "STUBBED_OR_MOCKED_PROD_CODE",
                            "HIGH",
                            node,
                            f"Stubbed enforcement/validation function '{node.name}' in production code",
                            "Critical verify/validate/auth/rate-limit function returns a trivial constant or no-op.",
                            "Check git log -L on this function and test whether invalid/unauthorized inputs are accepted.",
                        )

        prev_async = self.async_depth
        prev_prompt = self.prompt_builder_name
        # Nested sync def inside an async def (e.g. for asyncio.to_thread / run_in_executor)
        # does not execute on the event loop, so reset async_depth for sync defs.
        self.async_depth = (prev_async + 1) if is_async else 0
        if re.search(r"(system_?prompt|build_?prompt|make_?prompt|developer_?instruction)", node.name, re.I):
            self.prompt_builder_name = node.name
        self.generic_visit(node)
        self.async_depth = prev_async
        self.prompt_builder_name = prev_prompt

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node, is_async=True)

    def visit_For(self, node: ast.For) -> None:
        if not self.in_test:
            self.loop_depth += 1
            self.generic_visit(node)
            self.loop_depth -= 1

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        if not self.in_test:
            self.loop_depth += 1
            self.generic_visit(node)
            self.loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        if not self.in_test:
            self.loop_depth += 1
            self.generic_visit(node)
            self.loop_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if not self.in_test:
            cname = _get_call_name(node.func)
            cname_low = cname.lower()

            if self.loop_depth > 0 and isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                if attr == "synchronize" and "cuda" in cname_low:
                    self.add(
                        "ML_COMPUTE_THROTTLE",
                        "HIGH",
                        node,
                        "cuda.synchronize() inside loop",
                        "Host-device sync inside a loop breaks GPU pipeline overlap.",
                        "Profile loop with and without sync; verify if sync is actually needed per step.",
                    )
                elif attr in {"item", "cpu", "numpy", "tolist"}:
                    line_txt = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
                    if re.search(r"(loss|tensor|grad|logit|pred|embed|hidden|out|batch|step|torch)", line_txt, re.I):
                        self.add(
                            "ML_COMPUTE_THROTTLE",
                            "MEDIUM",
                            node,
                            f"Potential tensor .{attr}() sync inside loop",
                            f"Calling .{attr}() on a GPU tensor inside a loop causes synchronous D2H stalls.",
                            "Check tensor device and measure step throughput when deferred to logging steps.",
                        )

            if self.prompt_builder_name is not None:
                if any(tok in cname_low for tok in ("datetime.now", "datetime.utcnow", "time.time", "uuid4", "uuid1", "randint")):
                    self.add(
                        "CACHE_AND_COST_BLEED",
                        "HIGH",
                        node,
                        f"Volatile call '{cname_low}' inside prompt builder '{self.prompt_builder_name}'",
                        "Timestamps or UUIDs in static prompt prefixes invalidate prompt caching every turn.",
                        "Compare rendered system prompt across two calls and check prefix stability.",
                    )

            if self.async_depth > 0:
                if any(cname_low == blk or cname_low.endswith(f".{blk}") for blk in BLOCKING_IN_ASYNC_CALLS):
                    self.add(
                        "BACKEND_AND_SYSTEMS_THROTTLE",
                        "HIGH",
                        node,
                        f"Blocking sync call '{cname_low}' inside async function",
                        "Blocking calls inside async functions freeze the event loop and serialize concurrent requests.",
                        "Benchmark concurrent requests against an async replacement and verify output parity.",
                    )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if self.strict and not self.in_test:
            is_broad = node.type is None or (
                isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}
            )
            if is_broad and not _handler_has_observability(node.body) and not _is_trivial_probe_except_body(node.body):
                if any(isinstance(s, (ast.Pass, ast.Return, ast.Assign, ast.Expr)) for s in node.body):
                    self.add(
                        "SILENT_FALLBACK_AND_OVERRIDE",
                        "MEDIUM",
                        node,
                        "Broad except swallows failure without logging",
                        "Silent broad catch can mask an always-failing fast path so fallback runs 100% of calls.",
                        "Instrument the try block at runtime to verify whether the fast path succeeds or throws.",
                    )
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        if not self.in_test and self.has_model_tokens:
            test_src = _node_lines(self.lines, node.test)
            if MODEL_TOKENS_RE.search(test_src) and not NON_PY_BENIGN_COND_RE.search(test_src):
                start = max(0, node.lineno - 1)
                end = min(len(self.lines), min(getattr(node, "end_lineno", start + 1), start + 15))
                branch_head = "\n".join(self.lines[start:end])
                if NON_PY_ASYM_EFFECT_RE.search(branch_head) or re.search(r"(\[:\d+\]|guidance|system_prompt|truncat)", branch_head, re.I):
                    self.add(
                        "MODEL_ASYMMETRY",
                        "HIGH",
                        node,
                        "Model/provider-conditional branch affecting context, tools, or trace",
                        "Branch checks vendor/model name while changing context, tools, trace forwarding, or limits.",
                        "Feed identical synthetic input into each model branch and run scripts/diff_traces.py.",
                    )
        self.generic_visit(node)


def scan_python_ast(
    rel_path: str,
    source: str,
    lines: List[str],
    in_test: bool,
    findings: List[Finding],
    strict: bool = False,
) -> None:
    if in_test:
        if not PY_AST_TEST_PREFILTER_RE.search(source):
            return
        has_models = False
    else:
        if not PY_AST_PROD_PREFILTER_RE.search(source):
            return
        has_models = bool(MODEL_TOKENS_RE.search(source))
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError:
        return
    _PythonForensicVisitor(rel_path, lines, in_test, findings, has_models, strict=strict).visit(tree)


# JS/TS structural forensics (agent harnesses, MCP servers, web apps)

JS_SILENT_CATCH_RE = re.compile(r"\bcatch\s*(?:\([^)]*\))?\s*\{")
JS_LOG_OR_THROW_RE = re.compile(r"\b(console\.(error|warn|log)|logger\.|log\.|throw\b|Sentry\.|captureException|reportError)\b")
JS_PROMPT_FN_RE = re.compile(
    r"\b(?:function\s+\w*(?:system_?prompt|agent_?prompt|llm_?prompt|developer_?instructions?)\w*|"
    r"(?:build|make|create|get|format|render)(?:System|Agent|Llm)Prompt\w*\s*=)",
    re.I,
)
JS_VOLATILE_RE = re.compile(r"\b(Date\.now\(\)|new\s+Date\([^)]*\)|crypto\.randomUUID\(\)|Math\.random\(\))")
JS_TOOL_STRIP_RE = re.compile(r"\.filter\([^)]*(role\s*!==?\s*['\"]tool['\"]|type\s*!==?\s*['\"]tool_(result|use|call)['\"])", re.I)
JS_ASYNC_FN_RE = re.compile(r"\basync\s+(function\b|\([^)]*\)\s*=>|\w+\s*\()")
JS_SYNC_IO_RE = re.compile(r"\b(readFileSync|writeFileSync|appendFileSync|execSync|spawnSync|pbkdf2Sync)\s*\(")


def scan_js_ts(rel_path: str, lines: List[str], in_test: bool, findings: List[Finding], strict: bool = False) -> None:
    if in_test:
        return
    is_ui_jsx = rel_path.lower().endswith((".tsx", ".jsx"))
    is_cli_script = is_build_script_path(rel_path)

    for idx, line in enumerate(lines, start=1):
        # Blocking sync FS/child_process calls strictly inside an async function body (brace-scoped)
        if JS_ASYNC_FN_RE.search(line):
            depth = 0
            opened = False
            for offset in range(0, min(60, len(lines) - idx + 1)):
                wline = lines[idx - 1 + offset]
                if "{" in wline:
                    opened = True
                depth += wline.count("{") - wline.count("}")
                m_sync = JS_SYNC_IO_RE.search(wline)
                if m_sync and opened:
                    sev = "LOW" if is_cli_script else "HIGH"
                    findings.append(
                        Finding(
                            id="",
                            category="BACKEND_AND_SYSTEMS_THROTTLE",
                            severity=sev,
                            file=rel_path,
                            line=idx + offset,
                            end_line=idx + offset,
                            signal=f"Blocking sync call '{m_sync.group(1)}()' inside async JS/TS function",
                            snippet=excerpt(lines, idx + offset, radius=1),
                            rationale="Synchronous FS/process calls inside async handlers block the Node.js event loop.",
                            verify_hint="Benchmark concurrent handler requests using async fs/promises or child_process.",
                        )
                    )
                    break
                if opened and depth <= 0:
                    break

        # Silent catch block without logging or rethrow (--strict mode only to avoid large-repo noise)
        if strict and JS_SILENT_CATCH_RE.search(line):
            window = "\n".join(lines[idx - 1 : min(len(lines), idx + 5)])
            brace_slice = window.split("{", 1)[-1]
            block = brace_slice.split("}", 1)[0] if "}" in brace_slice else brace_slice
            if not JS_LOG_OR_THROW_RE.search(block):
                compact = re.sub(r"\s+", " ", block).strip()
                is_trivial_null_return = bool(
                    re.match(r"^return\s+(null|false|undefined|''|\"\"|\[\]|\{\})\s*;?$", compact)
                )
                if not is_trivial_null_return:
                    findings.append(
                        Finding(
                            id="",
                            category="SILENT_FALLBACK_AND_OVERRIDE",
                            severity="MEDIUM",
                            file=rel_path,
                            line=idx,
                            end_line=min(len(lines), idx + 3),
                            signal="Silent catch block without logging or rethrow",
                            snippet=excerpt(lines, idx, radius=2),
                            rationale="Silent catch blocks can hide broken fast paths or failed tool calls.",
                            verify_hint="Instrument the try block to confirm whether the primary path succeeds at runtime.",
                        )
                    )

        # Prompt cache busters in non-UI JS/TS prompt builders
        if not is_ui_jsx and JS_PROMPT_FN_RE.search(line):
            depth = 0
            opened = False
            for offset in range(0, min(30, len(lines) - idx + 1)):
                wline = lines[idx - 1 + offset]
                if "{" in wline:
                    opened = True
                depth += wline.count("{") - wline.count("}")
                m = JS_VOLATILE_RE.search(wline)
                if m:
                    findings.append(
                        Finding(
                            id="",
                            category="CACHE_AND_COST_BLEED",
                            severity="HIGH",
                            file=rel_path,
                            line=idx + offset,
                            end_line=idx + offset,
                            signal=f"Volatile call '{m.group(0)}' inside JS/TS prompt builder",
                            snippet=excerpt(lines, idx + offset, radius=1),
                            rationale="Injecting live timestamps or random IDs into static prompt prefixes defeats prompt caching.",
                            verify_hint="Compare serialized system prompt across consecutive requests for prefix stability.",
                        )
                    )
                    break
                if opened and depth <= 0:
                    break

        # Stripping tool messages/traces via .filter(...)
        if JS_TOOL_STRIP_RE.search(line):
            findings.append(
                Finding(
                    id="",
                    category="CONTEXT_TRACE_STARVATION",
                    severity="HIGH",
                    file=rel_path,
                    line=idx,
                    end_line=idx,
                    signal="Filter strips tool messages or tool results from trace",
                    snippet=excerpt(lines, idx, radius=1),
                    rationale="Dropping tool messages strips execution evidence from downstream agents or models.",
                    verify_hint="Diff pre-filter and post-filter message arrays with scripts/diff_traces.py.",
                )
            )


# Multi-language pattern scanner

LINE_RULES: List[Tuple[str, str, re.Pattern, str, str, bool]] = [
    (
        "ML_COMPUTE_THROTTLE",
        "HIGH",
        re.compile(r"\b(low_vram|medvram|med_vram)\s*[:=]\s*(True|true|1)\b"),
        "Hardcoded low-VRAM mode enabled",
        "Forces aggressive memory throttling that degrades inference/training throughput.",
        False,
    ),
    (
        "ML_COMPUTE_THROTTLE",
        "HIGH",
        re.compile(r"\b(enable_sequential_cpu_offload|enable_model_cpu_offload|offload_to_cpu\s*[:=]\s*(True|true))\b"),
        "Unconditional CPU offload enabled",
        "Shuttles model layers between CPU and GPU every forward pass.",
        False,
    ),
    (
        "ML_COMPUTE_THROTTLE",
        "HIGH",
        re.compile(r"(allow_tf32\s*=\s*False|enable_flash_sdp\s*\(\s*False|enable_mem_efficient_sdp\s*\(\s*False|TORCH_COMPILE_DISABLE|torch\.compile\([^)]*disable\s*=\s*True)"),
        "Hardware acceleration kernel explicitly disabled",
        "Disables TF32, FlashAttention/SDPA, or torch.compile unconditionally.",
        False,
    ),
    (
        "ML_COMPUTE_THROTTLE",
        "MEDIUM",
        re.compile(r"\battn_implementation\s*=\s*['\"]eager['\"]"),
        "Eager attention forced instead of SDPA/FlashAttention",
        "Eager attention increases memory usage and latency on modern GPUs.",
        False,
    ),
    (
        "ML_COMPUTE_THROTTLE",
        "MEDIUM",
        re.compile(r"\b(num_workers\s*=\s*0|pin_memory\s*=\s*False|use_cache\s*=\s*False)\b"),
        "Dataloader or KV-cache accelerator disabled",
        "Disabling dataloader workers, pinned memory, or KV cache reduces throughput.",
        False,
    ),
    (
        "ML_COMPUTE_THROTTLE",
        "MEDIUM",
        re.compile(r"(text_encoder|encoder|tokenizer|vision_tower)[^\n]{0,30}\.to\(\s*['\"]cpu['\"]\s*\)"),
        "Encoder explicitly forced to CPU",
        "Moving encoders to CPU inside training or inference paths bottlenecks steps.",
        False,
    ),
    (
        "ML_COMPUTE_THROTTLE",
        "MEDIUM",
        re.compile(r"(OMP_NUM_THREADS|MKL_NUM_THREADS)\s*[:=]\s*['\"]?1['\"]?|TOKENIZERS_PARALLELISM\s*[:=]\s*['\"]?false['\"]?", re.I),
        "CPU/tokenizer parallelism capped to single thread",
        "Single-thread cap can starve preprocessing and CPU workloads.",
        False,
    ),
    (
        "CONTEXT_TRACE_STARVATION",
        "HIGH",
        re.compile(r"(trace|traces|subagent|tool_output|tool_result|observation|history|messages|context)[^\n]{0,40}(\[:(?:[1-9]\d{1,2}|[1-4]\d{3})\]|\.slice\(\s*0\s*,\s*(?:[1-9]\d{1,2}|[1-4]\d{3})\s*\))", re.I),
        "Aggressive hardcoded slice on context/trace/tool payload",
        "Fixed small slice silently starves downstream agents or models of context.",
        False,
    ),
    (
        "CONTEXT_TRACE_STARVATION",
        "MEDIUM",
        re.compile(r"(?:=|return)\s+[^\n]{0,30}\b(messages|history|turns|traces)\s*\[\s*-(?:[1-9]|1[0-5])\s*:\s*\]"),
        "Hardcoded small tail-window drop on message/trace history",
        "Keeps only a small fixed turn count regardless of available token budget.",
        False,
    ),
    (
        "CONTEXT_TRACE_STARVATION",
        "MEDIUM",
        re.compile(r"\b(compact_threshold|compaction_threshold|compact_ratio|max_context_ratio)\s*[:=]\s*0\.[0-3]\d*\b", re.I),
        "Premature context compaction threshold (<40%)",
        "Triggers compaction well below context capacity, wasting tokens and dropping state.",
        False,
    ),
    (
        "POLICY_LAUNDERING_AND_SPEC_SUBVERSION",
        "HIGH",
        re.compile(r"\b(PROTECTED|BLOCKED|FORBIDDEN|RESTRICTED|DISALLOWED|BANNED|ETHICAL|POLICY_EXCLUDED)_(FIELDS|TRAITS|ATTRS|ATTRIBUTES|KEYS|FEATURES|PREFS|PREFERENCES|CATEGORIES)\b"),
        "Hardcoded policy/trait exclusion list in code",
        "Check whether this restriction came from an explicit human requirement or was self-authored.",
        False,
    ),
    (
        "CACHE_AND_COST_BLEED",
        "MEDIUM",
        re.compile(r"\b(time\.sleep|asyncio\.sleep)\s*\(\s*(?:0\.[5-9]\d*|[1-9]\d*(?:\.\d+)?)\s*\)"),
        "Hardcoded sleep delay (>=0.5s) in code path",
        "Fixed sleeps inside active loops or handlers can introduce artificial latency.",
        False,
    ),
    (
        "BACKEND_AND_SYSTEMS_THROTTLE",
        "HIGH",
        re.compile(r"\b(pool_size|max_connections|maxPoolSize|max_workers|concurrency|max_concurrency)\s*[:=]\s*1\b"),
        "Connection pool or worker concurrency capped to 1",
        "Hardcoding pool or worker concurrency to 1 serializes concurrent backend workloads.",
        False,
    ),
    (
        "BACKEND_AND_SYSTEMS_THROTTLE",
        "MEDIUM",
        re.compile(r"\b(keep_alive|keepAlive)\s*[:=]\s*(False|false)\b|\bminify\s*:\s*false\b|\bopt-level\s*=\s*0\b"),
        "HTTP keep-alive or production build optimization disabled",
        "Disabling connection reuse, minification, or compiler optimization degrades runtime latency.",
        False,
    ),
    (
        "SECURITY_AND_BOUNDARY_WEAKENING",
        "HIGH",
        re.compile(r"\b(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)"),
        "TLS certificate verification explicitly disabled",
        "Silently disabling TLS verification weakens transport security boundaries.",
        False,
    ),
    (
        "SECURITY_AND_BOUNDARY_WEAKENING",
        "HIGH",
        re.compile(r"\b(skip_auth|bypass_auth|disable_auth)\s*[:=]\s*(True|true)\b|\b(auth_required|require_auth|csrf_enabled|verify_signature)\s*[:=]\s*(False|false)\b|@csrf_exempt\b"),
        "Authentication, CSRF, or signature check explicitly disabled",
        "Verify whether this bypass was requested or silently introduced during an unrelated change.",
        False,
    ),
    (
        "STUBBED_OR_MOCKED_PROD_CODE",
        "MEDIUM",
        re.compile(r"(#|//)\s*(TODO:\s*implement|FIXME:\s*stub|placeholder\s+return|hardcoded\s+for\s+now|mock\s+response|dummy\s+return)", re.I),
        "Stub or mock placeholder left in production code",
        "Unimplemented stub or hardcoded mock return can silently replace real behavior.",
        False,
    ),
    (
        "TEST_AND_EVAL_TAMPERING",
        "HIGH",
        re.compile(r"\b(atol|abs_tol)\s*=\s*(0\.[0-9]+|1e-?[01]\b|[1-9]\b)|\b(rtol|rel_tol)\s*=\s*(0\.[1-9]|[1-9]\b)"),
        "Suspiciously loose numerical tolerance in test/eval",
        "Overly loose tolerance can mask precision regressions or broken outputs.",
        True,
    ),
    (
        "TEST_AND_EVAL_TAMPERING",
        "MEDIUM",
        re.compile(r"\b(test\.skip|it\.skip|describe\.skip|xit\(|xdescribe\(|continue-on-error:\s*true)\b"),
        "Skipped test or suppressed CI failure",
        "Skipped checks or error suppression can conceal regressions.",
        True,
    ),
]

DECEPTIVE_COMMENT_RE = re.compile(
    r"(#|//|/\*)\s*.*("
    r"avoid\s+oom|prevent\s+oom|for\s+stability|for\s+safety|for\s+thread\s+safety|"
    r"not\s+supported\s+by|sdk\s+does\s+not|api\s+does\s+not|kept\s+sequential|"
    r"temporary\s+workaround|disabled\s+for\s+now|safe\s+default|simplified\s+for\s+maintainability"
    r")",
    re.IGNORECASE,
)

INSTRUCTION_LAUNDERING_RE = re.compile(
    r"("
    r"default\s+to\s+blocked|blocked\s+unless|disabled\s+unless|"
    r"must\s+(strip|drop|exclude|block|remove|omit)|"
    r"protected\s+(trait|attribute|field)|"
    r"do\s+not\s+(enable|implement|include|forward|pass)|"
    r"prohibited\s+by\s+policy|ethical\s+(rule|policy|ground|constraint)|"
    r"always\s+truncate|always\s+offload|force\s+fp32|force\s+float32"
    r")",
    re.IGNORECASE,
)


DIGEST_SLICE_RE = re.compile(
    r"\b(digest|hexdigest|hash|sha\d*|md5|uuid|hex|operationid|callid|calldigest)\b[^\n]{0,40}(\.slice\(\s*0\s*,\s*\d{1,2}\s*\)|\[:\d{1,2}\])",
    re.I,
)
HTTP_TLS_CONTEXT_RE = re.compile(
    r"\b(requests|httpx|aiohttp|urllib|urlopen|session|client|http|ssl|tls|get|post|put|delete|patch|head|request|fetch)\b",
    re.I,
)
NON_PY_IF_COND_RE = re.compile(r"\bif\s*\(([^)]{1,180})\)")
NON_PY_CASE_RE = re.compile(r"\bcase\s+['\"]([^'\"]{2,40})['\"]\s*:")
NON_PY_ASYM_EFFECT_RE = re.compile(r"\b(maxTokens|max_tokens|maxChars|max_chars|truncate|slice\(\s*0|compact|compaction|handoff|strip|drop|tool_results?|tool_calls?|reasoning|thinking|temperature|contextWindow|context_window)\b", re.I)
NON_PY_BENIGN_COND_RE = re.compile(r"(AGENTS\.md|CLAUDE\.md|accounts\.google\.com|schema|error|status|version|email|account\.type)", re.I)


LINE_PROD_PREFILTER_RE = re.compile(
    r"(low_vram|medvram|med_vram|cpu_offload|offload_to_cpu|allow_tf32|flash_sdp|mem_efficient_sdp|"
    r"TORCH_COMPILE_DISABLE|torch\.compile|attn_implementation|num_workers|pin_memory|use_cache|"
    r"\.to\(|OMP_NUM_THREADS|MKL_NUM_THREADS|TOKENIZERS_PARALLELISM|\[:|\.slice\(|"
    r"compact_threshold|compaction_threshold|compact_ratio|max_context_ratio|"
    r"(?:PROTECTED|BLOCKED|FORBIDDEN|RESTRICTED|DISALLOWED|BANNED|ETHICAL|POLICY_EXCLUDED)_|"
    r"sleep\(|pool_size|max_connections|maxPoolSize|max_workers|concurrency|max_concurrency|"
    r"keep_alive|keepAlive|minify|opt-level|verify\s*=|rejectUnauthorized|InsecureSkipVerify|"
    r"NODE_TLS_REJECT_UNAUTHORIZED|skip_auth|bypass_auth|disable_auth|auth_required|require_auth|"
    r"csrf_enabled|verify_signature|csrf_exempt|TODO:\s*implement|FIXME:\s*stub|placeholder\s+return|"
    r"hardcoded\s+for\s+now|mock\s+response|dummy\s+return|"
    r"avoid\s+oom|prevent\s+oom|for\s+stability|for\s+safety|thread\s+safety|not\s+supported|"
    r"sdk\s+does\s+not|api\s+does\s+not|kept\s+sequential|temporary\s+workaround|disabled\s+for\s+now|"
    r"safe\s+default|simplified\s+for\s+maintainability|"
    r"claude|anthropic|gemini|google|vertex|gpt|openai|chatgpt|deepseek|llama|mistral|qwen|grok|xai)",
    re.I,
)
LINE_TEST_PREFILTER_RE = re.compile(r"(atol|abs_tol|rtol|rel_tol|test\.skip|it\.skip|describe\.skip|xit\(|xdescribe\(|continue-on-error)", re.I)


def scan_lines(
    rel_path: str,
    text: str,
    lines: List[str],
    in_test: bool,
    is_doc: bool,
    findings: List[Finding],
    strict: bool = False,
) -> None:
    if is_doc:
        if not INSTRUCTION_LAUNDERING_RE.search(text):
            return
        for idx, line in enumerate(lines, start=1):
            if INSTRUCTION_LAUNDERING_RE.search(line):
                findings.append(
                    Finding(
                        id="",
                        category="POLICY_LAUNDERING_AND_SPEC_SUBVERSION",
                        severity="MEDIUM",
                        file=rel_path,
                        line=idx,
                        end_line=idx,
                        signal="Restrictive policy/cap rule in agent instruction or planning doc",
                        snippet=excerpt(lines, idx, radius=1),
                        rationale="Self-authored rules in instruction/ADR docs can get enforced by later agent runs.",
                        verify_hint="Run git log -S / git blame on this line to verify human provenance.",
                    )
                )
        return

    if in_test:
        if not LINE_TEST_PREFILTER_RE.search(text):
            return
    elif not LINE_PROD_PREFILTER_RE.search(text):
        return

    def offset_to_line(pos: int) -> int:
        return text.count("\n", 0, pos) + 1

    # C-speed whole-file regex scan instead of O(lines * rules) Python loop
    for cat, sev, pat, signal, rationale, test_only in LINE_RULES:
        if test_only and not in_test:
            continue
        if not test_only and in_test:
            continue
        if not strict and cat == "CACHE_AND_COST_BLEED" and "sleep" in signal.lower():
            continue
        for m in pat.finditer(text):
            idx = offset_to_line(m.start())
            if idx > len(lines):
                continue
            line = lines[idx - 1]
            stripped = line.lstrip()
            if "re.compile(" in stripped or stripped.startswith(('r"', "r'")):
                continue
            if cat == "CONTEXT_TRACE_STARVATION" and DIGEST_SLICE_RE.search(line):
                continue
            if cat == "SECURITY_AND_BOUNDARY_WEAKENING":
                if stripped.startswith(("#", "//", "*", '"""', "'''", "description:", "summary:")):
                    continue
                if "``" in line or "`auth_required" in line:
                    continue
                if "verify=" in line.replace(" ", "").lower() and "rejectunauthorized" not in line.lower():
                    if not HTTP_TLS_CONTEXT_RE.search(line):
                        continue
            if cat == "BACKEND_AND_SYSTEMS_THROTTLE" and "ThreadPoolExecutor(" in line:
                next_window = "\n".join(lines[idx - 1 : min(len(lines), idx + 3)])
                if ".submit(" in next_window and "for " not in next_window:
                    continue
            findings.append(
                Finding(
                    id="",
                    category=cat,
                    severity=sev,
                    file=rel_path,
                    line=idx,
                    end_line=idx,
                    signal=signal,
                    snippet=excerpt(lines, idx, radius=1),
                    rationale=rationale,
                    verify_hint="Check git provenance, test counter-hypothesis, and measure A/B runtime impact.",
                )
            )

    if not in_test and not rel_path.endswith(".py"):
        for pat in (NON_PY_IF_COND_RE, NON_PY_CASE_RE):
            for m in pat.finditer(text):
                cond_text = m.group(1)
                if not (MODEL_TOKENS_RE.search(cond_text) and not NON_PY_BENIGN_COND_RE.search(cond_text)):
                    continue
                idx = offset_to_line(m.start())
                window = "\n".join(lines[max(0, idx - 1) : min(len(lines), idx + 8)])
                if NON_PY_ASYM_EFFECT_RE.search(window):
                    findings.append(
                        Finding(
                            id="",
                            category="MODEL_ASYMMETRY",
                            severity="HIGH",
                            file=rel_path,
                            line=idx,
                            end_line=min(len(lines), idx + 6),
                            signal="Model/provider-conditional branch affecting context, tools, or limits",
                            snippet=excerpt(lines, idx, radius=2),
                            rationale="Conditional branch changes context, tools, or limits based on model or provider name.",
                            verify_hint="Diff serialized payloads across each model branch with scripts/diff_traces.py.",
                        )
                    )

    if not in_test:
        for m in DECEPTIVE_COMMENT_RE.finditer(text):
            idx = offset_to_line(m.start())
            if idx > len(lines):
                continue
            stripped = lines[idx - 1].lstrip()
            if "re.compile(" in stripped or stripped.startswith(('r"', "r'")):
                continue
            window = "\n".join(lines[max(0, idx - 2) : min(len(lines), idx + 4)])
            if THROTTLE_ADJACENCY_RE.search(window):
                findings.append(
                    Finding(
                        id="",
                        category="DECEPTIVE_COMMENT_LEAD",
                        severity="MEDIUM",
                        file=rel_path,
                        line=idx,
                        end_line=min(len(lines), idx + 3),
                        signal="Defensive justification comment adjacent to throttle/cap",
                        snippet=excerpt(lines, idx, radius=2),
                        rationale="OOM/SDK/stability claims next to throttles should be checked against actual hardware and lockfiles.",
                        verify_hint="Verify the claimed constraint against installed SDK versions, memory usage, and an A/B run.",
                    )
                )


# Git history forensics

TRIVIAL_COMMIT_RE = re.compile(
    r"^\s*(docs?|typo|readme|format(ting)?|lint|style|chore|minor|cleanup|clean\s+up|"
    r"comments?|whitespace|refactor\s+naming|update\s+logging|add\s+logging)\b",
    re.IGNORECASE,
)

CRITICAL_DIFF_ADD_RE = re.compile(
    r"^\+(?!\+\+).*("
    r"low_vram|cpu_offload|allow_tf32\s*=\s*False|enable_flash_sdp\s*\(\s*False|"
    r"use_cache\s*=\s*False|num_workers\s*=\s*0|pool_size\s*[:=]\s*1\b|"
    r"max_workers\s*[:=]\s*1\b|concurrency\s*[:=]\s*1\b|minify\s*:\s*false|"
    r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|"
    r"skip_auth\s*[:=]\s*(True|true)|auth_required\s*[:=]\s*(False|false)|"
    r"PROTECTED_|BLOCKED_|FORBIDDEN_|RESTRICTED_|compact_threshold|compaction|"
    r"pytest\.mark\.skip|atol\s*=\s*0\.[1-9]"
    r")",
    re.IGNORECASE,
)

PERF_DIFF_DEL_RE = re.compile(
    r"^-(?!--).*("
    r"flash_attn|enable_flash_sdp|torch\.compile|bfloat16|bf16|float16|fp16|"
    r"allow_tf32\s*=\s*True|cache_control|pin_memory\s*=\s*True|use_cache\s*=\s*True"
    r")",
    re.IGNORECASE,
)

PERF_JUSTIFIED_MSG_RE = re.compile(
    r"\b(perf|performance|oom|memory|revert|benchmark|fp32|bf16|precision|cache|flash|compile)\b",
    re.IGNORECASE,
)


def run_git(root: Path, args: List[str]) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout
    except (OSError, subprocess.SubprocessError):
        return None


def scan_git_history(
    root: Path,
    git_depth: int,
    since_ref: Optional[str],
    findings: List[Finding],
) -> Dict[str, object]:
    meta: Dict[str, object] = {"git_available": False}
    if git_depth <= 0:
        return meta
    head = run_git(root, ["rev-parse", "--short", "HEAD"])
    if not head:
        return meta

    status = run_git(root, ["status", "--porcelain"]) or ""
    meta["git_available"] = True
    meta["head"] = head.strip()
    meta["dirty"] = bool(status.strip())

    log_args = ["log", "--no-merges", "--unified=0", "-p", "--format=__SAB_COMMIT__%H%x1f%ai%x1f%an%x1f%s%x1f%b__SAB_DIFF__"]
    if since_ref:
        if re.match(r"^\d{4}-\d{2}-\d{2}", since_ref):
            log_args.append(f"--since={since_ref}")
        else:
            log_args.append(f"{since_ref}..HEAD")
    log_args.extend(["-n", str(git_depth)])

    raw_log = run_git(root, log_args)
    if not raw_log:
        meta["commits_scanned"] = 0
        return meta

    chunks = [c for c in raw_log.split("__SAB_COMMIT__") if c.strip()]
    meta["commits_scanned"] = len(chunks)
    co_authors: Counter = Counter()

    for chunk in chunks:
        header_part, sep, diff = chunk.partition("__SAB_DIFF__")
        if not sep:
            continue
        parts = header_part.strip("\r\n").split("\x1f")
        if len(parts) < 4:
            continue
        sha, date_str, author, subject = parts[0], parts[1], parts[2], parts[3]
        body = parts[4] if len(parts) > 4 else ""
        for m in re.finditer(r"Co-Authored-By:\s*(.+)", body, re.IGNORECASE):
            co_authors[m.group(1).strip()] += 1

        if not diff.strip():
            continue

        current_file = "<git-diff>"
        current_is_code = False
        added_hits: List[Tuple[str, str]] = []
        deleted_perf: List[Tuple[str, str]] = []

        for dline in diff.splitlines():
            if dline.startswith("+++ b/"):
                current_file = dline[6:].strip()
                ext = Path(current_file).suffix.lower()
                current_is_code = (ext in CODE_EXTS) or is_instruction_doc(current_file)
                continue
            if not current_is_code:
                continue
            if is_test_path(current_file):
                if re.search(r"^\+(?!\+\+).*(pytest\.mark\.skip|atol\s*=\s*0\.[1-9]|test\.skip|it\.skip)", dline, re.I):
                    added_hits.append((current_file, dline[:200]))
                continue
            if CRITICAL_DIFF_ADD_RE.search(dline):
                added_hits.append((current_file, dline[:200]))
            if PERF_DIFF_DEL_RE.search(dline):
                deleted_perf.append((current_file, dline[:200]))

        if TRIVIAL_COMMIT_RE.search(subject) and (added_hits or deleted_perf):
            sample = (added_hits + deleted_perf)[0]
            findings.append(
                Finding(
                    id="",
                    category="GIT_STEALTH_DIFFS",
                    severity="HIGH",
                    file=sample[0],
                    line=1,
                    end_line=1,
                    signal=f"Stealth scope creep in commit {sha[:8]} ('{subject[:70]}')",
                    snippet=f"Commit {sha[:8]} ({date_str[:10]}, {author}): {subject}\nDiff sample: {sample[1]}",
                    rationale="Commit subject claims trivial work while diff adds throttles, blocklists, test skips, or deletes optimizations.",
                    verify_hint=f"Run `git show {sha[:8]}` and verify whether the runtime change was requested.",
                )
            )
        elif deleted_perf and not PERF_JUSTIFIED_MSG_RE.search(f"{subject}\n{body}"):
            sample = deleted_perf[0]
            findings.append(
                Finding(
                    id="",
                    category="GIT_STEALTH_DIFFS",
                    severity="MEDIUM",
                    file=sample[0],
                    line=1,
                    end_line=1,
                    signal=f"Undocumented optimization removal in commit {sha[:8]}",
                    snippet=f"Commit {sha[:8]} ({date_str[:10]}, {author}): {subject}\nRemoved: {sample[1]}",
                    rationale="Optimization or acceleration setting removed without explanation in commit message.",
                    verify_hint=f"Run `git show {sha[:8]}` and A/B test restoring the removed setting.",
                )
            )

    if co_authors:
        meta["co_author_trailers"] = dict(co_authors.most_common(10))
    return meta


# Reporting and CLI

def render_markdown(root: Path, files_scanned: int, git_meta: Dict[str, object], findings: List[Finding]) -> str:
    counts = Counter(f.category for f in findings)
    sev_counts = Counter(f.severity for f in findings)
    lines = [
        "# Pre-Scan Triage Report",
        "",
        f"- **Target:** `{root}`",
        f"- **UTC Timestamp:** `{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}`",
        f"- **Files Scanned:** `{files_scanned}`",
        f"- **Git HEAD:** `{git_meta.get('head', 'N/A')}` (dirty: `{git_meta.get('dirty', 'N/A')}`, commits scanned: `{git_meta.get('commits_scanned', 0)}`)",
        f"- **Total Leads:** `{len(findings)}` (`HIGH`: {sev_counts['HIGH']}, `MEDIUM`: {sev_counts['MEDIUM']}, `LOW`: {sev_counts['LOW']})",
        "",
        "> Static and git leads for Phase 2-4 investigation. "
        "Do not mark any lead as confirmed until it passes the 4-check verification gate.",
        "",
        "## Leads by Category",
        "",
        "| Category | Count |",
        "| :--- | ---: |",
    ]
    for cat, cnt in sorted(counts.items()):
        lines.append(f"| `{cat}` | {cnt} |")
    if not counts:
        lines.append("| *(none)* | 0 |")

    lines.extend(["", "## Prioritized Leads", ""])
    for f in findings:
        lines.extend(
            [
                f"### [{f.id}] `{f.severity}`: {f.signal}",
                f"- **Category:** `{f.category}`",
                f"- **Location:** `{f.file}:{f.line}`" + (f"-{f.end_line}" if f.end_line != f.line else ""),
                f"- **Rationale:** {f.rationale}",
                f"- **Next step:** {f.verify_hint}",
                "```text",
                f.snippet,
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def _ansi(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def iter_target_files(root: Path, extra_excludes: Sequence[str]) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    # Fast path inside git repos: respect .gitignore automatically via git ls-files
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=str(root),
            capture_output=True,
            timeout=15,
        )
        if proc.returncode == 0 and proc.stdout:
            patterns = list(DEFAULT_EXCLUDES) + list(extra_excludes)
            for raw in proc.stdout.split(b"\x00"):
                if not raw:
                    continue
                rel = raw.decode("utf-8", errors="replace").replace("\\", "/")
                parts = rel.split("/")
                if any(fnmatch.fnmatch(part, pat) for part in parts for pat in patterns):
                    continue
                if any(fnmatch.fnmatch(rel, pat) for pat in patterns):
                    continue
                p = root / rel
                if p.is_file():
                    yield p
            return
    except (OSError, subprocess.SubprocessError):
        pass

    patterns = list(DEFAULT_EXCLUDES) + list(extra_excludes)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        kept_dirs: List[str] = []
        for d in dirnames:
            rel_sub = d if rel_dir == "." else f"{rel_dir}/{d}"
            if any(fnmatch.fnmatch(d, pat) or fnmatch.fnmatch(rel_sub, pat) for pat in patterns):
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs
        for fn in filenames:
            yield Path(dirpath) / fn


def _scan_file_batch(batch: Tuple[List[Tuple[str, str]], bool]) -> Tuple[int, List[Finding]]:
    items, strict = batch
    local_findings: List[Finding] = []
    scanned = 0
    for fpath_str, rel in items:
        fpath = Path(fpath_str)
        is_doc = is_instruction_doc(rel)
        ext = fpath.suffix.lower()
        text = safe_read_text(fpath)
        if text is None:
            continue
        lines = text.splitlines()
        if not is_doc and is_minified_text(lines):
            continue
        scanned += 1
        in_test = is_test_path(rel)
        if ext == ".py":
            scan_python_ast(rel, text, lines, in_test, local_findings, strict=strict)
        elif ext in JS_TS_EXTS:
            scan_js_ts(rel, lines, in_test, local_findings, strict=strict)
        scan_lines(rel, text, lines, in_test, is_doc, local_findings, strict=strict)
    return scanned, local_findings


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Zero-dependency static, AST, and git pre-scanner for silent code degradation."
    )
    parser.add_argument("target", nargs="?", default=".", help="Target directory or file (default: .)")
    parser.add_argument("--json-out", help="Write JSON output to this path")
    parser.add_argument("--md-out", help="Write Markdown triage report to this path")
    parser.add_argument("--git-depth", type=int, default=100, help="Max git commits to inspect (0 to disable)")
    parser.add_argument("--since", help="Git ref or YYYY-MM-DD date to bound history scan")
    parser.add_argument("--exclude", action="append", default=[], help="Additional glob pattern to exclude")
    parser.add_argument("--categories", help="Comma-separated category filter")
    parser.add_argument("--max-findings", type=int, default=250, help="Cap emitted leads")
    parser.add_argument("--jobs", type=int, default=0, help="Worker processes for large repos (0=auto)")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Include noisier MEDIUM heuristics (broad except/silent catch blocks and non-async sleep calls)",
    )
    parser.add_argument("--fail-on-high", action="store_true", help="Exit with code 2 if HIGH leads found")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args(argv)

    root = Path(args.target).resolve()
    if not root.exists():
        print(f"Error: target path does not exist: {root}", file=sys.stderr)
        return 1

    cat_filter: Optional[Set[str]] = None
    if args.categories:
        cat_filter = {c.strip().upper() for c in args.categories.split(",") if c.strip()}

    findings: List[Finding] = []
    files_scanned = 0

    base_root = root.parent if root.is_file() else root
    candidates: List[Tuple[str, str]] = []
    for fpath in iter_target_files(root, args.exclude):
        rel = fpath.relative_to(base_root).as_posix()
        if is_excluded(rel, fpath.relative_to(base_root).parts, args.exclude):
            continue
        is_doc = is_instruction_doc(rel)
        ext = fpath.suffix.lower()
        if not is_doc and ext not in CODE_EXTS:
            continue
        candidates.append((str(fpath), rel))

    jobs = args.jobs if args.jobs > 0 else (min(8, os.cpu_count() or 1) if len(candidates) >= 400 else 1)
    if jobs > 1 and len(candidates) >= 400:
        chunk_size = max(50, (len(candidates) + jobs * 2 - 1) // (jobs * 2))
        batches = [(candidates[i : i + chunk_size], args.strict) for i in range(0, len(candidates), chunk_size)]
        with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as pool:
            for sc, flist in pool.map(_scan_file_batch, batches):
                files_scanned += sc
                findings.extend(flist)
    else:
        files_scanned, findings = _scan_file_batch((candidates, args.strict))

    git_meta = scan_git_history(base_root, args.git_depth, args.since, findings)

    seen: Set[Tuple[str, int, str, str]] = set()
    deduped: List[Finding] = []
    for f in findings:
        if cat_filter and f.category.upper() not in cat_filter:
            continue
        key = (f.file, f.line, f.category, f.signal)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)

    deduped.sort(key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.category, x.file, x.line))
    truncated = len(deduped) > args.max_findings
    deduped = deduped[: args.max_findings]
    for idx, f in enumerate(deduped, start=1):
        f.id = f"LEAD-{idx:03d}"

    payload = {
        "scanner": "sabotage-audit/forensic_scan.py",
        "utc_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": str(root),
        "files_scanned": files_scanned,
        "git": git_meta,
        "truncated": truncated,
        "summary": {
            "total_leads": len(deduped),
            "by_severity": dict(Counter(f.severity for f in deduped)),
            "by_category": dict(Counter(f.category for f in deduped)),
        },
        "leads": [asdict(f) for f in deduped],
    }

    md_report = render_markdown(root, files_scanned, git_meta, deduped)

    if args.json_out:
        out_p = Path(args.json_out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.md_out:
        out_p = Path(args.md_out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(md_report, encoding="utf-8")

    use_color = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
    sev = payload["summary"]["by_severity"]
    header = (
        f"[forensic_scan] target={root.name} files={files_scanned} "
        f"leads={len(deduped)} (HIGH={sev.get('HIGH', 0)}, MEDIUM={sev.get('MEDIUM', 0)}, LOW={sev.get('LOW', 0)})"
    )
    print(_ansi(header, "1", use_color))
    if deduped:
        sev_colors = {"HIGH": "31;1", "MEDIUM": "33", "LOW": "36"}
        for f in deduped[:25]:
            tag = _ansi(f"[{f.severity}]", sev_colors.get(f.severity, "0"), use_color)
            loc = _ansi(f"{f.file}:{f.line}", "34", use_color)
            print(f"  {f.id} {tag} ({f.category}) {loc}: {f.signal}")
        if len(deduped) > 25:
            print(f"  ... ({len(deduped) - 25} more; pass --md-out or --json-out for full list)")

    if args.fail_on_high and sev.get("HIGH", 0) > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
