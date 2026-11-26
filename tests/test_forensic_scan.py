import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER = REPO_ROOT / "scripts" / "forensic_scan.py"
VERIFIER = REPO_ROOT / "scripts" / "verify_equivalence.py"
TRACER = REPO_ROOT / "scripts" / "diff_traces.py"


class TestForensicScan(unittest.TestCase):
    def _run_scanner(self, target: Path, *extra_args: str) -> dict:
        with tempfile.TemporaryDirectory() as out_dir:
            json_out = Path(out_dir) / "scan.json"
            proc = subprocess.run(
                [sys.executable, str(SCANNER), str(target), "--json-out", str(json_out), "--no-color", *extra_args],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertIn(proc.returncode, (0, 2), msg=f"Scanner failed: {proc.stderr}")
            return json.loads(json_out.read_text(encoding="utf-8"))

    def test_detects_all_major_sabotage_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            (root / "train.py").write_text(
                "\n".join(
                    [
                        "import time",
                        "def run_training(batch_size=64, use_cache=True):",
                        "    # Avoid OOM on consumer hardware",
                        "    low_vram = True",
                        "    batch_size = min(batch_size, 2)",
                        "    use_cache = False",
                        "    for step in range(10):",
                        "        torch.cuda.synchronize()",
                        "        val = loss_tensor.item()",
                        "        time.sleep(0.1)",
                        "    try:",
                        "        return fast_kernel()",
                        "    except Exception:",
                        "        return slow_fallback()",
                    ]
                ),
                encoding="utf-8",
            )

            (root / "router.py").write_text(
                "\n".join(
                    [
                        "from datetime import datetime",
                        "PROTECTED_FIELDS = {'tier_a', 'tier_b'}",
                        "def build_system_prompt():",
                        "    return f'Now: {datetime.now().isoformat()}'",
                        "def forward_subagent(model_name, traces):",
                        "    if 'gemini' in model_name.lower():",
                        "        return traces[:1000]",
                        "    return traces",
                    ]
                ),
                encoding="utf-8",
            )

            (root / "AGENTS.md").write_text(
                "# Rules\nDefault to blocked on advanced ranking attributes unless leadership approves.\n",
                encoding="utf-8",
            )

            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_eval.py").write_text(
                "\n".join(
                    [
                        "import pytest",
                        "@pytest.mark.skip(reason='flaky')",
                        "def test_critical_parity():",
                        "    assert abs(1.0 - 0.5) < 1.0  # atol=0.5",
                        "def test_vacuous():",
                        "    assert True",
                    ]
                ),
                encoding="utf-8",
            )

            data = self._run_scanner(root, "--git-depth", "0")
            cats = set(data["summary"]["by_category"].keys())

            self.assertIn("ML_COMPUTE_THROTTLE", cats)
            self.assertIn("SILENT_FALLBACK_AND_OVERRIDE", cats)
            self.assertIn("MODEL_ASYMMETRY", cats)
            self.assertIn("CONTEXT_TRACE_STARVATION", cats)
            self.assertIn("CACHE_AND_COST_BLEED", cats)
            self.assertIn("POLICY_LAUNDERING_AND_SPEC_SUBVERSION", cats)
            self.assertIn("TEST_AND_EVAL_TAMPERING", cats)
            self.assertIn("DECEPTIVE_COMMENT_LEAD", cats)

    def test_detects_js_ts_harness_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent.ts").write_text(
                "\n".join(
                    [
                        "export function buildSystemPrompt() {",
                        "  return `Time: ${new Date().toISOString()} You are helpful.`;",
                        "}",
                        "export function handoff(model: string, messages: any[]) {",
                        "  try { return fastSerialize(messages); } catch (e) { return slowSerialize(messages); }",
                        "}",
                        "export function trim(model: string, messages: any[]) {",
                        "  if (model.includes('gemini')) {",
                        "    return messages.filter((m) => m.role !== 'tool').slice(0, 500);",
                        "  }",
                        "  return messages;",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            data = self._run_scanner(root, "--git-depth", "0", "--strict")
            cats = set(data["summary"]["by_category"].keys())
            self.assertIn("CACHE_AND_COST_BLEED", cats)
            self.assertIn("SILENT_FALLBACK_AND_OVERRIDE", cats)
            self.assertIn("CONTEXT_TRACE_STARVATION", cats)
            self.assertIn("MODEL_ASYMMETRY", cats)

    def test_strict_gates_noisy_medium_heuristics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "worker.py").write_text(
                "\n".join(
                    [
                        "import time",
                        "def poll():",
                        "    time.sleep(1.5)",
                        "    try:",
                        "        return fast_call()",
                        "    except Exception:",
                        "        return fallback_call()",
                    ]
                ),
                encoding="utf-8",
            )
            default_data = self._run_scanner(root, "--git-depth", "0")
            strict_data = self._run_scanner(root, "--git-depth", "0", "--strict")
            self.assertEqual(default_data["summary"]["total_leads"], 0)
            self.assertGreaterEqual(strict_data["summary"]["total_leads"], 2)

    def test_clean_codebase_produces_zero_leads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "\n".join(
                    [
                        "import asyncio, logging, urllib.request",
                        "from typing import Protocol",
                        "logger = logging.getLogger(__name__)",
                        "class AuthBackend(Protocol):",
                        "    def verify_token(self, token: str) -> bool: ...",
                        "def check_plugin_requirements() -> bool:",
                        "    return True",
                        "async def fetch_off_loop(url: str) -> bytes:",
                        "    def _sync_get() -> bytes:",
                        "        with urllib.request.urlopen(url, timeout=5) as r:",
                        "            return r.read()",
                        "    return await asyncio.to_thread(_sync_get)",
                        "def compute_sum(items: list[int]) -> int:",
                        "    try:",
                        "        return sum(items)",
                        "    except TypeError as exc:",
                        "        logger.exception('Invalid input: %s', exc)",
                        "        raise",
                    ]
                ),
                encoding="utf-8",
            )
            data = self._run_scanner(root, "--git-depth", "0")
            self.assertEqual(data["summary"]["total_leads"], 0)

    def test_git_stealth_diff_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Dev"], cwd=root, check=True)

            (root / "engine.py").write_text("use_cache = True\nallow_tf32 = True\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "feat: initial engine"], cwd=root, check=True, capture_output=True)

            (root / "engine.py").write_text("use_cache = False\nallow_tf32 = False\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-m", "docs: fix minor typo in comments"],
                cwd=root,
                check=True,
                capture_output=True,
            )

            data = self._run_scanner(root, "--git-depth", "10")
            cats = set(data["summary"]["by_category"].keys())
            self.assertIn("GIT_STEALTH_DIFFS", cats)

    def test_detects_non_ml_backend_web_and_security_sabotage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api.py").write_text(
                "\n".join(
                    [
                        "import requests",
                        "pool_size = 1",
                        "async def fetch_profile(url: str):",
                        "    return requests.get(url, verify=False).json()",
                        "def verify_webhook_signature(payload: bytes, sig: str) -> bool:",
                        "    return True",
                        "def compute_invoice(order_id: str):",
                        "    # TODO: implement real tax calculation",
                        "    return {'total': 0}",
                    ]
                ),
                encoding="utf-8",
            )
            (root / "server.ts").write_text(
                "\n".join(
                    [
                        "import fs from 'fs';",
                        "const config = { rejectUnauthorized: false, skip_auth: true, keepAlive: false };",
                        "export async function handleDownload(path: string) {",
                        "  return fs.readFileSync(path, 'utf8');",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            data = self._run_scanner(root, "--git-depth", "0")
            cats = set(data["summary"]["by_category"].keys())
            self.assertIn("BACKEND_AND_SYSTEMS_THROTTLE", cats)
            self.assertIn("STUBBED_OR_MOCKED_PROD_CODE", cats)
            self.assertIn("SECURITY_AND_BOUNDARY_WEAKENING", cats)

    def test_git_stealth_diff_catches_security_downgrade(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Dev"], cwd=root, check=True)

            (root / "client.py").write_text("resp = session.get(url, verify=True)\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "feat: add client"], cwd=root, check=True, capture_output=True)

            (root / "client.py").write_text("resp = session.get(url, verify=False)\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-m", "chore: minor formatting cleanup"],
                cwd=root,
                check=True,
                capture_output=True,
            )

            data = self._run_scanner(root, "--git-depth", "10")
            cats = set(data["summary"]["by_category"].keys())
            self.assertIn("GIT_STEALTH_DIFFS", cats)

    def test_demo_fixture_surfaces_planted_leads(self) -> None:
        data = self._run_scanner(REPO_ROOT / "demo", "--git-depth", "0")
        cats = set(data["summary"]["by_category"].keys())
        self.assertGreaterEqual(data["summary"]["total_leads"], 5)
        self.assertIn("ML_COMPUTE_THROTTLE", cats)
        self.assertIn("MODEL_ASYMMETRY", cats)
        self.assertIn("POLICY_LAUNDERING_AND_SPEC_SUBVERSION", cats)


class TestVerifyEquivalence(unittest.TestCase):
    def test_exact_equivalence_and_speedup_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            slow = root / "slow.py"
            fast = root / "fast.py"
            json_out = root / "receipt.json"

            slow.write_text("import time; time.sleep(0.03); print('result=42')\n", encoding="utf-8")
            fast.write_text("print('result=42')\n", encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(VERIFIER),
                    "--baseline",
                    f'"{sys.executable}" "{slow}"',
                    "--candidate",
                    f'"{sys.executable}" "{fast}"',
                    "--mode",
                    "exact",
                    "--warmup",
                    "1",
                    "--runs",
                    "4",
                    "--json-out",
                    str(json_out),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            receipt = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertTrue(receipt["equivalence"]["passed"])
            self.assertTrue(receipt["equivalence"]["bit_exact"])
            self.assertGreater(receipt["comparison"]["speedup_x"], 1.0)

    def test_float_equivalence_pass_and_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = root / "a.py"
            b_ok = root / "b_ok.py"
            b_bad = root / "b_bad.py"

            a.write_text('import json; print(json.dumps({"logits": [1.0, 2.0, 3.0]}))\n', encoding="utf-8")
            b_ok.write_text('import json; print(json.dumps({"logits": [1.000001, 1.999999, 3.0]}))\n', encoding="utf-8")
            b_bad.write_text('import json; print(json.dumps({"logits": [1.5, 2.0, 3.0]}))\n', encoding="utf-8")

            ok_proc = subprocess.run(
                [
                    sys.executable,
                    str(VERIFIER),
                    "--baseline",
                    f'"{sys.executable}" "{a}"',
                    "--candidate",
                    f'"{sys.executable}" "{b_ok}"',
                    "--mode",
                    "float",
                    "--atol",
                    "1e-4",
                    "--warmup",
                    "0",
                    "--runs",
                    "2",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(ok_proc.returncode, 0, msg=ok_proc.stderr)

            bad_proc = subprocess.run(
                [
                    sys.executable,
                    str(VERIFIER),
                    "--baseline",
                    f'"{sys.executable}" "{a}"',
                    "--candidate",
                    f'"{sys.executable}" "{b_bad}"',
                    "--mode",
                    "float",
                    "--atol",
                    "1e-4",
                    "--warmup",
                    "0",
                    "--runs",
                    "2",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(bad_proc.returncode, 2)


class TestDiffTraces(unittest.TestCase):
    def test_message_trace_asymmetry_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = root / "a.json"
            b = root / "b.json"
            out = root / "diff.json"

            a.write_text(
                json.dumps(
                    [
                        {"role": "system", "content": "System prompt"},
                        {"role": "assistant", "content": "Checking", "tool_calls": [{"id": "1", "name": "read"}]},
                        {"role": "tool", "content": "full output " * 50},
                    ]
                ),
                encoding="utf-8",
            )
            b.write_text(
                json.dumps([{"role": "system", "content": "System prompt"}]),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [sys.executable, str(TRACER), str(a), str(b), "--json-out", str(out), "--fail-on-diff"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            res = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(res["asymmetry_detected"])
            self.assertEqual(res["retention_pct"]["tool_results"], 0.0)

    def test_record_collateral_loss_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rec_in = root / "in.json"
            rec_out = root / "out.json"
            diff_out = root / "diff.json"

            rec_in.write_text(
                json.dumps(
                    [
                        {"sku": "1", "brand": "Northwind", "warranty": 24, "notes": "New"},
                        {"sku": "2", "brand": "Fabrikam", "warranty": 12, "notes": "Refurbished"},
                    ]
                ),
                encoding="utf-8",
            )
            rec_out.write_text(
                json.dumps([{"sku": "1", "brand": "Northwind", "warranty": 24, "notes": "New"}]),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TRACER),
                    str(rec_in),
                    str(rec_out),
                    "--mode",
                    "records",
                    "--id-key",
                    "sku",
                    "--json-out",
                    str(diff_out),
                    "--fail-on-diff",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            res = json.loads(diff_out.read_text(encoding="utf-8"))
            self.assertEqual(res["dropped_records"], 1)
            self.assertEqual(res["fields_lost_counts"]["brand"], 1)
            self.assertEqual(res["fields_lost_counts"]["warranty"], 1)


if __name__ == "__main__":
    unittest.main()
