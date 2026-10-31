"""Orchestration/receipt checks; child commands are harmless Python processes."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import run_host_regressions as runner


class HostRunnerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="openjk-host-runner-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def group(self, name, code):
        return {"id": name, "name": name, "sanitizers": [],
                "commands": [[sys.executable, "-c", code]]}

    def execute(self, groups, setup=lambda: {}, timeout=10):
        return runner.execute_groups(groups, self.root / "results", os.environ.copy(),
                                     self.root, setup, {"commit": "synthetic"}, timeout=timeout)

    def test_failure_retains_logs_and_marks_remaining_groups_not_run(self):
        receipt = self.execute([
            self.group("before", "print('first group passed')"),
            self.group("pixel-unpack-gl", "import sys; print('before failure'); print('diagnostic', file=sys.stderr); sys.exit(7)"),
            self.group("after", "raise AssertionError('must not run')"),
        ])
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual([row["status"] for row in receipt["groups"]], ["passed", "failed", "not_run"])
        self.assertEqual(receipt["groups"][1]["commands"][0]["exit_code"], 7)
        self.assertEqual(json.loads((self.root / "results/summary.json").read_text()), receipt)
        self.assertIn("before failure", (self.root / "results/logs/pixel-unpack-gl.stdout.txt").read_text())
        self.assertIn("diagnostic", (self.root / "results/logs/pixel-unpack-gl.stderr.txt").read_text())
        with patch.object(runner, "provenance", return_value={"commit": "synthetic"}):
            runner.collect_evidence(self.root / "results", self.root / "evidence", job_status="failure")
        manifest = json.loads((self.root / "evidence/manifest.json").read_text())
        self.assertEqual(manifest["host_status"], "failed")
        self.assertIn("host/logs/pixel-unpack-gl.stderr.txt", manifest["files"])

    def test_setup_failure_does_not_pass_or_launch_a_group(self):
        def fail_setup():
            raise FileNotFoundError("compiler unavailable")
        receipt = self.execute([self.group("before", "raise AssertionError('must not run')")], fail_setup)
        self.assertEqual(receipt["status"], "setup_failed")
        self.assertEqual(receipt["groups"][0]["status"], "not_run")
        self.assertIn("compiler unavailable", receipt["error"])

    def test_command_timeout_is_reported(self):
        receipt = self.execute([self.group("before", "import time; time.sleep(30)")], timeout=0.1)
        self.assertEqual(receipt["status"], "timeout")
        self.assertLess(receipt["duration_seconds"], 5)

    def test_allowlist_excludes_binaries_images_archives_and_raw_patches(self):
        host = self.root / "results"
        source = self.root / "source"
        host.mkdir()
        source.mkdir()
        (host / "summary.json").write_text('{"status": "not_run"}\n')
        (host / "pixels.ppm").write_bytes(b"P6\n1 1\n255\n\x00\x00\x00")
        for name in ("engine.exe", "library.dll", "evaluation.zip", "SUBMODULE_WORKTREES_AFTER_BUILD.txt"):
            (source / name).write_bytes(b"do not publish")
        (source / "host-orchestration.stdout.txt").write_text("synthetic orchestration record\n")
        with patch.object(runner, "provenance", return_value={}):
            runner.collect_evidence(host, self.root / "evidence", source_records=source)
        files = {path.relative_to(self.root / "evidence").as_posix()
                 for path in (self.root / "evidence").rglob("*") if path.is_file()}
        self.assertEqual(files, {"host/summary.json", "source/host-orchestration.stdout.txt", "manifest.json", "summary.txt"})
        manifest = json.loads((self.root / "evidence/manifest.json").read_text())
        self.assertEqual(manifest["host_status"], "not_run")

    def test_allowlisted_binary_or_symlink_is_rejected(self):
        host = self.root / "results"
        host.mkdir()
        suspect = host / "summary.json"
        suspect.write_bytes(b"MZ\x00fake executable")
        with patch.object(runner, "provenance", return_value={}):
            with self.assertRaises(ValueError):
                runner.collect_evidence(host, self.root / "binary-evidence")
            suspect.unlink()
            target = self.root / "elsewhere.json"
            target.write_text("{}\n")
            suspect.symlink_to(target)
            with self.assertRaises(ValueError):
                runner.collect_evidence(host, self.root / "symlink-evidence")


if __name__ == "__main__":
    unittest.main(verbosity=2)
