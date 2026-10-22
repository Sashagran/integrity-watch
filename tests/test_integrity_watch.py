import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from integrity_watch.core import (BaselineError, Policy, build_baseline, compare, generate_key, load_baseline,
                                  load_key, save_baseline, scan)

ROOT = Path(__file__).resolve().parents[1]


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.tree = self.tmp / "tree"
        (self.tree / "etc" / "ssh").mkdir(parents=True)
        (self.tree / "usr" / "bin").mkdir(parents=True)
        (self.tree / "etc" / "ssh" / "sshd_config").write_text("PermitRootLogin no\n")
        tool = self.tree / "usr" / "bin" / "tool"
        tool.write_text("#!/bin/sh\necho ok\n")
        tool.chmod(0o755)
        (self.tree / "usr" / "bin" / "link").symlink_to("tool")
        self.key_path = self.tmp / "key"
        generate_key(self.key_path)
        self.key = load_key(self.key_path)
        self.policy = Policy(paths=[str(self.tree)], exclude=["*.swp"])
        self.baseline = self.tmp / "baseline.json"

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def snapshot(self):
        records, _ = scan(self.policy)
        save_baseline(build_baseline(records, self.policy, self.key), self.baseline)
        return records

    def changes(self):
        old, _ = load_baseline(self.baseline, self.key)
        new, _ = scan(self.policy)
        return {(c.kind, Path(c.path).name, c.severity) for c in compare(old, new)}


class ScanTests(Fixture):
    def test_scan_records_files_and_symlinks(self):
        records, errors = scan(self.policy)
        self.assertEqual(errors, [])
        types = {Path(p).name: r.type for p, r in records.items()}
        self.assertEqual(types, {"sshd_config": "file", "tool": "file", "link": "symlink"})

    def test_exclude_patterns(self):
        (self.tree / "etc" / "x.swp").write_text("tmp")
        records, _ = scan(self.policy)
        self.assertFalse(any(p.endswith(".swp") for p in records))

    def test_algorithms(self):
        for algo, length in [("sha256", 64), ("sha512", 128), ("blake2b", 128), ("sha3_256", 64)]:
            records, _ = scan(Policy(paths=[str(self.tree)], algorithm=algo))
            self.assertTrue(all(len(r.digest) == length for r in records.values() if r.type == "file"), algo)

    def test_unknown_algorithm_rejected(self):
        with self.assertRaises(ValueError):
            Policy(paths=["/"], algorithm="md5")


class CompareTests(Fixture):
    def test_no_changes(self):
        self.snapshot()
        self.assertEqual(self.changes(), set())

    def test_content_change_detected(self):
        self.snapshot()
        (self.tree / "etc" / "ssh" / "sshd_config").write_text("PermitRootLogin yes\n")
        self.assertIn(("modified", "sshd_config", "high"), self.changes())

    def test_mtime_only_change_is_ignored(self):
        self.snapshot()
        os.utime(self.tree / "usr" / "bin" / "tool", (1, 1))
        self.assertEqual(self.changes(), set())

    def test_new_suid_file_is_critical(self):
        self.snapshot()
        p = self.tree / "usr" / "bin" / ".backdoor"
        p.write_text("x")
        p.chmod(0o4755)
        self.assertIn(("added", ".backdoor", "critical"), self.changes())

    def test_world_writable_permission_change(self):
        self.snapshot()
        (self.tree / "usr" / "bin" / "tool").chmod(0o777)
        self.assertIn(("permissions", "tool", "high"), self.changes())

    def test_removed_and_symlink_retarget(self):
        self.snapshot()
        (self.tree / "etc" / "ssh" / "sshd_config").unlink()
        link = self.tree / "usr" / "bin" / "link"
        link.unlink()
        link.symlink_to("/bin/sh")
        kinds = {(k, n) for k, n, _ in self.changes()}
        self.assertIn(("removed", "sshd_config"), kinds)
        self.assertIn(("symlink", "link"), kinds)


class BaselineSecurityTests(Fixture):
    def test_tampered_baseline_rejected(self):
        self.snapshot()
        data = json.loads(self.baseline.read_text())
        path = next(iter(data["payload"]["files"]))
        data["payload"]["files"][path]["digest"] = "0" * 64  # attacker "blesses" a modified file
        self.baseline.write_text(json.dumps(data))
        with self.assertRaisesRegex(BaselineError, "INVALID"):
            load_baseline(self.baseline, self.key)

    def test_wrong_key_rejected(self):
        self.snapshot()
        other = self.tmp / "other.key"
        generate_key(other)
        with self.assertRaises(BaselineError):
            load_baseline(self.baseline, load_key(other))

    def test_baseline_file_permissions(self):
        self.snapshot()
        self.assertEqual(self.baseline.stat().st_mode & 0o777, 0o600)

    def test_insecure_key_permissions_rejected(self):
        self.key_path.chmod(0o644)
        with self.assertRaisesRegex(BaselineError, "chmod 600"):
            load_key(self.key_path)

    def test_short_key_rejected(self):
        k = self.tmp / "short"
        k.write_text("abc")
        k.chmod(0o600)
        with self.assertRaises(BaselineError):
            load_key(k)


class CliTests(Fixture):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "integrity_watch", *args], capture_output=True, text=True, cwd=ROOT)

    def test_exit_codes(self):
        k, b = str(self.key_path), str(self.baseline)
        self.assertEqual(self.run_cli("init", "--key", k, "--baseline", b, str(self.tree)).returncode, 0)
        self.assertEqual(self.run_cli("check", "--key", k, "--baseline", b).returncode, 0)

        (self.tree / "usr" / "bin" / "tool").write_text("evil")
        proc = self.run_cli("check", "--key", k, "--baseline", b, "--format", "json")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout)["status"], "changed")

        self.assertEqual(self.run_cli("update", "--key", k, "--baseline", b, "--yes").returncode, 0)
        self.assertEqual(self.run_cli("check", "--key", k, "--baseline", b).returncode, 0)

        self.baseline.write_text(self.baseline.read_text().replace('"size": ', '"size": 1'))
        self.assertEqual(self.run_cli("check", "--key", k, "--baseline", b).returncode, 2)


if __name__ == "__main__":
    unittest.main()
