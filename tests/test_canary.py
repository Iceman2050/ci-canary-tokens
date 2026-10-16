"""Tests for ci-canary-tokens: generator format, registry matching, tripwire."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)
from canary import (  # noqa: E402
    generate_value, prefix_of, sha256_hex, register_canary,
    load_registry, check_blob,
)


class GeneratorTest(unittest.TestCase):
    def test_aws_canary_shape_matches_aws_key_id(self):
        for _ in range(20):
            v = generate_value("aws")
            self.assertRegex(v, r"^AKIA[0-9A-Z]{16}$")
            self.assertIn("CANARY", v, "canary marker missing from AWS key")
            self.assertEqual(len(v), 20)

    def test_token_canary_shape(self):
        for _ in range(20):
            v = generate_value("token")
            self.assertTrue(v.startswith("ing_canary_"))
            self.assertEqual(len(v), len("ing_canary_") + 32)

    def test_generated_values_are_unique(self):
        vals = {generate_value("aws") for _ in range(100)}
        self.assertEqual(len(vals), 100)

    def test_registry_stores_prefix_and_hash_never_plaintext(self):
        with tempfile.TemporaryDirectory() as d:
            reg = os.path.join(d, "registry.json")
            value = register_canary(reg, "ci-aws-1", "aws")
            with open(reg) as fh:
                raw = fh.read()
            self.assertNotIn(value, raw, "plaintext leaked into registry!")
            data = json.loads(raw)
            entry = data["canaries"][0]
            self.assertEqual(entry["name"], "ci-aws-1")
            self.assertEqual(entry["prefix"], prefix_of("aws"))
            self.assertEqual(entry["sha256"], sha256_hex(value))
            self.assertIn("created", entry)

    def test_cli_generate_registers_and_prints_once(self):
        with tempfile.TemporaryDirectory() as d:
            reg = os.path.join(d, "registry.json")
            proc = subprocess.run(
                [sys.executable, os.path.join(SRC, "canary.py"), "generate",
                 "--name", "n1", "--kind", "token", "--registry", reg],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("ing_canary_", proc.stdout)
            self.assertEqual(len(load_registry(reg)["canaries"]), 1)


class TripwireTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reg = os.path.join(self.tmp.name, "registry.json")
        self.aws_value = register_canary(self.reg, "ci-aws-canary-1", "aws")
        self.token_value = register_canary(self.reg, "ci-token-canary-1", "token")

    def tearDown(self):
        self.tmp.cleanup()

    def test_exfil_blob_with_canary_fires(self):
        # Simulated GhostAction-style exfiltration blob
        blob = ("stolen secrets dump:\n"
                f"AWS_ACCESS_KEY_ID={self.aws_value}\n"
                f"AWS_SECRET_ACCESS_KEY=fake-secret-not-tracked\n")
        fired = check_blob(self.reg, blob, source="workflow-log.txt")
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0]["name"], "ci-aws-canary-1")
        self.assertEqual(fired[0]["source"], "workflow-log.txt")

    def test_token_canary_fires(self):
        blob = f"leaked: API_TOKEN={self.token_value}"
        fired = check_blob(self.reg, blob, source="artifact.txt")
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0]["name"], "ci-token-canary-1")

    def test_clean_blob_stays_clean(self):
        blob = "build succeeded\ntests passed\nno secrets here: AKIAREALKEY12345678"
        self.assertEqual(check_blob(self.reg, blob, source="log.txt"), [])

    def test_prefix_only_match_fires_without_full_value(self):
        # Tripwire matches on prefix, so even a redacted/truncated leak fires
        blob = f"key id starts with {prefix_of('aws')}..."
        fired = check_blob(self.reg, blob, source="log.txt")
        self.assertTrue(fired)

    def test_cli_check_exit_codes(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(f"exfil: {self.aws_value}")
            dirty = fh.name
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("nothing to see here")
            clean = fh.name
        try:
            dirty_proc = subprocess.run(
                [sys.executable, os.path.join(SRC, "canary.py"), "check",
                 "--registry", self.reg, "--blob", dirty],
                capture_output=True, text=True)
            self.assertEqual(dirty_proc.returncode, 1)
            self.assertIn("ci-aws-canary-1", dirty_proc.stdout)

            clean_proc = subprocess.run(
                [sys.executable, os.path.join(SRC, "canary.py"), "check",
                 "--registry", self.reg, "--blob", clean],
                capture_output=True, text=True)
            self.assertEqual(clean_proc.returncode, 0)
        finally:
            os.unlink(dirty)
            os.unlink(clean)


if __name__ == "__main__":
    unittest.main(verbosity=2)
