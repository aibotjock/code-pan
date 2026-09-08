"""End-to-end: the codepan CLI as a real subprocess."""
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODEPAN = os.path.join(ROOT, "codepan")

BAD = "import requests\ndef fetch(url):\n    return requests.get(url).json()\n"
GOOD = "import aiohttp\nasync def fetch(u, s):\n    async with s.get(u) as r:\n        return await r.json()\n"


def run(db, *argv, stdin=None, cwd=None, project="cliproj"):
    env = dict(os.environ)
    env.update({"CODELEDGER_DB": str(db), "CODELEDGER_ACTOR": "cli-tester",
                "PYTHONIOENCODING": "utf-8"})
    if project:
        env["CODELEDGER_PROJECT"] = project
    else:
        env.pop("CODELEDGER_PROJECT", None)
    return subprocess.run([sys.executable, CODEPAN, *argv], input=stdin,
                          capture_output=True, text=True, env=env,
                          cwd=cwd or ROOT, timeout=60)


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "ledger.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_fail_check_link_flow(self):
        r = run(self.db, "fail", "--reason", "no pooling; timeouts",
                "--signature", "TimeoutError", "--evidence", "test=regression suite",
                stdin=BAD)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("QUARANTINED", r.stdout)

        r = run(self.db, "check", stdin=BAD)
        self.assertEqual(r.returncode, 1)
        self.assertIn("BLOCK", r.stdout)

        r = run(self.db, "ok", "--title", "aiohttp pooled fetch",
                "--evidence", "test=42 passed", stdin=GOOD)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("PROVEN", r.stdout)

        r = run(self.db, "link", "1", "--replacement-id", "2", "--note", "pooled sessions")
        self.assertIn("linked", r.stdout)

        r = run(self.db, "check", stdin=BAD)
        self.assertIn("use instead", r.stdout)

    def test_file_and_snippet_inputs(self):
        path = os.path.join(self.tmp.name, "good.py")
        with open(path, "w") as fh:
            fh.write(GOOD)
        r = run(self.db, "ok", path, "--evidence", "test=ok")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run(self.db, "check", "def unique(xs): return sorted(set(xs))")
        self.assertIn("no significant matches", r.stdout)

    def test_secret_refusal_exits_2(self):
        r = run(self.db, "ok", "--evidence", "test=x",
                stdin='KEY = "AKIAIOSFODNN7EXAMPLE"\nprint(1)\n')
        self.assertEqual(r.returncode, 2)
        self.assertIn("allow_redact", r.stderr)

    def test_exp_explain_and_search(self):
        run(self.db, "fail", "--reason", "r", "--evidence", "test=t", stdin=BAD)
        r = run(self.db, "exp", "fetch", "url")
        self.assertIn("Known failures", r.stdout)
        r = run(self.db, "explain", "1")
        self.assertIn("history:", r.stdout)
        self.assertIn("cli-tester", r.stdout)
        r = run(self.db, "search", "fetch", "--state", "quarantined")
        self.assertIn("QUARANTINED", r.stdout)

    def test_maintain_conf_and_reactivate(self):
        run(self.db, "fail", "--reason", "r", "--evidence", "test=t", stdin=BAD)
        r = run(self.db, "maintain", "--dry-run")
        self.assertIn("stats:", r.stdout)
        r = run(self.db, "conf", "1", "--delta", "0.2", "--reason", "re-confirmed by hand")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run(self.db, "reactivate", "1", "--reason", "requests 2.32 fixed pooling")
        self.assertIn("PROBATION", r.stdout)

    def test_project_defaults_to_cwd(self):
        workdir = os.path.join(self.tmp.name, "somerepo")
        os.makedirs(workdir)
        r = run(self.db, "exp", "anything", project=None, cwd=workdir)
        self.assertIn("somerepo-", r.stdout)  # <dirname>-<hash> scope

    def test_no_input_is_usage_error(self):
        r = run(self.db, "check", stdin=None)
        self.assertEqual(r.returncode, 2)
        self.assertIn("no input", r.stderr)


if __name__ == "__main__":
    unittest.main()
