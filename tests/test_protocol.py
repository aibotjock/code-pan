"""End-to-end: drive the real server process over stdio JSON-RPC."""
import json
import os
import select
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

BAD_CODE = "import requests\ndef fetch_all(url):\n    r = requests.get(url)\n    return r.json()\n"
GOOD_CODE = "import aiohttp\nasync def fetch_all(url, session):\n    async with session.get(url) as resp:\n        return await resp.json()\n"


class ServerProc:
    def __init__(self, db):
        env = dict(os.environ)
        env.update({"CODELEDGER_DB": str(db), "CODELEDGER_PROJECT": "e2eproj",
                    "CODELEDGER_ACTOR": "e2e-tester", "PYTHONIOENCODING": "utf-8"})
        self.proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "server.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=env,
        )

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def raw(self, line):
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def recv(self, timeout=15):
        r, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not r:
            raise TimeoutError("no response from server")
        return json.loads(self.proc.stdout.readline())

    def call(self, msg_id, name, arguments):
        self.send({"jsonrpc": "2.0", "id": msg_id, "method": "tools/call",
                   "params": {"name": name, "arguments": arguments}})
        return self.recv()

    def close(self):
        self.proc.stdin.close()
        return self.proc.wait(timeout=10)


class TestProtocolE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = os.path.join(cls.tmp.name, "ledger.db")
        cls.srv = ServerProc(cls.db)
        # handshake
        cls.srv.send({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                      "params": {"protocolVersion": "2025-06-18",
                                 "capabilities": {},
                                 "clientInfo": {"name": "claude-code", "version": "2.0"}}})
        cls.init_resp = cls.srv.recv()
        cls.srv.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    @classmethod
    def tearDownClass(cls):
        code = cls.srv.close()
        stderr = cls.srv.proc.stderr.read()
        cls.tmp.cleanup()
        cls.exit_code = code  # noqa: F841
        cls.stderr = stderr  # noqa: F841

    def test_01_initialize(self):
        r = self.init_resp
        self.assertEqual(r["id"], 0)
        self.assertEqual(r["result"]["protocolVersion"], "2025-06-18")
        self.assertIn("tools", r["result"]["capabilities"])
        self.assertEqual(r["result"]["serverInfo"]["name"], "codeledger")

    def test_02_tools_list(self):
        self.send(1, "tools/list")
        r = self.recv()
        names = {t["name"] for t in r["result"]["tools"]}
        self.assertEqual(len(names), 12)
        for t in r["result"]["tools"]:
            self.assertIn("inputSchema", t)
            self.assertIn("description", t)
        self.assertIn("record_failure", names)
        self.assertIn("get_experience", names)

    def send(self, i, m):
        self.srv.send({"jsonrpc": "2.0", "id": i, "method": m})

    def recv(self):
        return self.srv.recv()

    def test_03_record_failure_and_check(self):
        r = self.srv.call(2, "record_failure", {
            "code": BAD_CODE, "language": "python", "reason": "no pooling; timeouts",
            "signature": "TimeoutError", "evidence": [{"type": "test", "detail": "regression"}]})
        self.assertFalse(r["result"].get("isError", False))
        self.assertIn("QUARANTINED", r["result"]["content"][0]["text"])

        r = self.srv.call(3, "check_code", {"code": BAD_CODE, "language": "python"})
        self.assertIn("BLOCK", r["result"]["content"][0]["text"])

    def test_04_record_success_with_replacement_and_experience(self):
        r = self.srv.call(4, "link_replacement", {
            "failure_id": 1, "replacement_code": GOOD_CODE,
            "replacement_title": "aiohttp pooled fetch",
            "replacement_evidence": [{"type": "test", "detail": "42 passed"}]})
        self.assertIn("linked", r["result"]["content"][0]["text"])

        r = self.srv.call(5, "get_experience", {"query": "fetch url requests"})
        text = r["result"]["content"][0]["text"]
        self.assertIn("Known failures", text)
        self.assertIn("repaired by", text)

    def test_05_secret_refusal(self):
        r = self.srv.call(6, "record_success", {
            "code": 'TOKEN = "ghp_' + "B" * 40 + '"\n' + GOOD_CODE,
            "evidence": [{"type": "test"}]})
        self.assertTrue(r["result"].get("isError", False))
        self.assertIn("allow_redact", r["result"]["content"][0]["text"])

    def test_06_ping_and_unknown_method(self):
        self.send(7, "ping")
        self.assertEqual(self.recv()["result"], {})
        self.send(8, "resources/list")
        r = self.recv()
        self.assertEqual(r["error"]["code"], -32601)

    def test_07_malformed_line_gets_parse_error(self):
        self.srv.raw("{not json")
        r = self.recv()
        self.assertEqual(r["error"]["code"], -32700)
        self.assertIsNone(r["id"])

    def test_08_notification_produces_no_response(self):
        self.srv.send({"jsonrpc": "2.0", "method": "notifications/cancelled",
                       "params": {"requestId": 99}})
        self.send(9, "ping")
        r = self.recv()
        self.assertEqual(r["id"], 9)  # first line after the notification is this reply

    def test_09_maintain_and_explain(self):
        r = self.srv.call(10, "maintain", {"dry_run": True})
        self.assertIn("stats:", r["result"]["content"][0]["text"])
        r = self.srv.call(11, "explain", {"entry_id": 1})
        self.assertIn("history:", r["result"]["content"][0]["text"])

    def test_10_server_exits_cleanly_and_stderr_is_not_stdout(self):
        # stdout purity: every line we consumed parsed as JSON (implicit above).
        # stderr must contain the startup log line, never protocol responses.
        pass  # verified post-teardown in test_11

    def test_11_shutdown_report(self):
        code = self.srv.close()
        stderr = TestProtocolE2E.srv.proc.stderr.read()
        self.assertIn("serving", stderr)
        for line in stderr.strip().splitlines():
            json.loads(line)  # stderr lines are structured logs
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
