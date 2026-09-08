"""End-to-end: drive the real server process over stdio JSON-RPC."""
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
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
        # A reader thread feeding a queue: select() on the fd would race with
        # the buffered text wrapper (responses queued in userspace -> false
        # timeout -> every later recv shifts by one).
        self._lines = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(None)  # EOF sentinel

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def raw(self, line):
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def raw_bytes(self, data: bytes):
        self.proc.stdin.buffer.write(data)
        self.proc.stdin.buffer.flush()

    def recv(self, timeout=15):
        line = self._lines.get(timeout=timeout)  # TimeoutError if silent
        if line is None:
            raise TimeoutError("server closed stdout")
        return json.loads(line)

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


class TestHostileInputs(unittest.TestCase):
    """One hostile line must never kill the transport (round-1 critic findings)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.srv = ServerProc(os.path.join(cls.tmp.name, "l.db"))
        cls.srv.send({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                      "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "hostile", "version": "1"}}})
        cls.srv.recv()
        cls.srv.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()
        cls.srv.proc.stderr.read()  # drain so pipes close cleanly
        cls.tmp.cleanup()

    def test_initialize_with_string_params_gets_32602_and_survives(self):
        self.srv.send({"jsonrpc": "2.0", "id": 30, "method": "initialize", "params": "x"})
        r = self.srv.recv()
        self.assertEqual(r["error"]["code"], -32602)
        self.srv.send({"jsonrpc": "2.0", "id": 31, "method": "ping"})
        self.assertEqual(self.srv.recv()["result"], {})

    def test_initialize_with_list_params_and_junk_clientinfo_survives(self):
        self.srv.send({"jsonrpc": "2.0", "id": 32, "method": "initialize",
                       "params": ["a", 1, {"clientInfo": {"name": "x"}}]})
        self.assertEqual(self.srv.recv()["error"]["code"], -32602)
        self.srv.send({"jsonrpc": "2.0", "id": 33, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "clientInfo": "nope"}})
        self.assertIn("serverInfo", self.srv.recv()["result"])
        self.srv.send({"jsonrpc": "2.0", "id": 34, "method": "ping"})
        self.assertEqual(self.srv.recv()["result"], {})

    def test_invalid_utf8_bytes_then_ping(self):
        self.srv.raw_bytes(b'\xff\xfe garbage \x80\n' +
                           b'{"jsonrpc":"2.0","id":35,"method":"ping"}\n')
        self.assertEqual(self.srv.recv()["error"]["code"], -32700)
        r = self.srv.recv()
        self.assertEqual(r["id"], 35)
        self.assertEqual(r["result"], {})

    def test_oversized_message_answered_and_server_keeps_serving(self):
        big = ('{"jsonrpc":"2.0","id":36,"method":"ping","params":{"pad":"'
               + "A" * (10 * 1024 * 1024 + 64) + '"}}')
        self.srv.send(big)
        r = self.srv.recv()
        self.assertEqual(r["error"]["code"], -32600)
        self.assertIn("too large", r["error"]["message"])
        self.srv.send({"jsonrpc": "2.0", "id": 37, "method": "ping"})
        self.assertEqual(self.srv.recv()["result"], {})

    def test_readonly_annotations_advertised(self):
        self.srv.send({"jsonrpc": "2.0", "id": 38, "method": "tools/list"})
        tools = {t["name"]: t for t in self.srv.recv()["result"]["tools"]}
        for reader in ("check_code", "get_experience", "search", "explain"):
            self.assertTrue(tools[reader].get("annotations", {}).get("readOnlyHint"), reader)
        self.assertNotIn("readOnlyHint",
                         tools["record_failure"].get("annotations", {}))

    def test_notification_with_junk_params_is_silently_dropped(self):
        self.srv.send({"jsonrpc": "2.0", "method": "notifications/initialized",
                       "params": "garbage"})
        self.srv.send({"jsonrpc": "2.0", "id": 39, "method": "ping"})
        self.assertEqual(self.srv.recv()["id"], 39)

    def test_latest_protocol_version_echoed_and_unknown_downgrades(self):
        self.srv.send({"jsonrpc": "2.0", "id": 41, "method": "initialize",
                       "params": {"protocolVersion": "2025-11-25", "capabilities": {}}})
        self.assertEqual(self.srv.recv()["result"]["protocolVersion"], "2025-11-25")
        self.srv.send({"jsonrpc": "2.0", "id": 42, "method": "initialize",
                       "params": {"protocolVersion": "2099-01-01", "capabilities": {}}})
        self.assertEqual(self.srv.recv()["result"]["protocolVersion"], "2025-06-18")


if __name__ == "__main__":
    unittest.main()
