"""Unit tests: normalization, secret hygiene, SQLite store."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from codeledger.ledger import (  # noqa: E402
    Store, normalize, fingerprint, shingles, similarity, redact,
)


class TestNormalize(unittest.TestCase):
    def test_comments_and_whitespace_ignored(self):
        a = "def f():\n    # comment\n    return 1\n\n\n"
        b = "def f():\n    return 1"
        self.assertEqual(normalize(a, "python"), normalize(b, "python"))
        self.assertEqual(fingerprint(a, "python"), fingerprint(b, "python"))

    def test_c_style_comments(self):
        a = "int x = 1; // note\n/* block\ncomment */int y = 2;"
        b = "int x = 1;\nint y = 2;"
        self.assertEqual(normalize(a), normalize(b))

    def test_sql_dashes(self):
        self.assertEqual(normalize("SELECT 1 -- tail\n", "sql"), "SELECT 1")

    def test_hash_inside_string_preserved(self):
        self.assertIn("# keep", normalize('x = "# keep"', "python"))

    def test_url_in_string_preserved(self):
        self.assertIn("https://x", normalize('u = "https://x.y"', "javascript"))

    def test_token_change_changes_fingerprint(self):
        self.assertNotEqual(fingerprint("a = 1", "python"), fingerprint("a = 2", "python"))

    def test_similarity_bands(self):
        base = "def fetch(url):\n    r = requests.get(url)\n    return r.json()"
        self.assertEqual(similarity(shingles(base), shingles(base + "\n# note")), 1.0)
        variant = "def fetch(url):\n    r = requests.get(url, timeout=5)\n    return r.json()"
        self.assertGreater(similarity(shingles(base), shingles(variant)), 0.3)
        other = "class Widget:\n    def paint(self, canvas):\n        canvas.clear()"
        self.assertLess(similarity(shingles(base), shingles(other)), 0.2)


class TestRedact(unittest.TestCase):
    def test_aws_key(self):
        out, kinds = redact('key = "AKIAIOSFODNN7EXAMPLE"')
        self.assertIn("aws_access_key", kinds)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)

    def test_github_token(self):
        tok = "ghp_" + "A" * 36
        out, kinds = redact(f"t = '{tok}'")
        self.assertIn("github_token", kinds)
        self.assertNotIn(tok, out)

    def test_private_key_block(self):
        out, kinds = redact("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END-----")
        self.assertIn("private_key_block", kinds)
        self.assertNotIn("PRIVATE KEY-----\nabc", out)

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
        out, kinds = redact(f"Authorization: Bearer {jwt}")
        self.assertIn("jwt", kinds)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", out)

    def test_generic_credential_assignment(self):
        out, kinds = redact('password = "hunter2hunter2"')
        self.assertIn("credential_assignment", kinds)
        self.assertNotIn("hunter2hunter2", out)

    def test_placeholders_ignored(self):
        for snippet in ('api_key = "your-key-here"', 'token = "XXXXXXXXXXXX"',
                        'password = "${DB_PASSWORD}"', 'secret = "changeme"',
                        'api_key = "sk-proj-example"'):
            _, kinds = redact(snippet)
            self.assertEqual(kinds, [], snippet)

    def test_non_secret_literal_ignored(self):
        _, kinds = redact("token = 'token'")
        self.assertEqual(kinds, [])


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "l.db"))

    def tearDown(self):
        self.store.conn.close()
        self.tmp.cleanup()

    def test_insert_get_update(self):
        eid = self.store.insert(title="t", code="x=1", norm_hash="h1")
        e = self.store.get(eid)
        self.assertEqual(e["state"], "probation")
        self.assertEqual(e["scope"], "project")
        self.store.update(eid, confidence=0.9)
        updated = self.store.get(eid)
        self.assertEqual(updated["confidence"], 0.9)
        self.assertEqual(updated["created_at"], e["created_at"])  # creation is immutable

    def test_events_append_only_and_ordered(self):
        self.store.add_event(1, "created", actor="t", new_state="probation")
        self.store.add_event(1, "promoted", actor="t", prev_state="probation", new_state="proven")
        self.assertEqual([e["action"] for e in self.store.events(1)], ["created", "promoted"])

    def test_links_and_rewrite(self):
        self.store.link(1, 2, "n")
        self.assertEqual(len(self.store.links_from(1)), 1)
        self.assertEqual(len(self.store.links_to(2)), 1)
        self.store.rewrite_links(1, 3)
        self.assertEqual(self.store.links_from(1), [])
        self.assertEqual(len(self.store.links_from(3)), 1)

    def test_find_by_hash_prefers_project_scope(self):
        self.store.insert(title="g", code="c", norm_hash="fp", scope="global")
        self.store.insert(title="p", code="c", norm_hash="fp", scope="project", project="proj")
        self.assertEqual(self.store.find_by_hash("fp", "proj")["scope"], "project")

    def test_text_search_fts_and_like_fallback(self):
        self.store.insert(title="aiohttp session reuse", code="s = aiohttp.ClientSession()", norm_hash="h1")
        self.assertIn(1, self.store.text_search(["aiohttp"]))
        self.assertEqual(self.store.text_search(["zzzzz"]), {})
        fallback = Store(os.path.join(self.tmp.name, "l2.db"), use_fts=False)
        try:
            self.assertFalse(fallback.fts)
            fallback.insert(title="aiohttp session reuse", code="s = aiohttp.ClientSession()", norm_hash="h1")
            self.assertIn(1, fallback.text_search(["aiohttp"]))
        finally:
            fallback.conn.close()

    def test_insert_with_event_is_one_transaction(self):
        eid = self.store.insert(
            event={"action": "created", "actor": "t", "new_state": "probation",
                   "new_confidence": 0.3},
            title="t", code="c", norm_hash="h1")
        self.assertIsNotNone(self.store.get(eid))
        evs = self.store.events(eid)
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["action"], "created")
        self.assertEqual(evs[0]["new_confidence"], 0.3)

    def test_stats(self):
        self.store.insert(title="t", code="c", norm_hash="h")
        st = self.store.stats()
        self.assertEqual(st["total"], 1)
        self.assertEqual(st["by_state"]["probation"], 1)
        self.assertEqual(st["events"], 0)


if __name__ == "__main__":
    unittest.main()
