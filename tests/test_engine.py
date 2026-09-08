"""Unit tests: state machine guards, evidence rules, secret refusal, maintenance."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from codeledger import engine  # noqa: E402
from codeledger.engine import ToolError  # noqa: E402
from codeledger.ledger import Store  # noqa: E402

BAD_CODE = (
    "import requests\n"
    "def fetch_all(url):\n"
    "    r = requests.get(url)\n"
    "    r.raise_for_status()\n"
    "    return r.json()\n"
)
GOOD_CODE = (
    "import aiohttp\n"
    "async def fetch_all(url, session):\n"
    "    async with session.get(url) as resp:\n"
    "        resp.raise_for_status()\n"
    "        return await resp.json()\n"
)
UNRELATED = "def sort_unique(xs):\n    return sorted(set(xs))\n"


def ctx_for(store, project="proj"):
    return {"store": store, "actor": "tester", "project": project, "db_path": store.db_path}


def backdate(store, entry_id, ts="2020-01-01T00:00:00+00:00"):
    store.conn.execute(
        "UPDATE entries SET created_at = ?, last_verified_at = NULL WHERE id = ?", (ts, entry_id)
    )
    store.conn.commit()


class EngineBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "l.db"))
        self.ctx = ctx_for(self.store)

    def tearDown(self):
        self.store.conn.close()
        self.tmp.cleanup()


class TestRecordSuccess(EngineBase):
    def test_objective_evidence_creates_proven(self):
        out = engine.record_success(self.ctx, {
            "code": GOOD_CODE, "language": "python", "title": "aiohttp fetch",
            "evidence": [{"type": "test", "detail": "pytest: 12 passed"}]})
        self.assertIn("PROVEN", out)
        e = self.store.get(1)
        self.assertEqual(e["state"], "proven")
        self.assertAlmostEqual(e["confidence"], 0.65)
        self.assertEqual(e["success_count"], 1)

    def test_opinion_only_creates_probation(self):
        out = engine.record_success(self.ctx, {
            "code": GOOD_CODE, "evidence": [{"type": "agent_opinion"}]})
        self.assertIn("PROBATION", out)
        self.assertEqual(self.store.get(1)["state"], "probation")

    def test_objective_evidence_promotes_probation(self):
        engine.record_success(self.ctx, {"code": GOOD_CODE, "evidence": [{"type": "agent_opinion"}]})
        engine.record_success(self.ctx, {"code": GOOD_CODE, "evidence": [{"type": "lint"}]})
        self.assertEqual(self.store.get(1)["state"], "proven")
        self.assertIn("promoted", [ev["action"] for ev in self.store.events(1)])

    def test_repeated_successes_accumulate_capped(self):
        for _ in range(5):
            engine.record_success(self.ctx, {"code": GOOD_CODE, "evidence": [{"type": "test"}]})
        e = self.store.get(1)
        self.assertEqual(e["success_count"], 5)
        self.assertLessEqual(e["confidence"], 0.95)
        self.assertEqual(e["id"], 1)  # deduped by fingerprint, not duplicated

    def test_conflicting_success_on_quarantined(self):
        engine.record_failure(self.ctx, {"code": BAD_CODE, "reason": "timeouts",
                                         "evidence": [{"type": "test"}]})
        before = self.store.get(1)["confidence"]
        out = engine.record_success(self.ctx, {"code": BAD_CODE, "evidence": [{"type": "test"}]})
        e = self.store.get(1)
        self.assertEqual(e["state"], "quarantined")  # never auto-un-quarantined
        self.assertLess(e["confidence"], before)
        self.assertIn("reactivate", out)

    def test_human_reject_rejected_in_success(self):
        with self.assertRaises(ToolError):
            engine.record_success(self.ctx, {"code": GOOD_CODE,
                                             "evidence": [{"type": "human_reject"}]})


class TestRecordFailure(EngineBase):
    def test_opinion_only_stays_probation(self):
        out = engine.record_failure(self.ctx, {"code": BAD_CODE, "reason": "looks fragile",
                                               "evidence": [{"type": "agent_opinion"}]})
        self.assertIn("PROBATION", out)
        self.assertEqual(self.store.get(1)["state"], "probation")

    def test_objective_failure_quarantines(self):
        engine.record_failure(self.ctx, {
            "code": BAD_CODE, "reason": "timeouts under load", "signature": "TimeoutError",
            "evidence": [{"type": "regression_test"}]})
        e = self.store.get(1)
        self.assertEqual(e["state"], "quarantined")
        self.assertAlmostEqual(e["confidence"], 0.70)
        self.assertEqual(e["failure_signature"], "TimeoutError")

    def test_human_reject_quarantines_harder(self):
        engine.record_failure(self.ctx, {
            "code": BAD_CODE, "reason": "user rejected approach",
            "evidence": [{"type": "human_reject"}]})
        self.assertAlmostEqual(self.store.get(1)["confidence"], 0.85)

    def test_failure_on_proven_auto_quarantines(self):
        engine.record_success(self.ctx, {"code": GOOD_CODE, "evidence": [{"type": "test"}]})
        engine.record_failure(self.ctx, {"code": GOOD_CODE, "reason": "regression",
                                         "evidence": [{"type": "test"}]})
        e = self.store.get(1)
        self.assertEqual(e["state"], "quarantined")
        ev = [x for x in self.store.events(1) if x["action"] == "auto_quarantined"]
        self.assertEqual(ev[0]["prev_state"], "proven")

    def test_failure_on_quarantined_reinforces(self):
        engine.record_failure(self.ctx, {"code": BAD_CODE, "reason": "r1", "evidence": [{"type": "test"}]})
        engine.record_failure(self.ctx, {"code": BAD_CODE, "reason": "r2", "evidence": [{"type": "test"}]})
        e = self.store.get(1)
        self.assertEqual(e["state"], "quarantined")
        self.assertAlmostEqual(e["confidence"], 0.75)
        self.assertEqual(e["failure_count"], 2)

    def test_reason_required(self):
        with self.assertRaises(ToolError):
            engine.record_failure(self.ctx, {"code": BAD_CODE, "evidence": [{"type": "test"}]})

    def test_failure_with_replacement_links(self):
        out = engine.record_failure(self.ctx, {
            "code": BAD_CODE, "reason": "timeouts", "evidence": [{"type": "test"}],
            "replacement_code": GOOD_CODE, "replacement_title": "aiohttp fetch",
            "replacement_evidence": [{"type": "test", "detail": "12 passed"}]})
        self.assertIn("linked", out)
        links = self.store.links_from(1)
        self.assertEqual(len(links), 1)
        self.assertEqual(self.store.get(links[0]["replacement_id"])["state"], "proven")


class TestCheckAndGetExperience(EngineBase):
    def setUp(self):
        super().setUp()
        engine.record_failure(self.ctx, {
            "code": BAD_CODE, "reason": "connection storms; no pooling", "signature": "TimeoutError",
            "env": {"os": "macos", "python": "3.12"}, "evidence": [{"type": "test"}],
            "replacement_code": GOOD_CODE, "replacement_title": "aiohttp pooled fetch",
            "replacement_evidence": [{"type": "test"}]})
        engine.record_success(self.ctx, {"code": UNRELATED, "evidence": [{"type": "test"}]})

    def test_strong_match_blocks(self):
        out = engine.check_code(self.ctx, {"code": BAD_CODE + "# reformatted\n", "language": "python"})
        self.assertIn("BLOCK", out)
        self.assertIn("use instead", out)

    def test_env_conflict_weakens_warning(self):
        out = engine.check_code(self.ctx, {"code": BAD_CODE, "env": {"os": "linux"}})
        self.assertNotIn("BLOCK", out)
        self.assertIn("env differs", out)

    def test_proven_reuse_candidate(self):
        out = engine.check_code(self.ctx, {"code": UNRELATED})
        self.assertIn("reuse candidate", out)

    def test_no_match(self):
        out = engine.check_code(self.ctx, {"code": "const q = new Queue();" + "x" * 3})
        self.assertIn("no significant matches", out)

    def test_get_experience_shows_both_sides(self):
        out = engine.get_experience(self.ctx, {"query": "requests fetch url"})
        self.assertIn("Known failures", out)
        self.assertIn("repaired by", out)
        out2 = engine.get_experience(self.ctx, {"query": "sort unique dedupe"})
        self.assertIn("Proven patterns", out2)

    def test_search_state_filter(self):
        self.assertIn("QUARANTINED", engine.search(self.ctx, {"query": "requests", "state": "quarantined"}))
        self.assertIn("no matches", engine.search(self.ctx, {"query": "requests", "state": "proven"}))


class TestLifecycle(EngineBase):
    def test_promote_requires_objective_evidence(self):
        engine.record_success(self.ctx, {"code": GOOD_CODE, "evidence": [{"type": "agent_opinion"}]})
        with self.assertRaises(ToolError):
            engine.promote(self.ctx, {"entry_id": 1, "reason": "looks fine"})
        engine.record_success(self.ctx, {"code": GOOD_CODE, "evidence": [{"type": "test"}]})
        out = engine.promote(self.ctx, {"entry_id": 1, "reason": "tests green"})
        self.assertIn("proven", out.lower())

    def test_promote_to_global_gates(self):
        for _ in range(2):
            engine.record_success(self.ctx, {"code": GOOD_CODE, "evidence": [{"type": "test"}]})
        with self.assertRaises(ToolError):
            engine.promote(self.ctx, {"entry_id": 1, "reason": "r", "to_global": True})
        engine.record_success(self.ctx, {"code": GOOD_CODE, "evidence": [{"type": "test"}]})
        out = engine.promote(self.ctx, {"entry_id": 1, "reason": "confirmed in 2 repos", "to_global": True})
        self.assertIn("GLOBAL", out)
        # visible from another project
        other = ctx_for(self.store, "other-proj")
        self.assertIn("aiohttp", engine.search(other, {"query": "aiohttp", "state": "proven"})
                      or engine.search(other, {"query": "fetch", "state": "proven"}))

    def test_quarantine_requires_objective_grounds(self):
        engine.record_success(self.ctx, {"code": GOOD_CODE, "evidence": [{"type": "agent_opinion"}]})
        with self.assertRaises(ToolError):
            engine.quarantine(self.ctx, {"entry_id": 1, "reason": "don't like it"})
        out = engine.quarantine(self.ctx, {"entry_id": 1, "reason": "user rejected",
                                           "evidence": [{"type": "human_reject"}]})
        self.assertIn("QUARANTINED", out)

    def test_reactivate_preserves_history_and_requires_fresh_evidence(self):
        engine.record_failure(self.ctx, {"code": BAD_CODE, "reason": "timeout", "evidence": [{"type": "test"}]})
        out = engine.reactivate(self.ctx, {"entry_id": 1, "reason": "requests 2.32 fixed pooling"})
        self.assertIn("PROBATION", out)
        e = self.store.get(1)
        self.assertEqual(e["state"], "probation")
        self.assertAlmostEqual(e["confidence"], 0.30)
        actions = [ev["action"] for ev in self.store.events(1)]
        self.assertIn("created", actions)
        self.assertIn("reactivated", actions)  # history preserved
        engine.record_success(self.ctx, {"code": BAD_CODE, "evidence": [{"type": "test"}]})
        self.assertEqual(self.store.get(1)["state"], "proven")

    def test_update_confidence_bounds(self):
        engine.record_success(self.ctx, {"code": GOOD_CODE, "evidence": [{"type": "test"}]})
        with self.assertRaises(ToolError):
            engine.update_confidence(self.ctx, {"entry_id": 1, "delta": 0.6, "reason": "too much"})
        engine.update_confidence(self.ctx, {"entry_id": 1, "value": 1.5, "reason": "human blessed it"})
        self.assertEqual(self.store.get(1)["confidence"], 1.0)

    def test_explain_shows_history(self):
        engine.record_failure(self.ctx, {"code": BAD_CODE, "reason": "x", "evidence": [{"type": "test"}]})
        engine.reactivate(self.ctx, {"entry_id": 1, "reason": "dep upgraded"})
        out = engine.explain(self.ctx, {"entry_id": 1})
        self.assertIn("history:", out)
        self.assertIn("reactivated", out)
        self.assertIn("by tester", out)


class TestSecrets(EngineBase):
    def test_refuses_to_store_secrets(self):
        leaky = 'import requests\nAPI_KEY = "sk-ant-api03-1234567890abcdef1234"\n' + BAD_CODE
        with self.assertRaises(ToolError) as cm:
            engine.record_failure(self.ctx, {"code": leaky, "reason": "r", "evidence": [{"type": "test"}]})
        self.assertIn("allow_redact", str(cm.exception))

    def test_allow_redact_stores_sanitized(self):
        leaky = 'password = "hunter2hunter2"\n' + BAD_CODE
        engine.record_failure(self.ctx, {"code": leaky, "reason": "r",
                                         "evidence": [{"type": "test"}], "allow_redact": True})
        dump = json.dumps([dict(r) for r in self.store.conn.execute("SELECT * FROM entries").fetchall()])
        self.assertNotIn("hunter2hunter2", dump)
        self.assertIn("REDACTED", dump)

    def test_evidence_detail_sanitized(self):
        engine.record_success(self.ctx, {
            "code": GOOD_CODE,
            "evidence": [{"type": "human_confirm", "detail": 'key AKIAIOSFODNN7EXAMPLE ok'}]})
        dump = json.dumps([dict(r) for r in self.store.conn.execute("SELECT * FROM entries").fetchall()])
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", dump)


class TestMaintain(EngineBase):
    def test_decay_and_stale_demotion(self):
        engine.record_success(self.ctx, {"code": GOOD_CODE, "evidence": [{"type": "test"}]})
        backdate(self.store, 1)
        out = engine.maintain(self.ctx, {})
        self.assertIn("decay #1", out)
        e = self.store.get(1)
        self.assertAlmostEqual(e["confidence"], 0.35)
        self.assertEqual(e["state"], "probation")  # 0.35 < 0.45 demotes stale proven
        self.assertIn("decay", [ev["action"] for ev in self.store.events(1)])

    def test_archive_stale_low_value_probation(self):
        # two opinion-only failures: probation, no successes, confidence 0.20
        for i in range(2):
            engine.record_failure(self.ctx, {"code": GOOD_CODE, "reason": f"meh {i}",
                                             "evidence": [{"type": "agent_opinion"}]})
        self.assertLess(self.store.get(1)["confidence"], 0.25)
        backdate(self.store, 1)
        engine.maintain(self.ctx, {})
        self.assertEqual(self.store.get(1)["archived"], 1)

    def test_merge_exact_duplicates(self):
        engine.record_failure(self.ctx, {"code": BAD_CODE, "reason": "a", "evidence": [{"type": "test"}]})
        self.store.insert(title="dup", code=BAD_CODE, norm_hash=self.store.get(1)["norm_hash"],
                          scope="project", project="proj", state="quarantined",
                          confidence=0.5, success_count=1, failure_count=2)
        engine.maintain(self.ctx, {})
        dup = self.store.get(2)
        keep = self.store.get(1)
        self.assertEqual(dup["archived"], 1)
        self.assertEqual(dup["superseded_by"], 1)
        self.assertEqual(keep["failure_count"], 3)
        self.assertEqual(keep["success_count"], 1)

    def test_dry_run_changes_nothing(self):
        engine.record_success(self.ctx, {"code": GOOD_CODE, "evidence": [{"type": "test"}]})
        backdate(self.store, 1)
        out = engine.maintain(self.ctx, {"dry_run": True})
        self.assertIn("dry-run", out)
        self.assertAlmostEqual(self.store.get(1)["confidence"], 0.65)

    def test_stats_line(self):
        out = engine.maintain(self.ctx, {})
        self.assertIn("stats:", out)
        self.assertIn("db", out)


class TestConcurrency(unittest.TestCase):
    """Two real writer processes on one DB: no lost writes, no crashes (critic scenario)."""

    def test_two_processes_no_lost_writes(self):
        import subprocess
        tmp = tempfile.TemporaryDirectory()
        try:
            db = os.path.join(tmp.name, "c.db")
            writer = os.path.join(tmp.name, "w.py")
            with open(writer, "w") as fh:
                fh.write(
                    "import sys\n"
                    f"sys.path.insert(0, {os.path.dirname(os.path.dirname(os.path.abspath(__file__)))!r})\n"
                    "from codeledger.ledger import Store\n"
                    "from codeledger import engine\n"
                    f"db = {db!r}\n"
                    "s = Store(db)\n"
                    "ctx = {'store': s, 'actor': 'writer', 'project': 'p', 'db_path': db}\n"
                    "tag = sys.argv[1]\n"
                    "for i in range(25):\n"
                    "    engine.record_success(ctx, {'code': f'def {tag}_{i}(): return {i}',\n"
                    "                                'evidence': [{'type': 'test'}]})\n"
                )
            env = dict(os.environ, PYTHONIOENCODING="utf-8")
            procs = [subprocess.Popen([sys.executable, writer, tag], env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                     for tag in ("a", "b")]
            for p in procs:
                _, err = p.communicate(timeout=120)
                self.assertEqual(p.returncode, 0, err.decode()[:400])
            store = Store(db)
            try:
                st = store.stats()
                self.assertEqual(st["total"], 50)
                self.assertGreaterEqual(st["events"], 50)
            finally:
                store.conn.close()
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
