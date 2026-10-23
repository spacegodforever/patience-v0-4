import asyncio, json, os, sys, tempfile, threading, unittest
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SRC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC))
from engine import Patience
from llm_oracle import LLMOracle, parse_assessment, AssessmentValidationError
from executor import ExecutionRefused
from audit_log import verify
from agent_daemon import TriggerAgent
from trigger_worker import TriggerWorker

GOOD = {"relevance": .7, "urgency": .4, "uncertainty": .2, "consequence": .3, "opportunity": .5,
        "confidence": .8, "evidence": ["model saw it"], "assumptions": [], "unknowns": [],
        "competing_explanations": ["a", "b"]}


class MockLLM(BaseHTTPRequestHandler):
    reply = json.dumps(GOOD); status = 200; seen = []
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        MockLLM.seen.append((self.path, self.headers.get("Authorization"), body.get("model")))
        out = json.dumps({"choices": [{"message": {"content": MockLLM.reply}}]}).encode()
        self.send_response(MockLLM.status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass


class Base(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory(); self.addCleanup(d.cleanup)
        self.root = Path(d.name); self.state = self.root / "state.json"
        self.p = Patience(self.state)


class OracleTests(Base):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), MockLLM)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}/v1"
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()
    def setUp(self):
        super().setUp(); MockLLM.reply = json.dumps(GOOD); MockLLM.status = 200; MockLLM.seen = []
    def oracle(self, **kw):
        return LLMOracle(env={"PATIENCE_LLM_BASE_URL": self.url, "PATIENCE_LLM_API_KEY": "k",
                              "PATIENCE_LLM_MODEL": "m", "PATIENCE_LLM_TIMEOUT": "3", **kw})

    def test_no_key_uses_heuristic_and_records_path(self):
        p = Patience(self.state, oracle=LLMOracle(env={}))
        r = p.cycle("summarize notes")
        self.assertEqual(r["oracle_path"], "heuristic")
        self.assertEqual(p.state.assessments[-1]["oracle_path"], "heuristic")

    def test_llm_output_parsed_into_assessment(self):
        p = Patience(self.state, oracle=self.oracle())
        r = p.cycle("summarize notes")
        self.assertEqual(r["oracle_path"], "llm")
        self.assertEqual(r["assessment"]["evidence"], ["model saw it"])
        self.assertEqual(MockLLM.seen[0], ("/v1/chat/completions", "Bearer k", "m"))

    def test_invalid_model_output_falls_back(self):
        MockLLM.reply = json.dumps({**GOOD, "urgency": 7})
        o = self.oracle(); p = Patience(self.state, oracle=o)
        self.assertEqual(p.cycle("summarize")["oracle_path"], "heuristic")
        self.assertIn("urgency", o.last_error)

    def test_http_error_falls_back(self):
        MockLLM.status = 500
        self.assertEqual(Patience(self.state, oracle=self.oracle()).cycle("x y")["oracle_path"], "heuristic")

    def test_model_cannot_lower_rule_consequence(self):
        r = Patience(self.state, oracle=self.oracle()).cycle("delete irreversible credential")
        self.assertEqual(r["oracle_path"], "llm")
        self.assertTrue(r["decision"]["requires_authorization"])

    def test_parse_rejects_garbage(self):
        with self.assertRaises(AssessmentValidationError):
            parse_assessment("no json here")
        self.assertEqual(parse_assessment("```json\n" + json.dumps(GOOD) + "\n```").confidence, .8)


class ExecutionTests(Base):
    def test_held_decision_refused_until_authorized_then_receipt(self):
        r = self.p.propose("publish irreversible note", "write_note", {"filename": "a.md", "text": "hi"})
        did = r["decision_id"]
        self.assertEqual([d["id"] for d in self.p.pending()], [did])
        with self.assertRaises(ExecutionRefused):
            self.p.execute(did)
        self.p.authorize_decision(did, "matthew")
        rc = self.p.execute(did)
        self.assertEqual((rc["decision_id"], rc["approver"]), (did, "matthew"))
        for k in ("id", "timestamp", "result_hash"): self.assertTrue(rc[k])
        self.assertEqual((self.root / "sandbox" / "a.md").read_text(), "hi")

    def test_authorization_is_per_decision_not_per_action_type(self):
        a = self.p.propose("delete irreversible thing A", "append_memory", {"content": "A"})["decision_id"]
        b = self.p.propose("delete irreversible thing B", "append_memory", {"content": "B"})["decision_id"]
        self.p.authorize_decision(a, "matthew")
        self.p.execute(a)
        with self.assertRaises(ExecutionRefused):
            self.p.execute(b)

    def test_idempotent(self):
        did = self.p.propose("summarize this", "append_memory", {"content": "once"})["decision_id"]
        self.p.execute(did); n = len(self.p.state.memory)
        again = self.p.execute(did)
        self.assertTrue(again["already_executed"]); self.assertEqual(len(self.p.state.memory), n)

    def test_non_allowlisted_refused_even_if_authorized(self):
        did = self.p.propose("summarize", "shell", {"cmd": "rm -rf /"})["decision_id"]
        self.p.authorize_decision(did, "matthew")
        with self.assertRaisesRegex(ExecutionRefused, "allowlisted"):
            self.p.execute(did)

    def test_sandbox_escape_refused(self):
        did = self.p.propose("summarize", "write_note", {"filename": "../evil", "text": "x"})["decision_id"]
        with self.assertRaises(ExecutionRefused):
            self.p.execute(did)

    def test_denied_cannot_execute(self):
        did = self.p.propose("delete irreversible", "append_memory", {"content": "x"})["decision_id"]
        self.p.deny_decision(did, "matthew", "no")
        with self.assertRaises(ExecutionRefused):
            self.p.execute(did)

    def test_schedule_reminder(self):
        due = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        did = self.p.propose("remind me", "schedule_reminder", {"title": "call", "due_at": due})["decision_id"]
        self.p.execute(did)
        self.assertEqual(self.p.state.tasks[-1]["title"], "call")


class AuditTests(Base):
    def make(self):
        did = self.p.propose("delete irreversible", "append_memory", {"content": "x"})["decision_id"]
        self.p.authorize_decision(did, "matthew"); self.p.execute(did)
        d2 = self.p.propose("delete irreversible 2", "append_memory", {"content": "y"})["decision_id"]
        self.p.deny_decision(d2, "matthew")
        return self.p.audit.path

    def test_chain_valid_and_covers_events(self):
        path = self.make()
        self.assertTrue(verify(path)["ok"])
        events = {e["event"] for e in self.p.audit.entries()}
        self.assertTrue({"decision", "votes", "authorization", "execution", "denial"} <= events)

    def test_edit_detected(self):
        path = self.make(); lines = path.read_text().splitlines()
        lines[2] = lines[2].replace("matthew", "mallory") if "matthew" in lines[2] else lines[2].replace('"votes"', '"vote"')
        path.write_text("\n".join(lines) + "\n")
        self.assertFalse(verify(path)["ok"])

    def test_middle_deletion_detected(self):
        path = self.make(); lines = path.read_text().splitlines(); del lines[1]
        path.write_text("\n".join(lines) + "\n")
        self.assertFalse(verify(path)["ok"])

    def test_tail_truncation_detected(self):
        path = self.make(); lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[:-1]) + "\n")
        r = verify(path); self.assertFalse(r["ok"]); self.assertIn("head anchor", r["errors"][-1])


class WorkerTests(Base):
    def queue(self, *events):
        q = self.root / "queue.jsonl"
        with q.open("a") as f:
            for e in events: f.write(json.dumps(e) + "\n")
        return q

    def test_routes_executes_and_holds(self):
        q = self.queue({"trigger_type": "idle_reassessment", "payload": {"r": 1}},
                       {"trigger_type": "x", "payload": {}, "proposed": {"executor": "append_memory", "params": {"content": "delete irreversible"}}})
        # second event text is benign; force a risky one:
        self.queue({"trigger_type": "manual", "payload": {"note": "delete irreversible credential"},
                    "proposed": {"executor": "append_memory", "params": {"content": "z"}}})
        out = TriggerWorker(self.state, q).process_once()
        self.assertEqual([o["outcome"] for o in out], ["executed", "executed", "held_for_approval"])
        events = [e["event"] for e in Patience(self.state).audit.entries()]
        self.assertIn("trigger_routed", events)

    def test_restart_resumes_without_duplication(self):
        q = self.queue({"trigger_type": "a", "payload": {"n": 1}}, {"trigger_type": "b", "payload": {"n": 2}})
        self.assertEqual(len(TriggerWorker(self.state, q).process_once()), 2)
        mem = len(Patience(self.state).state.memory)
        self.assertEqual(TriggerWorker(self.state, q).process_once(), [])  # restart: nothing redone
        self.queue({"trigger_type": "c", "payload": {"n": 3}})
        out = TriggerWorker(self.state, q).process_once()
        self.assertEqual([o["line"] for o in out], [3])
        self.assertGreater(len(Patience(self.state).state.memory), mem)

    def test_crash_mid_event_reuses_decision(self):
        q = self.queue({"trigger_type": "a", "payload": {"n": 1}})
        with self.assertRaises(SystemExit):
            TriggerWorker(self.state, q).process_once(crash_after_decision=True)
        n_dec = len(Patience(self.state).state.decisions)
        out = TriggerWorker(self.state, q).process_once()
        self.assertEqual(out[0]["outcome"], "executed")
        st = Patience(self.state).state
        self.assertEqual(len(st.decisions), n_dec); self.assertEqual(len(st.receipts), 1)

    def test_daemon_output_feeds_worker(self):
        now = datetime.now(timezone.utc)
        self.p.add_task("ship v0.5", (now - timedelta(minutes=1)).isoformat())
        q = self.root / "queue.jsonl"
        TriggerAgent(self.state, q).inspect_once()
        out = TriggerWorker(self.state, q).process_once()
        self.assertIn("executed", [o["outcome"] for o in out])
        self.assertTrue(list((self.root / "sandbox").glob("reminder-*.md")))


class MissionTests(Base):
    def test_numeric_priority_coerced(self):
        self.p.set_mission("m", "e", "o", 2)
        self.assertEqual(Patience(self.state).state.priority, "2")
        with self.assertRaises(ValueError):
            self.p.set_mission("m", "e", "o", {"bad": 1})


try:
    import mcp  # noqa
    HAVE_MCP = True
except ImportError:
    HAVE_MCP = False


@unittest.skipUnless(HAVE_MCP, "mcp SDK not installed")
class MCPTests(Base):
    def test_starts_and_lists_tools_and_calls(self):
        from mcp import ClientSession
        from mcp.client.stdio import stdio_client, StdioServerParameters
        params = StdioServerParameters(command=sys.executable, args=[str(SRC / "mcp_server.py")],
                                       env={**os.environ, "PATIENCE_STATE": str(self.state)})
        async def run():
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    names = {t.name for t in (await s.list_tools()).tools}
                    res = await s.call_tool("verify_audit", {})
                    return names, res
        names, res = asyncio.run(asyncio.wait_for(run(), 30))
        self.assertTrue({"propose_action", "list_pending", "authorize", "verify_audit"} <= names)
        self.assertFalse(res.is_error if hasattr(res, "is_error") else res.isError)


if __name__ == "__main__":
    unittest.main()
