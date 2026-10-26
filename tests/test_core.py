import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine import Patience
from agent_daemon import TriggerAgent
from scheduler import parse_due
from governance import GovernanceGate
from models import Decision


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.state = self.root / 'state.json'
        self.queue = self.root / 'queue.jsonl'
        self.p = Patience(self.state)

    def agent(self):
        return TriggerAgent(self.state, self.queue, idle_minutes=1)

    def test_authorization_is_not_execution(self):
        result = self.p.cycle('Please respond with a summary')
        self.assertTrue(result['verification']['authorized'])
        self.assertFalse(result['verification']['executed'])
        self.assertFalse(result['verification']['verified'])

    def test_high_consequence_is_blocked(self):
        result = self.p.cycle('delete private credentials')
        self.assertTrue(result['decision']['requires_authorization'])
        self.assertFalse(result['verification']['authorized'])

    def test_explicit_gate_overrides_autonomous_allowlist(self):
        decision = Decision('research', 'review required', .5, True, 'review')
        self.assertFalse(GovernanceGate().may_execute(decision, []))

    def test_timezone_is_required(self):
        with self.assertRaises(ValueError):
            self.p.add_task('bad date', '2026-10-02T12:00:00')
        self.assertEqual(self.p.state.tasks, [])

    def test_checkpoint_waits_until_due_and_deduplicates_restart(self):
        now = datetime.now(timezone.utc)
        self.p.add_task('review', (now + timedelta(hours=1)).isoformat())
        agent = self.agent()
        self.assertEqual(agent.inspect_once(), [])
        agent._now = lambda: now + timedelta(hours=2)
        types = [kind for kind, _ in agent.inspect_once()]
        self.assertEqual(types, ['task_due', 'checkpoint'])
        restarted = self.agent()
        restarted._now = agent._now
        self.assertEqual(restarted.inspect_once(), [])

    def test_idle_repeats(self):
        agent = self.agent()
        now = datetime.now(timezone.utc)
        agent._now = lambda: now
        agent.inspect_once()
        now += timedelta(minutes=2)
        self.assertEqual(agent.inspect_once()[0][0], 'idle_reassessment')
        now += timedelta(minutes=2)
        self.assertEqual(agent.inspect_once()[0][0], 'idle_reassessment')

    def test_blocked_and_uncertain_deduplicate(self):
        self.p.cycle('maybe delete credentials')
        agent = self.agent()
        self.assertEqual([kind for kind, _ in agent.inspect_once()], ['blocked_action', 'high_uncertainty'])
        self.assertEqual(self.agent().inspect_once(), [])

    def test_prose_checkpoint_is_not_a_due_date(self):
        self.p.state.next_checkpoint = 'After human authorization'
        self.p.memory_store.save(self.p.state)
        self.assertEqual(self.agent().inspect_once(), [])

    def test_corrupt_state_fails_loud(self):
        self.state.write_text('{bad', encoding='utf-8')
        with self.assertRaises(ValueError):
            self.agent().inspect_once()

    def test_corrupt_queue_fails_loud(self):
        self.queue.write_text('{bad', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'line 1'):
            self.agent()

    def test_cycle_preserves_timed_checkpoint(self):
        due = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        self.p.add_task('test', due)
        self.p.cycle('summarize status')
        self.assertEqual(parse_due(self.p.state.next_checkpoint), parse_due(due))


if __name__ == '__main__':
    unittest.main()
