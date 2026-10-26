from datetime import datetime, timezone
from models import Task, PatienceState

def parse_due(value):
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError('Due timestamp must be ISO format with a timezone.') from error
    if result.tzinfo is None:
        raise ValueError('Due timestamp must include a timezone, such as +00:00.')
    return result.astimezone(timezone.utc)

class TemporalLayer:
    def add_task(self, state: PatienceState, task: Task) -> None:
        if task.due_at:
            task.due_at = parse_due(task.due_at).isoformat()
        state.tasks.append(task.__dict__)

    def due_tasks(self, state: PatienceState, now=None):
        now = now or datetime.now(timezone.utc)
        due = []
        for task in state.tasks:
            if task.get("status") != "active" or not task.get("due_at"):
                continue
            try:
                t = parse_due(task["due_at"])
                if t <= now:
                    due.append(task)
            except ValueError as error:
                raise ValueError(f"Invalid due timestamp for task {task.get('id')}") from error
        return due

    def next_checkpoint(self, state: PatienceState) -> str:
        active = [t for t in state.tasks if t.get("status") == "active" and t.get("due_at")]
        return min(active, key=lambda x: parse_due(x["due_at"]))["due_at"] if active else "No scheduled checkpoint"
