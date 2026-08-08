"""Recipient-side decline markers: the per-recipient signal surfacing
mid-stream (a shared task stays live for the others) and the collective
terminal ending streams chain-wide.

Run: python3 -m unittest discover tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush import TaskDeclined, TaskDeclinedByRecipient  # noqa: E402
from simplepush.client import Event  # noqa: E402

from test_cancel import GROUP_RESPONSE, TASK_A, TASK_B, collect, make_group  # noqa: E402


def declined_by_recipient_event(task_id, version, *, reason="declined", note=None, actor=None):
    data = {"type": "taskDeclinedByRecipient", "taskId": task_id, "reason": reason}
    if note is not None:
        data["note"] = note
    raw = {
        "eventType": "TaskDeclinedByRecipient",
        "version": version,
        "createdAt": "2026-08-06T10:02:00Z",
        "data": data,
    }
    if actor is not None:
        raw["actor"] = actor
    return Event.from_raw(raw)


def declined_event(task_id, version):
    return Event.from_raw({
        "eventType": "TaskDeclined",
        "version": version,
        "createdAt": "2026-08-06T10:03:00Z",
        "data": {"type": "taskDeclined", "taskId": task_id},
    })


class DeclineStreamTest(unittest.IsolatedAsyncioTestCase):

    async def test_single_recipient_decline_signals_then_ends_the_inputs_stream(self):
        client, group, _calls = make_group([GROUP_RESPONSE])
        task = group.instances[0]
        actor = {"publicId": "usr_a", "name": "Alice", "deviceName": "Pixel"}
        client._hub._dispatch(declined_by_recipient_event(
            TASK_A, 1, reason="failed", note="printer is on fire", actor=actor))
        client._hub._dispatch(declined_event(TASK_A, 2))

        # No timeout: this only returns because taskDeclined is terminal.
        items = await collect(task.inputs(replay=True))
        self.assertEqual(len(items), 2)
        signal, terminal = items
        self.assertIsInstance(signal, TaskDeclinedByRecipient)
        self.assertEqual(signal.task_id, TASK_A)
        self.assertEqual(signal.reason, "failed")
        self.assertEqual(signal.note, "printer is on fire")
        self.assertEqual(signal.actor, actor)
        self.assertIsInstance(terminal, TaskDeclined)
        self.assertEqual(terminal.task_id, TASK_A)

    async def test_partial_decline_is_not_terminal(self):
        # Shared mode: one recipient declined, the others may still answer —
        # the stream surfaces the signal and stays open (ends on timeout).
        client, group, _calls = make_group([GROUP_RESPONSE])
        client._hub._dispatch(declined_by_recipient_event(TASK_A, 1))

        items = await collect(group.instances[0].inputs(replay=True, timeout=0.05))
        self.assertEqual(len(items), 1)
        self.assertIsInstance(items[0], TaskDeclinedByRecipient)
        self.assertEqual(items[0].reason, "declined")

    async def test_replies_stream_surfaces_the_decline_signal_too(self):
        client, group, _calls = make_group([GROUP_RESPONSE])
        client._hub._dispatch(declined_by_recipient_event(TASK_A, 1, note="not me"))
        client._hub._dispatch(declined_event(TASK_A, 2))

        items = await collect(group.instances[0].replies(replay=True))
        self.assertEqual([type(i) for i in items], [TaskDeclinedByRecipient, TaskDeclined])
        self.assertEqual(items[0].note, "not me")

    async def test_collective_decline_ends_a_subtask_stream_too(self):
        # taskDeclined is entity-wide terminal like taskCanceled: a fully
        # declined root closes every stream of the chain.
        client, group, _calls = make_group([
            GROUP_RESPONSE,
            {"subtaskId": "sub_00000000-0000-7000-8000-000000000010",
             "createdAt": "2026-08-06T10:00:30Z"},
        ])
        subtask = group.instances[0].append(content="follow-up")
        client._hub._dispatch(declined_event(TASK_A, 1))

        items = await collect(subtask.inputs(replay=True))
        self.assertEqual(len(items), 1)
        self.assertIsInstance(items[0], TaskDeclined)

    async def test_per_recipient_signal_stays_off_subtask_streams(self):
        # The signal is task-scoped (no subtaskId), so a subtask's stream
        # filters it out; only the entity-wide terminal reaches it.
        client, group, _calls = make_group([
            GROUP_RESPONSE,
            {"subtaskId": "sub_00000000-0000-7000-8000-000000000010",
             "createdAt": "2026-08-06T10:00:30Z"},
        ])
        subtask = group.instances[0].append(content="follow-up")
        client._hub._dispatch(declined_by_recipient_event(TASK_A, 1))

        items = await collect(subtask.inputs(replay=True, timeout=0.05))
        self.assertEqual(items, [])

    async def test_group_inputs_surface_each_members_decline_then_end(self):
        # Independent mode: each member's decline is its own signal+terminal
        # pair; the merged group stream ends when every member has ended.
        client, group, _calls = make_group([GROUP_RESPONSE])
        client._hub._dispatch(declined_by_recipient_event(TASK_A, 1))
        client._hub._dispatch(declined_event(TASK_A, 2))
        client._hub._dispatch(declined_by_recipient_event(TASK_B, 1))
        client._hub._dispatch(declined_event(TASK_B, 2))

        items = await collect(group.inputs(replay=True))
        self.assertEqual(len(items), 4)
        by_task = {}
        for tagged in items:
            by_task.setdefault(tagged.instance.task_id, []).append(tagged.item)
        self.assertEqual([type(i) for i in by_task[TASK_A]], [TaskDeclinedByRecipient, TaskDeclined])
        self.assertEqual([type(i) for i in by_task[TASK_B]], [TaskDeclinedByRecipient, TaskDeclined])



def subtask_declined_by_recipient_event(task_id, subtask_id, version, *, reason="declined", note=None, actor=None):
    data = {"type": "subtaskDeclinedByRecipient", "parentTaskId": task_id, "subtaskId": subtask_id, "reason": reason}
    if note is not None:
        data["note"] = note
    raw = {
        "eventType": "SubtaskDeclinedByRecipient",
        "version": version,
        "createdAt": "2026-08-07T10:02:00Z",
        "data": data,
    }
    if actor is not None:
        raw["actor"] = actor
    return Event.from_raw(raw)


def subtask_declined_event(task_id, subtask_id, version):
    return Event.from_raw({
        "eventType": "SubtaskDeclined",
        "version": version,
        "createdAt": "2026-08-07T10:03:00Z",
        "data": {"type": "subtaskDeclined", "parentTaskId": task_id, "subtaskId": subtask_id},
    })


class SubtaskDeclineStreamTest(unittest.IsolatedAsyncioTestCase):

    async def test_subtask_decline_signals_then_ends_only_its_own_stream(self):
        from simplepush import SubtaskDeclined, SubtaskDeclinedByRecipient
        client, group, _calls = make_group([
            GROUP_RESPONSE,
            {"subtaskId": "sub_00000000-0000-7000-8000-000000000010",
             "createdAt": "2026-08-07T10:00:30Z"},
        ])
        subtask = group.instances[0].append(content="follow-up")
        sub_id = subtask.subtask_id
        client._hub._dispatch(subtask_declined_by_recipient_event(
            TASK_A, sub_id, 1, reason="failed", note="not this step"))
        client._hub._dispatch(subtask_declined_event(TASK_A, sub_id, 2))

        # No timeout: resolves only because subtaskDeclined is a scoped terminal.
        items = await collect(subtask.inputs(replay=True))
        self.assertEqual([type(i) for i in items], [SubtaskDeclinedByRecipient, SubtaskDeclined])
        self.assertEqual(items[0].reason, "failed")
        self.assertEqual(items[0].note, "not this step")
        self.assertEqual(items[0].subtask_id, sub_id)
        self.assertEqual(items[1].parent_task_id, TASK_A)

        # The ROOT task's stream is untouched (scoped, not chain-wide).
        root_items = await collect(group.instances[0].inputs(replay=True, timeout=0.05))
        self.assertEqual(root_items, [])

    async def test_subtask_replies_stream_ends_on_the_scoped_terminal_too(self):
        from simplepush import SubtaskDeclined
        client, group, _calls = make_group([
            GROUP_RESPONSE,
            {"subtaskId": "sub_00000000-0000-7000-8000-000000000010",
             "createdAt": "2026-08-07T10:00:30Z"},
        ])
        subtask = group.instances[0].append(content="follow-up")
        client._hub._dispatch(subtask_declined_event(TASK_A, subtask.subtask_id, 1))

        items = await collect(subtask.replies(replay=True))
        self.assertEqual(len(items), 1)
        self.assertIsInstance(items[0], SubtaskDeclined)

if __name__ == "__main__":
    unittest.main()
