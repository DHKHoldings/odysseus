"""Regression tests for opt-in strict tool approvals."""

from src.tool_approval_scopes import ToolApprovalScope
from src.tool_approvals import ToolApprovalStore
from src.tool_capabilities import capabilities_for_action


def test_strict_mode_restricts_task_approval_to_one_action(monkeypatch):
    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "1")

    store = ToolApprovalStore()
    content = "printf exact"

    pending = store.create(
        owner="Alice",
        session_id="session-1",
        origin_run_id="run-1",
        tool_name="bash",
        content=content,
        workspace=None,
        external_untrusted_context_seen=True,
        capabilities=capabilities_for_action("bash", content),
    )

    grant = store.consume(
        pending.approval_id,
        decision="approve_task",
        owner="alice",
        session_id="session-1",
    )

    assert grant is not None
    assert grant.scope is ToolApprovalScope.SINGLE_ACTION
    assert grant.allow_remaining_actions is False
    assert grant.grants_chat_session is False


def test_strict_mode_restricts_chat_session_approval_to_one_action(monkeypatch):
    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "1")

    store = ToolApprovalStore()
    content = "printf exact"

    pending = store.create(
        owner="Alice",
        session_id="session-1",
        origin_run_id="run-1",
        tool_name="bash",
        content=content,
        workspace=None,
        external_untrusted_context_seen=True,
        capabilities=capabilities_for_action("bash", content),
    )

    grant = store.consume(
        pending.approval_id,
        decision="approve",
        owner="alice",
        session_id="session-1",
    )

    assert grant is not None
    assert grant.scope is ToolApprovalScope.SINGLE_ACTION
    assert grant.allow_remaining_actions is False
    assert grant.grants_chat_session is False


def test_strict_mode_rejects_existing_chat_session_grants(monkeypatch):
    from core.models import ChatMessage, Session
    from src.tool_approval_scopes import (
        CHAT_SESSION_APPROVAL_CONTEXT_MARKER,
        stamp_chat_session_grant,
    )

    card = {
        "kind": "tool_approval",
        "approval_id": "approval-existing",
        "session_id": "session-1",
        "resolved": "approve",
    }
    stamp_chat_session_grant(card, "session-1", "approve")

    session = Session(
        id="session-1",
        name="Chat",
        endpoint_url="http://example.invalid",
        model="test",
        history=[
            ChatMessage(
                "assistant",
                "approval requested",
                {"tool_events": [{"ask_user": card}]},
            ),
            ChatMessage("user", "continue"),
        ],
    )

    monkeypatch.delenv("ODYSSEUS_STRICT_TOOL_APPROVALS", raising=False)
    normal_messages = session.get_context_messages()
    assert normal_messages[-1]["metadata"][CHAT_SESSION_APPROVAL_CONTEXT_MARKER] is True

    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "1")
    strict_messages = session.get_context_messages()
    assert CHAT_SESSION_APPROVAL_CONTEXT_MARKER not in (
        strict_messages[-1].get("metadata") or {}
    )


def test_strict_mode_does_not_issue_persistent_chat_grant(monkeypatch):
    from types import SimpleNamespace
    from routes import chat_routes
    from src.tool_approval_scopes import (
        CHAT_SESSION_APPROVAL_SIGNATURE_FIELD,
    )

    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "1")

    card = {
        "kind": "tool_approval",
        "approval_id": "approval-1",
        "session_id": "session-1",
    }
    metadata = {
        "_db_id": "message-1",
        "tool_events": [{"ask_user": card}],
    }
    session = SimpleNamespace(
        id="session-1",
        history=[SimpleNamespace(metadata=metadata)],
    )

    db_message = SimpleNamespace(meta_data=None)

    class Column:
        def __eq__(self, value):
            return value

    class FakeDBMessage:
        id = Column()
        session_id = Column()

    class FakeQuery:
        def filter(self, *conditions):
            return self

        def first(self):
            return db_message

    class FakeDB:
        def query(self, model):
            assert model is FakeDBMessage
            return FakeQuery()

        def commit(self):
            pass

        def rollback(self):
            raise AssertionError("Unexpected database rollback")

        def close(self):
            pass

    monkeypatch.setattr(chat_routes, "DBChatMessage", FakeDBMessage)
    monkeypatch.setattr(chat_routes, "SessionLocal", lambda: FakeDB())

    assert chat_routes._mark_tool_approval_resolved(
        session, "approval-1", "approve"
    ) is True

    import json
    persisted = json.loads(db_message.meta_data)
    assert persisted["tool_events"][0]["ask_user"]["resolved"] == "approve"
    assert "_db_id" not in persisted

    assert card["resolved"] == "approve"
    assert CHAT_SESSION_APPROVAL_SIGNATURE_FIELD not in card


def test_strict_mode_displays_single_action_approval(monkeypatch):
    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "1")

    store = ToolApprovalStore()
    pending = store.create(
        owner="alice",
        session_id="session-1",
        origin_run_id="run-1",
        tool_name="bash",
        content="printf exact",
        workspace=None,
        external_untrusted_context_seen=False,
        capabilities=capabilities_for_action("bash", "printf exact"),
    )

    payload = pending.public_payload()
    options = payload["options"]

    assert [option["label"] for option in options] == [
        "Allow this action once",
        "Deny",
    ]
    assert [option["value"] for option in options] == [
        "approve",
        "deny",
    ]

    grant = store.consume(
        pending.approval_id,
        decision=options[0]["value"],
        owner="alice",
        session_id="session-1",
    )

    assert grant is not None
    assert grant.scope is ToolApprovalScope.SINGLE_ACTION
    assert grant.allow_remaining_actions is False
    assert grant.grants_chat_session is False


def test_legacy_mode_preserves_existing_approval_options(monkeypatch):
    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "0")

    store = ToolApprovalStore()
    pending = store.create(
        owner="alice",
        session_id="session-1",
        origin_run_id="run-1",
        tool_name="bash",
        content="printf exact",
        workspace=None,
        external_untrusted_context_seen=True,
        capabilities=capabilities_for_action("bash", "printf exact"),
    )

    options = pending.public_payload()["options"]

    assert [option["label"] for option in options] == [
        "Allow for this task",
        "Allow for this chat session",
        "Deny",
    ]
    assert [option["value"] for option in options] == [
        "approve_task",
        "approve",
        "deny",
    ]
