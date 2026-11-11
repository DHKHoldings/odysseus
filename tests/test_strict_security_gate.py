import pytest

from src.tool_capabilities import ToolRunSecurityContext


@pytest.mark.parametrize(
    "tool,content",
    [
        ("bash", "pwd"),
        ("edit_file", '{"path":"test.txt","content":"changed"}'),
        ("manage_memory", '{"action":"add","content":"test"}'),
        ("send_email", '{"to":"test@example.com","subject":"test"}'),
        ("web_fetch", '{"url":"https://example.com"}'),
    ],
)
def test_strict_mode_blocks_sensitive_tools_without_external_context(
    monkeypatch, tool, content
):
    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "1")
    context = ToolRunSecurityContext(external_untrusted_context_seen=False)

    assert context.decision_for(tool, content).allowed is False


def test_strict_mode_allows_safe_workspace_read(monkeypatch):
    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "1")
    context = ToolRunSecurityContext(external_untrusted_context_seen=False)

    assert context.decision_for("read_file", '{"path":"notes.txt"}').allowed is True


def test_strict_mode_cannot_be_bypassed_by_unattended_tools(monkeypatch):
    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "1")
    context = ToolRunSecurityContext(
        external_untrusted_context_seen=False,
        unattended_tools=frozenset({"bash", "edit_file"}),
    )

    assert context.decision_for("bash", "pwd").allowed is False
    assert context.decision_for("edit_file", '{"path":"notes.txt"}').allowed is False


def test_legacy_mode_preserves_trusted_execution(monkeypatch):
    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "0")
    context = ToolRunSecurityContext(external_untrusted_context_seen=False)

    assert context.decision_for("bash", "pwd").allowed is True


async def test_strict_approved_write_executes_once(monkeypatch, tmp_path):
    from src import tool_execution
    from src.agent_runtime.authority import RequestAuthority
    from src.tool_approvals import ToolApprovalStore
    from src.tool_capabilities import capabilities_for_action
    from src.tool_types import ToolBlock

    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "1")
    monkeypatch.setattr(tool_execution, "_owner_is_admin", lambda owner: True)

    authority = RequestAuthority(
        "strict-request", "alice", "session", str(tmp_path), ()
    )
    content = "approved.txt\noriginal"
    store = ToolApprovalStore()

    pending = store.create(
        owner="alice",
        session_id="session",
        origin_run_id="strict-run",
        tool_name="write_file",
        content=content,
        workspace=str(tmp_path),
        request_authority=authority,
        external_untrusted_context_seen=False,
        capabilities=capabilities_for_action("write_file", content),
    )
    approval = store.consume(
        pending.approval_id,
        decision="approve",
        owner="alice",
        session_id="session",
    )
    assert approval is not None

    async def dispatch(body, exact):
        return await tool_execution.execute_tool_block(
            ToolBlock("write_file", body),
            owner="alice",
            session_id="session",
            workspace=str(tmp_path),
            request_authority=authority,
            exact_approval=exact,
            security_context=ToolRunSecurityContext(
                external_untrusted_context_seen=False
            ),
        )

    _, first = await dispatch(content, approval)
    assert first.get("exit_code") == 0, first
    assert (tmp_path / "approved.txt").read_text() == "original"

    _, replay = await dispatch(content, approval)
    assert replay.get("blocked") is True, replay
    assert (tmp_path / "approved.txt").read_text() == "original"


async def test_strict_approval_rejects_changed_content(monkeypatch, tmp_path):
    from src import tool_execution
    from src.agent_runtime.authority import RequestAuthority
    from src.tool_approvals import ToolApprovalStore
    from src.tool_capabilities import capabilities_for_action
    from src.tool_types import ToolBlock

    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "1")
    monkeypatch.setattr(tool_execution, "_owner_is_admin", lambda owner: True)

    authority = RequestAuthority(
        "strict-request", "alice", "session", str(tmp_path), ()
    )
    content = "approved.txt\noriginal"
    store = ToolApprovalStore()

    pending = store.create(
        owner="alice",
        session_id="session",
        origin_run_id="strict-run",
        tool_name="write_file",
        content=content,
        workspace=str(tmp_path),
        request_authority=authority,
        external_untrusted_context_seen=False,
        capabilities=capabilities_for_action("write_file", content),
    )
    approval = store.consume(
        pending.approval_id,
        decision="approve",
        owner="alice",
        session_id="session",
    )
    assert approval is not None

    _, result = await tool_execution.execute_tool_block(
        ToolBlock("write_file", "approved.txt\nchanged"),
        owner="alice",
        session_id="session",
        workspace=str(tmp_path),
        request_authority=authority,
        exact_approval=approval,
        security_context=ToolRunSecurityContext(
            external_untrusted_context_seen=False
        ),
    )

    assert result.get("blocked") is True, result
    assert not (tmp_path / "approved.txt").exists()


async def test_strict_mode_blocks_unapproved_granted_write(monkeypatch, tmp_path):
    from src import tool_execution
    from src.agent_runtime.authority import OperationGrant, RequestAuthority
    from src.tool_types import ToolBlock

    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "1")
    monkeypatch.setattr(tool_execution, "_owner_is_admin", lambda owner: True)

    authority = RequestAuthority(
        "strict-request",
        "alice",
        "session",
        str(tmp_path),
        (OperationGrant("write_file"),),
    )

    _, result = await tool_execution.execute_tool_block(
        ToolBlock("write_file", "unapproved.txt\nblocked"),
        owner="alice",
        session_id="session",
        workspace=str(tmp_path),
        request_authority=authority,
        security_context=ToolRunSecurityContext(
            external_untrusted_context_seen=False
        ),
    )

    assert result.get("blocked") is True, result
    assert not (tmp_path / "unapproved.txt").exists()


def test_strict_mode_rejects_legacy_approval_bypass(monkeypatch):
    monkeypatch.setenv("ODYSSEUS_STRICT_TOOL_APPROVALS", "1")

    context = ToolRunSecurityContext(
        external_untrusted_context_seen=False,
        approval_gate_bypassed=True,
        unattended_tools=frozenset({"bash", "write_file"}),
    )

    for tool, content in (
        ("bash", "pwd"),
        ("write_file", "bypass.txt\\nunsafe"),
    ):
        decision = context.decision_for(tool, content)
        assert decision.allowed is False, (tool, decision)
