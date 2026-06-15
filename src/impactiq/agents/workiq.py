"""Work IQ MCP server registry — the single place that encodes, per server,
exactly which tools ImpactIQ is allowed to call.

Why this exists: every Work IQ MCP server ships a BROAD tool set. The
Dataverse server can drop tables and delete records; Mail can send; Teams
can delete chats. Attaching a server with its full tool set would blow past
ImpactIQ's safety bounds (data-writes-only / draft-only / confirm-before-act).
So we attach every server with a strict ``allowed_tools`` allow-list, and we
keep a ``forbidden_patterns`` denylist that the tests assert can never
intersect the allow-list. The deterministic confirm-and-audit gate still
sits in front of every mutation; this registry is the second wall.

Identity: all Work IQ MCP calls run On-Behalf-Of the signed-in user
(delegated), permission-trimmed by M365 — the service identity never uses
these. So ImpactIQ can only ever do what the user could do themselves, and
only the bounded subset of that.

Server IDs / exact tool names marked (verify at build) are confirmed against
the live Work IQ reference docs when each connection is wired; Mail is
confirmed (mcp_MailTools).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from azure.ai.projects.models import MCPTool

from ..settings import Settings

# Foundry-connection endpoint form (what the portal "Connect ... tool" dialog
# uses): tenant-agnostic - the connection's OAuth identity-passthrough supplies
# the user/tenant context. (The coding-agent docs show a tenant-scoped
# `/agents/tenants/{tenantId}/servers/{server}` form; that's the raw-MCP-client
# path, not the Foundry-connection path we use.)
_SERVER_URL = "https://agent365.svc.cloud.microsoft/agents/servers/{server}"

# Substrings that must NEVER appear in any server's allow-list. These encode
# the hard bounds independent of exact tool spelling: no schema/config
# changes, no destructive deletes, no outbound sends, no membership/channel
# administration. The safety test asserts allow-lists are disjoint from these.
GLOBAL_FORBIDDEN_PATTERNS = (
    # Schema/config changes (NOT describe_table / list_tables, which are reads).
    "create_table",
    "update_table",
    "delete_table",
    # Destructive record/content deletes.
    "delete_record",
    "deletemessage",
    "deleteevent",      # also catches DeleteEventById
    "delete_event",
    "cancelevent",      # organizer cancel = destructive
    "deletechat",       # also catches DeleteChatMessage
    # Outbound send (draft-only discipline).
    "sendmail",
    "senddraft",
    # Membership / channel administration.
    "removemember",
    "deletechannel",
    # Dataverse Business-Skill + file-upload surfaces (config-ish / out of
    # scope for the bounded write path).
    "skill",          # upsert_skill / delete_skill / create_skill_resource
    "file_upload",    # init_file_upload / commit_file_upload
)


@dataclass(frozen=True)
class WorkIQServer:
    key: str                       # our short name
    label: str
    server_id: str                 # the mcp_* server id in the endpoint URL
    allowed_tools: tuple[str, ...]  # the ONLY tools we attach
    connection_attr: str           # Settings attribute holding the connection id
    mutating: bool                 # True if any allowed tool writes/creates
    # The read-only subset safe to use WITHOUT a confirm gate (for the assist
    # path). Mutating tools (create/send) are excluded here and only run
    # behind an explicit confirm action. Empty => the whole allow-list is read.
    read_only_tools: tuple[str, ...] = ()
    # Mutating tools that are INERT — they change only the user's own private
    # state and cannot reach another person (e.g. creating an Outlook DRAFT:
    # nothing goes out until the user sends it from Outlook). These auto-run
    # in gated mode; the approval gate is reserved for consequence (sends,
    # invites, record writes). NOT included in read_only builds.
    auto_approve_tools: tuple[str, ...] = ()
    verify_at_build: bool = False  # server_id / tool names still to confirm
    notes: str = ""


REGISTRY: dict[str, WorkIQServer] = {
    # Tool names confirmed LIVE against the server — the doc-derived
    # mcp_MailTools_graph_mail_* names do NOT exist on it. Reads make mail a
    # first-class answer source (SearchMessages = live Graph mailbox search,
    # the recency complement to the lagging semantic index). Excluded:
    # SendEmailWithAttachments / SendDraftMessage / Forward* (outbound sends),
    # DeleteMessage / DeleteAttachment (destructive), attachment
    # upload/download (out of scope).
    "mail": WorkIQServer(
        key="mail",
        label="Work IQ Mail",
        server_id="mcp_MailTools",
        allowed_tools=(
            "SearchMessages",
            "GetMessage",
            "GetAttachments",
            "CreateDraftMessage",
            "UpdateDraft",
            "ReplyToMessage",      # reply DRAFT (sendImmediately stays false)
            "ReplyAllToMessage",   # reply-all DRAFT
            "FlagEmail",
        ),
        read_only_tools=(
            "SearchMessages",
            "GetMessage",
            "GetAttachments",
        ),
        # Draft creation is inert (lands in the user's OWN Drafts; nothing is
        # sent until they send it from Outlook) — the draft IS the safety
        # artifact, so it runs without a tap. Replies stay gated because of
        # their sendImmediately parameter.
        auto_approve_tools=(
            "CreateDraftMessage",
            "UpdateDraft",
        ),
        connection_attr="foundry_workiq_mail_connection_id",
        mutating=True,
        notes=(
            "Reads = the live-mail answer source; drafts auto-run (inert); "
            "reply/flag mutations are approval-gated; never "
            "Send*/Forward*/Delete*."
        ),
    ),
    # Read-only — manager/reports/profile/search. Fixes routing ('who owns
    # this / who to contact'). Lowest risk, highest immediate value.
    "user": WorkIQServer(
        key="user",
        label="Work IQ User",
        server_id="mcp_MeServer",  # confirmed from the Foundry connect dialog
        # Tool names confirmed by a LIVE mcp_list_tools call - the published
        # `mcp_graph_*` names were WRONG for this endpoint and silently filtered
        # the allow-list to empty.
        allowed_tools=(
            "GetMyDetails",
            "GetUserDetails",
            "GetMultipleUsersDetails",
            "GetManagerDetails",
            "GetDirectReportsDetails",
        ),
        connection_attr="foundry_workiq_user_connection_id",
        mutating=False,
        notes="Read-only ('Me' server, mcp_MeServer): profile, manager, reports, user search.",
    ),
    # Dataverse CRUD — RECORDS ONLY. Table/schema, delete, Business-Skill and
    # file-upload tools are deliberately excluded (data-writes-only, no config).
    "dataverse": WorkIQServer(
        key="dataverse",
        label="Microsoft Dataverse",
        # DIRECT endpoint ({org}/api/mcp), NOT the Agent365 gateway: the
        # allow-list authorizes by CALLING APP ID, and only the direct path
        # presents our allow-listed impactiq-workiq app. The gateway presents
        # its own app and 403s regardless.
        server_id="api/mcp",
        # Tool names confirmed by a LIVE tools/list against the real endpoint.
        # The old fetch/describe_table/list_tables guesses do not exist.
        allowed_tools=(
            "create_record",
            "update_record",
            "read_query",
            "search",
            "describe",
        ),
        read_only_tools=(
            "read_query",
            "search",
            "describe",
        ),
        connection_attr="foundry_workiq_dataverse_connection_id",
        mutating=True,
        notes=(
            "EXCLUDES create_table/update_table/delete_table (config), "
            "delete_record (destructive), upsert/delete skill + skill-resource "
            "(config), and the file upload/download tools (out of scope). The "
            "§7.2 write uses update_record / create_record only, behind the "
            "deterministic offer gate."
        ),
    ),
    # Calendar — find a free slot (read) + create/update an event (behind
    # confirm). Delete is excluded.
    "calendar": WorkIQServer(
        key="calendar",
        label="Work IQ Calendar",
        server_id="mcp_CalendarTools",
        # Confirmed via live mcp_list_tools. Excludes DeleteEventById /
        # CancelEvent (destructive) and Accept/Decline/Forward (out of scope).
        allowed_tools=(
            "FindMeetingTimes",
            "ListEvents",
            "ListCalendarView",
            "CreateEvent",   # booking — behind confirm
            "UpdateEvent",   # behind confirm
            "GetUserDateAndTimeZoneSettings",
            "GetRooms",
        ),
        read_only_tools=(
            "FindMeetingTimes",
            "ListEvents",
            "ListCalendarView",
            "GetUserDateAndTimeZoneSettings",
            "GetRooms",
        ),
        connection_attr="foundry_workiq_calendar_connection_id",
        mutating=True,
        notes="Find-a-time + list are reads; create/update an event is confirm-gated.",
    ),
    # Word — save a generated FRD/spec as a doc; read docs/comments. No delete.
    "word": WorkIQServer(
        key="word",
        label="Work IQ Word",
        server_id="mcp_WordTools",
        allowed_tools=(
            "mcp_WordTools_graph_word_createDocument",
            "mcp_WordTools_graph_word_readDocument",
            "mcp_WordTools_graph_word_addComment",
        ),
        connection_attr="foundry_workiq_word_connection_id",
        mutating=True,
        verify_at_build=True,
        notes="Park the drafter's output as a Word doc, behind confirm.",
    ),
    # Teams — post the manager notification for real. Strictly send-on-confirm;
    # no delete/channel-admin/membership tools.
    "teams": WorkIQServer(
        key="teams",
        label="Work IQ Teams",
        server_id="mcp_TeamsServer",  # confirmed from the connect dialog
        # Confirmed via live mcp_list_tools. Send tools are confirm-gated;
        # reads give the "who's discussing this" signal. Excludes all
        # delete / channel-admin / membership / file-send / message-edit ops.
        allowed_tools=(
            "SendMessageToUser",      # the manager notify — confirm-gated
            "SendMessageToChannel",   # confirm-gated
            "ListChats",
            "ListChannels",
            "ListChatMessages",
            "ListChannelMessages",
            "SearchTeamsMessages",
            "GetUserPresence",
        ),
        read_only_tools=(
            "ListChats",
            "ListChannels",
            "ListChatMessages",
            "ListChannelMessages",
            "SearchTeamsMessages",
            "GetUserPresence",
        ),
        connection_attr="foundry_workiq_teams_connection_id",
        mutating=True,
        notes="Reads = activity signal; SendMessage* is real outbound, confirm-before-send.",
    ),
}


def server_url(server: WorkIQServer, settings: Settings) -> str:
    # Dataverse uses the DIRECT per-org endpoint ({org}/api/mcp). The Agent365
    # gateway path 403s for Dataverse because the gateway presents its own app
    # id; the direct path presents our allow-listed client (via the Foundry
    # custom-OAuth connection scoped to the Dataverse resource).
    if server.key == "dataverse":
        base = (settings.dataverse_url or "").rstrip("/")
        return f"{base}/api/mcp"
    return _SERVER_URL.format(server=server.server_id)


def build_workiq_tool(
    key: str,
    settings: Settings,
    *,
    read_only: bool = False,
    gate_mutations: bool = True,
) -> MCPTool | None:
    """Build the allow-listed MCP tool for a Work IQ server, or None if its
    connection isn't configured. Runs OBO via the OAuth-passthrough
    connection, so it executes as the signed-in user.

    Capability model (full reasoning, gated mutations):
    * default — the FULL allow-list is attached so the agent can reason over
      every capability; reads run freely, but each MUTATING tool call pauses
      the run with an ``mcp_approval_request`` the human must approve
      (Foundry-native human-in-the-loop). This is how the agent "goes back
      and forth" across IQs without losing the confirm-before-act rule.
    * ``read_only=True`` — only the read subset, no approvals needed
      (legacy/utility paths).
    * ``gate_mutations=False`` — full list with no approval pauses; ONLY for
      tightly-scoped single-purpose turns that are themselves behind an
      explicit user confirmation (e.g. the create-draft action endpoint).
    """
    server = REGISTRY[key]
    connection_id = getattr(settings, server.connection_attr, None)
    if not connection_id:
        return None
    # Dataverse also needs the org URL to build its direct endpoint.
    if key == "dataverse" and not settings.dataverse_url:
        return None
    if read_only:
        tools = server.read_only_tools or server.allowed_tools
        if server.mutating and not server.read_only_tools:
            return None  # mutating server with no declared read subset -> unsafe
        require_approval: object = "never"
    else:
        tools = server.allowed_tools
        if server.mutating and gate_mutations:
            # Reads and inert mutations auto-run; everything with outward
            # consequence (sends, invites) pauses for human approval.
            ungated = [
                t
                for t in (*server.read_only_tools, *server.auto_approve_tools)
                if t in tools
            ]
            require_approval = {"never": {"tool_names": ungated}} if ungated else "always"
        else:
            require_approval = "never"
    return MCPTool(
        server_label=f"workiq-{server.key}",
        server_url=server_url(server, settings),
        require_approval=require_approval,
        allowed_tools=list(tools),
        project_connection_id=connection_id,
    )


def allowlist_is_safe(server: WorkIQServer) -> bool:
    """No allowed tool may match a forbidden pattern (the safety invariant)."""
    for tool in server.allowed_tools:
        low = tool.lower()
        if any(p in low for p in GLOBAL_FORBIDDEN_PATTERNS):
            return False
    return True
