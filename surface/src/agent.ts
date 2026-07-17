/**
 * ImpactIQ Custom Engine Agent - the Teams / Microsoft 365 Copilot surface.
 *
 * Deliberately thin: questions go to the local Python bridge, which runs the
 * multi-agent pipeline. UX contract:
 *
 *  - Every message is triaged first: conversational follow-ups and vague
 *    messages are answered/clarified in seconds; only concrete new analysis
 *    questions pay for the full pipeline.
 *  - The answer is a chat message (plain markdown). Cards appear only for
 *    things the user acts on: a small "next step" offer, the editable
 *    notification draft, the record-fix preview.
 *  - Nothing sends or writes without an explicit confirmation; the bridge
 *    re-gates every action server-side and audit-logs it.
 */
import { createHash, createHmac, randomUUID } from "node:crypto";
import { ActivityTypes } from "@microsoft/agents-activity";
import { AgentApplication, MemoryStorage, TurnContext } from "@microsoft/agents-hosting";
import config from "./config";

interface ConversationState {
  report: any;
  question: string;
  offer: any | null;
  artifactCard: any | null;
  draftCard: any | null;
  // Rolling memory: what was said and what ImpactIQ actually did (sends,
  // applied fixes), so follow-ups and returning users get continuity.
  history: { role: "user" | "impactiq"; text: string }[];
  actions: string[];
  // The signed-in user's On-Behalf-Of token for the current turn - forwarded
  // to the bridge as X-ImpactIQ-User-Token so content reads / Work IQ /
  // bounded writes run as them. Refreshed each turn; undefined when auth
  // isn't configured. This state bucket is keyed by the user's Entra identity
  // (see stateKey), so the token is never shared with another user even in a
  // multi-member channel.
  userToken?: string;
  lastActivityAt: number;
  // A suspended /agent run waiting on the user's Approve/Deny for a gated
  // mutating Work IQ tool (book a meeting, send a Teams message). Holds the
  // handle needed to resume the SAME run via /agent/approve.
  pendingAssist: {
    agent_name: string;
    agent_version: string | null;
    response_id: string;
    resume_path: string; // bridge endpoint that resumes the run (e.g. "/agent/approve")
    pending: { id: string; server_label: string; tool_name: string; arguments: string }[];
  } | null;
  // Proposed-but-not-yet-applied tap actions (a sandbox fix, a failed-run
  // resubmit). They stay offered in every subsequent next-steps card until
  // tapped or superseded - so exploring other options never strands the
  // Apply action, and the user never has to re-type "apply the fix" (which
  // would just re-run the analysis: the agent can propose, not apply).
  pendingActions: { key: string; title: string; data: any }[];
}

// Per-user conversation state. The key is the user's Entra identity combined
// with the conversation id (see stateKey), NEVER the conversation id alone: a
// channel can contain several members, and their tokens, reports, and pending
// actions must never mix. The unified capability-aware agent (estate engine +
// records + all Work IQ + knowledge base + the deep multi-agent pipeline as a
// tool, in one loop) is the default surface for every message; the agent
// itself decides when to convene the specialist pipeline, so there is no
// pre-router.
const stateByConversation = new Map<string, ConversationState>();

// Context lifetime: in-memory, swept after 24h of inactivity. (Production:
// durable bot-state storage keyed by the same per-user key; same shape.)
const CONTEXT_TTL_MS = 24 * 60 * 60 * 1000;

// The state key isolates one user's turn state from everyone else's in the
// same conversation. It combines the caller's Entra tenant + object id with
// the conversation id. The object id (aadObjectId) is the stable, unique Entra
// identifier; display names and email local parts are neither and are never
// used for identity. If Entra identity is unavailable (an unauthenticated
// local channel), the conversation id alone is used, which matches the
// single-user local model.
function userScope(context: TurnContext): string {
  const from: any = context.activity.from ?? {};
  const oid: string = from.aadObjectId || "";
  const tenant: string =
    (context.activity.conversation as any)?.tenantId ||
    (context.activity.channelData as any)?.tenant?.id ||
    "";
  return oid ? `${tenant}:${oid}` : "";
}

function stateKey(context: TurnContext): string {
  const raw = (context.activity.conversation?.id ?? "").split(";")[0];
  const scope = userScope(context);
  return scope ? `${scope}#${raw}` : raw;
}

function getState(conversationId: string): ConversationState {
  let s = stateByConversation.get(conversationId);
  if (s && Date.now() - s.lastActivityAt > CONTEXT_TTL_MS) {
    stateByConversation.delete(conversationId);
    s = undefined;
  }
  if (!s) {
    s = {
      report: null,
      question: "",
      offer: null,
      artifactCard: null,
      draftCard: null,
      history: [],
      actions: [],
      lastActivityAt: Date.now(),
      pendingAssist: null,
      pendingActions: [],
    };
    stateByConversation.set(conversationId, s);
  }
  return s;
}

function remember(s: ConversationState, role: "user" | "impactiq", text: string): void {
  s.history.push({ role, text: text.slice(0, 600) });
  if (s.history.length > 12) {
    s.history.splice(0, s.history.length - 12);
  }
  s.lastActivityAt = Date.now();
}

const storage = new MemoryStorage();

// Delegated (On-Behalf-Of) sign-in. The id keys the authorization handler AND
// the route auth gate. Only wired when IMPACTIQ_OAUTH_CONNECTION_NAME is set
// (production): the SDK then requires a one-time sign-in before a turn runs and
// we forward the resulting per-user token to the bridge. Empty locally → no
// auth wired; the bridge falls back to the browser sign-in there.
const AUTH_HANDLER_ID = "obo";
const AUTH_HANDLERS: string[] = config.oauthConnectionName ? [AUTH_HANDLER_ID] : [];

export const agentApp = new AgentApplication({
  storage,
  // Enable proactive messaging so we can deliver the manager handoff card to
  // the recipient outside the request/response flow.
  proactive: { storage },
  ...(config.oauthConnectionName
    ? {
        authorization: {
          [AUTH_HANDLER_ID]: {
            azureBotOAuthConnectionName: config.oauthConnectionName,
            title: "Sign in to ImpactIQ",
            text:
              "Sign in so ImpactIQ can look at your records and Work IQ signals " +
              "on your behalf. You only need to do this once.",
          },
        },
      }
    : {}),
});

// Fetch the signed-in user's token for the On-Behalf-Of flow. With
// AUTH_HANDLERS on the message route the SDK guarantees sign-in before the
// handler runs, so this returns a token; best-effort (the bridge returns a
// clean needs-signin message if it's ever missing). Returns undefined when
// auth isn't configured.
async function getUserToken(context: TurnContext): Promise<string | undefined> {
  if (!config.oauthConnectionName) return undefined;
  try {
    const tr = await agentApp.authorization.getToken(context, AUTH_HANDLER_ID);
    return tr?.token || undefined;
  } catch {
    return undefined;
  }
}

// Maps a UNIQUE user identifier -> the proactive conversation id stored for
// that person, so we can push a handoff card to a manager who has interacted
// with ImpactIQ at least once. Only globally-unique keys are stored: the Entra
// object id (aadObjectId) and, when the channel exposes it, the full user
// principal name / email. Display names and email local parts are deliberately
// NOT keys: they are not unique, and matching on them could deliver a handoff
// to the wrong person.
const convIdByKey = new Map<string, string>();

async function rememberConversation(context: TurnContext): Promise<string | undefined> {
  try {
    const convId = await agentApp.proactive.storeConversation(context);
    const from: any = context.activity.from ?? {};
    const uniqueKeys = [from.aadObjectId, from.userPrincipalName, from.email];
    for (const k of uniqueKeys) {
      if (k) convIdByKey.set(String(k).toLowerCase(), convId);
    }
    return convId;
  } catch {
    // Proactive storage unavailable -> the in-chat card render still works.
    return undefined;
  }
}

// A send function that works AFTER the inbound HTTP request has completed -
// the long agent turn runs in the background and delivers its results
// proactively, so the channel never times out and redelivers the message
// (Teams retries at ~15s; Copilot retries with fresh activity ids, which
// defeats id-based dedupe).
function proactiveSender(convId: string): (activity: any) => Promise<void> {
  return async (activity: any) => {
    const a = typeof activity === "string" ? { type: "message", text: activity } : activity;
    await agentApp.proactive.sendActivity(agentApp.adapter, convId, a as any);
  };
}

// Resolve a handoff recipient to a stored conversation id by EXACT match on a
// unique identifier only (Entra object id or full UPN/email). There is no
// display-name or email-local-part fallback: those are not unique, so guessing
// from them risks delivering to the wrong person. An unresolved recipient
// returns undefined and the caller falls back to rendering the card in-chat.
function resolveConvId(recipient: string): string | undefined {
  const r = (recipient || "").trim().toLowerCase();
  if (!r) return undefined;
  return convIdByKey.get(r);
}

// Headers for every bridge call: JSON + the shared secret (when configured) +
// a per-request HMAC signature over the timestamp, a random nonce, the path,
// and the body hash. The signature lets the bridge reject a captured request
// that is replayed or whose body was tampered with. Empty locally (the guard
// is a no-op); set in production so only the surface can reach the bridge API.
function bridgeHeaders(
  path: string,
  bodyString: string,
  userToken?: string
): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (userToken) h["X-ImpactIQ-User-Token"] = userToken;
  if (config.bridgeKey) {
    h["X-ImpactIQ-Key"] = config.bridgeKey;
    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = randomUUID();
    const bodyHash = createHash("sha256").update(bodyString, "utf8").digest("hex");
    const msg = `${ts}\n${nonce}\n${path}\n${bodyHash}`;
    h["X-ImpactIQ-Timestamp"] = ts;
    h["X-ImpactIQ-Nonce"] = nonce;
    h["X-ImpactIQ-Signature"] = createHmac("sha256", config.bridgeKey)
      .update(msg, "utf8")
      .digest("hex");
  }
  return h;
}

async function bridgePost(path: string, body: unknown, userToken?: string): Promise<any> {
  const bodyString = JSON.stringify(body);
  const resp = await fetch(`${config.bridgeUrl}${path}`, {
    method: "POST",
    headers: bridgeHeaders(path, bodyString, userToken),
    body: bodyString,
    signal: AbortSignal.timeout(config.bridgeTimeoutMs),
  });
  const data: any = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const detail = data?.detail || resp.statusText;
    throw new Error(`${resp.status}: ${detail}`);
  }
  return data;
}

// Drain the bridge's milestone buffer for a conversation. Polled during a long
// /agent turn so the user sees the play-by-play ("Mapping dependencies…",
// "✓ Governance check done", …) instead of a silent wait. Best-effort with a
// short timeout - a missed tick is harmless; the next one catches up.
async function drainProgress(conv: string, userToken?: string): Promise<string[]> {
  try {
    const bodyString = JSON.stringify({ conversation: conv });
    const r = await fetch(`${config.bridgeUrl}/progress`, {
      method: "POST",
      headers: bridgeHeaders("/progress", bodyString, userToken),
      body: bodyString,
      signal: AbortSignal.timeout(8000),
    });
    const d: any = await r.json().catch(() => ({}));
    return Array.isArray(d.events) ? d.events : [];
  } catch {
    return [];
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// Poll a launched bridge job. Returns {job_status: running|done|error|unknown};
// a transient network error is treated as "running" so we keep waiting.
async function pollResult(jobId: string, userToken?: string): Promise<any> {
  try {
    const bodyString = JSON.stringify({ job_id: jobId });
    const r = await fetch(`${config.bridgeUrl}/agent/result`, {
      method: "POST",
      headers: bridgeHeaders("/agent/result", bodyString, userToken),
      body: bodyString,
      signal: AbortSignal.timeout(8000),
    });
    const d: any = await r.json().catch(() => ({}));
    return d?.job_status ? d : { job_status: "running" };
  } catch {
    return { job_status: "running" };
  }
}

// Launch a long bridge turn as a JOB and poll it to completion, streaming
// /progress milestones via `send`. Every call here is sub-second, so a turn that
// runs minutes never sits on one open request - so neither Node's fetch
// (undici, ~300s) nor a host idle timeout (e.g. Azure App Service ~230s) can
// abort it. `bridgeTimeoutMs` is the TOTAL wait budget we enforce, not a
// single-request timeout. Back-compatible: a bridge that answers synchronously
// (no job_id) returns its result body directly.
async function runJob(
  startPath: string,
  body: unknown,
  conv: string,
  send: (a: any) => Promise<any>,
  userToken?: string
): Promise<any> {
  const start = await bridgePost(startPath, body, userToken);
  const jobId = start?.job_id;
  if (!jobId) return start;
  const deadline = Date.now() + config.bridgeTimeoutMs;
  let progressSeen = 0;
  let heartbeatFired = false;
  const heartbeatAt = Date.now() + 60_000;
  for (;;) {
    await sleep(3000);
    if (conv) {
      for (const line of await drainProgress(conv, userToken)) {
        progressSeen++;
        await send(line).catch(() => {});
      }
    }
    const r = await pollResult(jobId, userToken);
    if (r.job_status === "done") return r.result;
    if (r.job_status === "error") throw new Error(r.detail || "the analysis failed");
    if (r.job_status === "unknown")
      throw new Error("lost track of the analysis - please ask again");
    if (!heartbeatFired && progressSeen === 0 && Date.now() > heartbeatAt) {
      heartbeatFired = true;
      await send("Still working on it - this can take a moment.").catch(() => {});
    }
    if (Date.now() > deadline)
      throw new Error("this is taking longer than expected - please try again");
  }
}

// Channel-redelivery dedupe: small FIFO of recently seen activity ids.
const seenActivityIds: string[] = [];
const SEEN_ACTIVITY_MAX = 200;
function alreadyHandled(id: string | undefined): boolean {
  if (!id) return false;
  if (seenActivityIds.includes(id)) return true;
  seenActivityIds.push(id);
  if (seenActivityIds.length > SEEN_ACTIVITY_MAX) {
    seenActivityIds.shift();
  }
  return false;
}

// Second wall: Copilot redeliveries arrive with FRESH activity ids, so also
// drop an identical question in the same conversation within a short window
// (a real user re-ask lands well outside it once turns ack in seconds).
const lastQuestionByConv = new Map<string, { text: string; at: number }>();
const DUP_WINDOW_MS = 60_000;
function duplicateQuestion(conversationId: string, text: string): boolean {
  const prev = lastQuestionByConv.get(conversationId);
  const now = Date.now();
  lastQuestionByConv.set(conversationId, { text, at: now });
  return !!prev && prev.text === text && now - prev.at < DUP_WINDOW_MS;
}

function cardActivity(card: any): any {
  return {
    type: "message",
    attachments: [
      { contentType: "application/vnd.microsoft.card.adaptive", content: card },
    ],
  };
}

// Next-step options as an Adaptive Card with one Action.Submit per step,
// rendered UNDER the response. Teams `suggestedActions` can't do this - they
// are 1:1-only, unsupported once the turn has attachments (our cards), capped
// in display, and always render by the compose box, never inline (Microsoft
// Learn, "Add card actions in a bot"). Action.Submit buttons render reliably
// as a list in BOTH Teams and Copilot. A tap arrives as a card action
// {action:"suggested_step", query} → we run it like a typed message, so the
// chain continues (each reply produces a fresh next-steps card).
function nextStepsCard(suggestions: any[], pending: { title: string; data: any }[] = []): any | null {
  // Persistent pending actions (Apply the fix / Resubmit) FIRST, so a prepared
  // action stays one tap away across turns; then the model's fresh next steps.
  const pendingActions = (pending || []).map((p) => ({
    type: "Action.Submit",
    title: p.title.slice(0, 48),
    data: p.data,
  }));
  const suggestionActions = (suggestions || []).slice(0, 6).map((s: any) => ({
    type: "Action.Submit",
    title: String(s.title || s.query || "").slice(0, 48),
    data: { action: "suggested_step", query: String(s.query || s.title || "") },
  }));
  const actions = [...pendingActions, ...suggestionActions];
  if (!actions.length) return null;
  return {
    type: "AdaptiveCard",
    $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
    version: "1.4", // Teams mobile renders <=1.2 fully; 1.4 actions are fine on desktop/web
    body: [
      { type: "TextBlock", text: "Next steps", weight: "Bolder", isSubtle: true, wrap: true },
    ],
    actions,
  };
}

// Track a proposed-but-unapplied tap action so it persists in next-steps.
function addPendingAction(state: ConversationState, key: string, title: string, data: any): void {
  state.pendingActions = (state.pendingActions || []).filter((p) => p.key !== key);
  state.pendingActions.push({ key, title, data });
  if (state.pendingActions.length > 4) state.pendingActions.shift();
}

function clearPendingAction(state: ConversationState, key: string): void {
  state.pendingActions = (state.pendingActions || []).filter((p) => p.key !== key);
}

// Pull the primary (non-discard) Action.Submit out of a proposal card so we
// can re-offer it as a persistent next-step button.
function primaryCardAction(card: any): { action: string; [k: string]: any } | null {
  for (const a of card?.actions ?? []) {
    const d = a?.data;
    if (d && d.action && d.action !== "discard") return d;
  }
  return null;
}

// After a card action (Apply fix, resubmit, confirm), keep the chain going:
// ask the bridge for fresh next-step options grounded in what just happened.
async function sendChipsAfter(
  sender: (a: any) => Promise<any>,
  state: ConversationState,
  lastReply: string
): Promise<void> {
  try {
    const r = await bridgePost("/suggest", {
      history: state.history,
      last_reply: lastReply,
    });
    const card = nextStepsCard(
      Array.isArray(r.suggestions) ? r.suggestions : [],
      state.pendingActions || []
    );
    if (card) {
      await sender(cardActivity(card));
    }
  } catch {
    /* next-step options are best-effort - never block the action result */
  }
}

function offerCard(offer: any): any {
  return {
    type: "AdaptiveCard",
    $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
    version: "1.5",
    body: [{ type: "TextBlock", text: offer.intro, wrap: true }],
    actions: [
      { type: "Action.Submit", title: offer.label, data: { action: offer.action } },
      { type: "Action.Submit", title: "No thanks", data: { action: "dismiss_offer" } },
    ],
  };
}

// Turn a gated tool call into a plain, human sentence for the approval card,
// so the user sees exactly what they're approving (no raw tool names / JSON).
function fmtRecipients(v: any): string {
  if (Array.isArray(v)) {
    return v
      .map((r: any) => r?.name || r?.address || r?.emailAddress?.address || String(r))
      .join(", ");
  }
  return v ? String(v) : "";
}

function mailBodyPreview(a: any): string {
  const text = String(a.body || a.content || a.bodyContent || a.comment || "").trim();
  if (!text) return "";
  const trimmed = text.length > 600 ? `${text.slice(0, 600)}…` : text;
  return `\n\n> ${trimmed.replace(/\n/g, "\n> ")}`;
}

function describeAction(p: { tool_name: string; arguments: string }): string {
  let a: any = {};
  try {
    a = JSON.parse(p.arguments || "{}");
  } catch {
    a = {};
  }
  const to = fmtRecipients(a.toRecipients || a.to || a.recipients);
  switch (p.tool_name) {
    case "CreateEvent":
      return `📅 **Book a meeting**${a.subject ? `: "${a.subject}"` : ""}${
        a.start ? ` - ${a.start}${a.end ? ` to ${a.end}` : ""}` : ""
      }${Array.isArray(a.attendees) && a.attendees.length ? ` with ${a.attendees.join(", ")}` : ""}.`;
    case "UpdateEvent":
      return `📅 **Update a calendar event**${a.subject ? `: "${a.subject}"` : ""}.`;
    case "SendMessageToUser":
      return `💬 **Send a Teams message** to ${a.userId || a.recipient || "a person"}:\n\n> ${
        a.message || a.content || a.body || "(message body)"
      }`;
    case "SendMessageToChannel":
      return `💬 **Post to a Teams channel** (${a.channelId || a.channel || "channel"}):\n\n> ${
        a.message || a.content || a.body || "(message body)"
      }`;
    // Work IQ Mail tools. Render an email-style preview (sent as a chat
    // message, where full markdown - bold labels + blockquoted body -
    // actually renders): this preview is the user's chance to read what
    // lands in their mailbox.
    case "CreateDraftMessage":
    case "UpdateDraft":
      return (
        `Here's a preview of the ${p.tool_name === "UpdateDraft" ? "updated draft" : "draft email"} I'll create in your Outlook - nothing is sent; you review and send it yourself:\n` +
        `${a.subject ? `\n**Subject:** ${a.subject}` : ""}` +
        `${to ? `\n**To:** ${to}` : ""}` +
        `\n\n**Body:**` +
        mailBodyPreview(a)
      );
    case "ReplyToMessage":
    case "ReplyAllToMessage": {
      const sendNow = a.sendImmediately === true || a.sendImmediately === "true";
      return (
        `Here's the ${p.tool_name === "ReplyAllToMessage" ? "reply-all" : "reply"} draft I'll create in your Outlook` +
        (sendNow
          ? ` - ⚠️ this call would SEND IMMEDIATELY, not draft. Deny unless you asked for that.`
          : ` - it stays in Drafts; you review and send it yourself:`) +
        `\n\n**Body:**` +
        mailBodyPreview(a)
      );
    }
    case "FlagEmail":
      return `🚩 **Flag an email** for follow-up${a.flagStatus ? ` (${a.flagStatus})` : ""}.`;
    default:
      return `Run **${p.tool_name}** with: ${(p.arguments || "{}").slice(0, 300)}`;
  }
}

// The full action previews are sent as chat MESSAGES (where markdown like
// blockquoted email bodies renders properly - Adaptive Cards don't support
// it); this compact card carries only the decision. Nothing mutating happens
// until this tap - confirm-before-act, on every action.
function approvalCard(
  pending: { id: string; tool_name: string; arguments: string }[],
  intro: string
): any {
  const body: any[] = [
    {
      type: "TextBlock",
      text:
        intro ||
        (pending.length > 1
          ? "Shall I go ahead with the actions previewed above?"
          : "Shall I go ahead as previewed above - or tell me what to change?"),
      wrap: true,
      weight: "Bolder",
    },
  ];
  return {
    type: "AdaptiveCard",
    $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
    version: "1.5",
    body,
    actions: [
      // Plain Action.Submit only: the msteams messageBack wrapper echoes the
      // tap as the user's message in Teams, but Copilot drops its value
      // payload, so the tap would reach the MODEL as text instead of the
      // action handler. Reliability wins.
      { type: "Action.Submit", title: "Approve", data: { action: "approve_assist" } },
      { type: "Action.Submit", title: "Deny", data: { action: "deny_assist" } },
    ],
  };
}

agentApp.onConversationUpdate("membersAdded", async (context: TurnContext) => {
  // Fire-and-forget estate prewarm: by the time the user types their first
  // question, the dependency graph is already cached bridge-side. No welcome
  // message - a static greeting adds little; the first real reply (with its
  // suggested next steps) does the onboarding.
  bridgePost("/warmup", {}).catch(() => {});
});

async function handleCardAction(
  context: TurnContext,
  value: any,
  convId?: string,
  userToken?: string
): Promise<void> {
  const conversationId = stateKey(context);
  const state = getState(conversationId);
  state.userToken = userToken; // forwarded to the bridge on as-user actions
  const artifact = state?.report?.generated_artifact;
  const user = context.activity.from?.name || "teams-user";
  // Slow card actions (sandbox fix, resubmit, bounded record write) can run
  // >15s - the Copilot card-action invoke would time out ("Something went
  // wrong") if we block on them. So fast-ack in-request, then run the work in
  // the background and deliver proactively (same pattern as the message
  // handler). `send` is proactive when available, else falls back to the
  // in-request context.
  const send = convId
    ? proactiveSender(convId)
    : async (a: any) => {
        await context.sendActivity(a);
      };
  const background = (work: () => Promise<void>): void => {
    void work().catch((e: any) => send(`❌ ${e?.message ?? e}`).catch(() => {}));
  };

  switch (value.action) {
    // ── step 1: the user accepted an offer ────────────────────────────────
    case "draft_notification": {
      if (!state?.draftCard) {
        await context.sendActivity("I've lost that draft - please re-ask the question.");
        return;
      }
      await context.sendActivity(cardActivity(state.draftCard));
      return;
    }
    case "show_remediation":
    case "show_ticket":
    case "show_backfill":
    case "show_reuse": {
      if (!state?.artifactCard) {
        await context.sendActivity("I've lost that draft - please re-ask the question.");
        return;
      }
      await context.sendActivity(cardActivity(state.artifactCard));
      return;
    }
    case "dismiss_offer": {
      await context.sendActivity("👍 No problem - it stays a draft. Anything else?");
      return;
    }

    // ── step 2: confirmed actions (server re-gates every one) ─────────────
    case "create_draft": {
      if (!artifact) {
        await context.sendActivity("I've lost the draft context - please re-ask the question.");
        return;
      }
      await context.sendActivity("✍️ Putting that in your Outlook Drafts...");
      try {
        const res = await bridgePost("/action/create_draft", {
          artifact,
          user,
          confirmed: true, // this handler ONLY runs from an explicit tap
          edited_text: (value.edited_text || "").trim() || null, // user's edits win
        }, state.userToken);
        state.actions.push(`Created an Outlook draft (audit ${res.audit_event_id})`);
        remember(state, "impactiq", "Created an Outlook draft for the user to review and send.");
        await context.sendActivity(
          `✅ **Draft saved to your Outlook Drafts** (audit ${res.audit_event_id}). ` +
            "Open Outlook to review, set the recipient, and send it yourself - " +
            "I don't send anything."
        );
      } catch (e: any) {
        await context.sendActivity(`❌ Couldn't create the draft: ${e.message}`);
      }
      return;
    }
    case "discard": {
      await context.sendActivity("🗑️ Draft discarded. Nothing was sent.");
      return;
    }
    // A tapped "next step" option - run it exactly like the user typed it, so
    // it chains (and produces a fresh next-steps card). Action.Submit is used
    // (not suggestedActions) because Teams can't list multiple of those under
    // a reply once the turn has attachments (Microsoft Learn).
    case "suggested_step": {
      const q = String(value.query || "").trim();
      if (!q) {
        await context.sendActivity("That option expired - please ask again.");
        return;
      }
      await processQuestion(context, state, q, conversationId, convId);
      return;
    }
    // Apply a proposed sandbox fix, behind the explicit tap.
    case "apply_sandbox_fix": {
      clearPendingAction(state, "sandbox_fix"); // consumed - stop re-offering it
      await context.sendActivity("🔧 Applying the fix in the sandbox..."); // fast ack
      background(async () => {
        const res = await bridgePost("/action/sandbox_fix", {
          fix_id: value.fix_id,
          confirmed: true,
          user,
        }, state.userToken);
        const lines: string[] = [`**${res.title}** - applied in the sandbox.`];
        for (const d of res.done ?? []) {
          lines.push(`✅ ${d.component}: ${d.change}`);
        }
        for (const p of res.partial ?? []) {
          lines.push(`⚠️ ${p.component}: ${p.change} - ${p.reason}`);
        }
        for (const o of res.outstanding ?? []) {
          lines.push(`⬜ Outstanding: ${o.step} - ${o.reason}`);
        }
        if ((res.done ?? []).length === 0 && (res.partial ?? []).length === 0) {
          lines.push("Nothing could be applied - see the outstanding items above.");
        }
        const summary = lines.join("\n\n");
        remember(state, "impactiq", summary);
        await send(summary);
        await sendChipsAfter(send, state, summary);
      });
      return;
    }
    // Resubmit one failed live-flow run, behind the per-run tap.
    case "apply_resubmit_run": {
      clearPendingAction(state, `resubmit:${value.resubmit_id}`); // consumed
      await context.sendActivity("▶️ Resubmitting the run..."); // fast ack
      background(async () => {
        const res = await bridgePost("/action/resubmit_run", {
          resubmit_id: value.resubmit_id,
          confirmed: true,
          user,
        }, state.userToken);
        const summary = `✅ Run resubmitted for **${res.flow}** - it is re-running against the current live definition now. Check the flow's run history in a minute to confirm it succeeded.`;
        remember(state, "impactiq", summary);
        await send(summary);
        await sendChipsAfter(send, state, summary);
      });
      return;
    }
    case "confirm_remediation": {
      if (!artifact) {
        await context.sendActivity("I've lost the proposal context - please re-ask the question.");
        return;
      }
      await context.sendActivity("✍️ Applying the fix..."); // fast ack
      background(async () => {
        let res: any;
        try {
          res = await bridgePost("/action/remediate", {
            artifact,
            user,
            confirmation_type: value.confirmation, // "tap" | "typed"
            typed_value: value.typed_confirmation ?? null,
            user_referenced_document: false,
          }, state.userToken);
        } catch (e: any) {
          await send(`❌ Write refused: ${e.message}`);
          return;
        }
        state.actions.push(
          `Applied a data fix to record ${res.record_id} (audit ${res.audit_event_id})`
        );
        remember(state, "impactiq", `Applied fix to record ${res.record_id}.`);
        const summary =
          `✅ **Fix applied** to record \`${res.record_id}\` (audit ${res.audit_event_id}). ` +
          `Changed: ${Object.entries(res.changes)
            .map(([k, v]) => `${k} → ${v}`)
            .join(", ")}`;
        await send(summary);
        await sendChipsAfter(send, state, summary);
      });
      return;
    }
    // ── gated Work IQ action: approve/deny, then resume the SAME run ───────
    case "approve_assist":
    case "deny_assist": {
      const pa = state.pendingAssist;
      if (!pa) {
        await context.sendActivity("That approval has expired - please ask again.");
        return;
      }
      const approve = value.action === "approve_assist";
      const approvals: Record<string, boolean> = {};
      for (const p of pa.pending) approvals[p.id] = approve;
      state.pendingAssist = null; // consume; a resume may set a fresh one
      if (approve) {
        state.actions.push(`Approved: ${pa.pending.map((p) => p.tool_name).join(", ")}`);
        await context.sendActivity("✅ Approved - carrying that out...");
      } else {
        await context.sendActivity("👍 Skipped - I won't do that.");
      }
      // Resumes are long turns too - same fast-return + proactive-delivery
      // pattern as the message handler, so the tap is never redelivered.
      const resumeConvId = await rememberConversation(context);
      const resumeSend = resumeConvId
        ? proactiveSender(resumeConvId)
        : async (a: any) => {
            await context.sendActivity(a);
          };
      const resume = async () => {
        // Full opaque conversation id - a truncated id is a small namespace
        // that can collide across conversations in a multi-user deployment.
        const conv = (context.activity.conversation?.id ?? "").split(";")[0];
        try {
          // Same job/poll path as a fresh turn - a resume is a long turn too
          // (it keeps running the agent loop after the decision).
          const res = await runJob(
            pa.resume_path || "/agent/approve",
            {
              agent_name: pa.agent_name,
              agent_version: pa.agent_version,
              response_id: pa.response_id,
              approvals,
              pending: pa.pending,
              user,
            },
            conv,
            resumeSend,
            state.userToken
          );
          await renderAssistResult(resumeSend, state, res);
        } catch (e: any) {
          await resumeSend(`❌ ${e.message}`).catch(() => {});
        }
      };
      if (resumeConvId) {
        void resume();
      } else {
        await resume();
      }
      return;
    }
    // Interactive handoff: the sender delivers, the manager resumes.
    case "notify_manager": {
      if (!artifact || artifact.artifact_type !== "manager_handoff") {
        await context.sendActivity("I've lost the handoff context - please re-ask the question.");
        return;
      }
      const editedText = (value.edited_text || "").trim();
      const toSend = editedText ? { ...artifact, draft_text: editedText } : artifact;
      await context.sendActivity(`📨 Notifying ${toSend.recipient}...`);
      try {
        const res = await bridgePost("/handoff/deliver", {
          artifact: toSend,
          user,
          confirmed: true, // this handler only runs from the sender's explicit tap
        }, state.userToken);
        state.actions.push(
          `Notified ${res.recipient} with an interactive handoff (baton ${res.baton_id}, audit ${res.audit_event_id})`
        );
        remember(state, "impactiq", `Sent an interactive handoff to ${res.recipient}.`);

        // Try to PUSH the card to the manager's own Teams chat. Falls back to
        // rendering it here if we don't have a conversation for them yet
        // (they need to have messaged ImpactIQ once).
        let pushed = false;
        const convId = resolveConvId(res.recipient);
        if (convId) {
          try {
            await agentApp.proactive.sendActivity(agentApp.adapter, convId, cardActivity(res.card));
            pushed = true;
          } catch {
            pushed = false;
          }
        }
        if (pushed) {
          await context.sendActivity(
            `✅ **Sent to ${res.recipient} in Teams.** They'll get an actionable card and can ` +
              "dig into it from *their own* side - only they can see their team's context."
          );
        } else {
          await context.sendActivity(
            `✅ **Notification ready for ${res.recipient}.** I couldn't reach them proactively ` +
              "(they need to have opened ImpactIQ once), so here's the card they'll act on:"
          );
          await context.sendActivity(cardActivity(res.card));
        }
      } catch (e: any) {
        await context.sendActivity(`❌ Couldn't send the handoff: ${e.message}`);
      }
      return;
    }
    case "baton_tell_more": {
      const batonId = value.baton_id;
      if (!batonId) {
        await context.sendActivity("That handoff has expired - please ask again.");
        return;
      }
      await context.sendActivity("🔎 Looking at what this means in *your* context - one moment...");
      try {
        const res = await bridgePost("/handoff/resume", { baton_id: batonId, user }, state.userToken);
        remember(state, "impactiq", res.summary_text || "");
        await context.sendActivity(
          "Here's what I can see from **your** vantage point (visible only to you):"
        );
        await context.sendActivity(res.summary_text || "I couldn't pull a clear read this time.");
      } catch (e: any) {
        await context.sendActivity(`❌ ${e.message}`);
      }
      return;
    }
    case "baton_ack": {
      try {
        await bridgePost("/handoff/ack", {
          baton_id: value.baton_id,
          stance: value.stance || "",
          user,
        });
      } catch {
        // acknowledgement is best-effort - never block the user on it
      }
      await context.sendActivity(
        value.stance === "clear"
          ? "👍 Noted - no concern. I've logged your response."
          : "👍 Thanks - I've logged that you'll review it."
      );
      return;
    }
    case "route_backfill": {
      await context.sendActivity(
        "📄 Bulk changes are never applied directly - route the blueprint to the suggested " +
          "approver via a notification instead."
      );
      return;
    }
    default: {
      await context.sendActivity(`(unhandled card action: ${value.action ?? "?"})`);
    }
  }
}

// Listen for ANY message to be received. MUST BE AFTER ANY OTHER MESSAGE HANDLERS
agentApp.onActivity(ActivityTypes.Message, async (context: TurnContext) => {
  // Teams REDELIVERS an activity (same id) if the bot doesn't complete the
  // HTTP request within ~15s - and our turns legitimately take 60s+. Without
  // this guard a slow turn runs twice and the user sees duplicate answers.
  if (alreadyHandled(context.activity.id)) {
    console.log(`[surface] duplicate delivery of activity ${context.activity.id} - skipped`);
    return;
  }

  // Register the sender's conversation so we can later push a handoff card to
  // them proactively (the manager just needs to message ImpactIQ once) - and
  // so THIS turn's results can be delivered after the handler returns.
  const convId = await rememberConversation(context);

  // The per-user On-Behalf-Of token (sign-in is already guaranteed by
  // AUTH_HANDLERS on this route when auth is configured). Forwarded to the
  // bridge so the pipeline runs as this user. Undefined when auth isn't
  // configured → bridge uses its local fallback.
  const userToken = await getUserToken(context);

  // Adaptive Card Action.Submit arrives as a message with `value` and no text.
  const value: any = (context.activity as any).value;
  if (value && typeof value === "object" && value.action) {
    await handleCardAction(context, value, convId, userToken);
    return;
  }

  const question = (context.activity.text || "").trim();
  if (!question) {
    return;
  }
  // Per-user, per-conversation key. Teams/Copilot conversation ids can carry a
  // ";messageid=..." suffix (stripped in stateKey) and a channel can hold many
  // members, so state and dedupe are keyed by the caller's Entra identity plus
  // the conversation, never the conversation id alone.
  const conversationId = stateKey(context);
  console.log(
    `[surface] msg conv=…${conversationId.slice(-8)} act=${context.activity.id} ` +
      `text="${question.slice(0, 50)}"`
  );
  if (duplicateQuestion(conversationId, question)) {
    console.log(`[surface] duplicate question within ${DUP_WINDOW_MS / 1000}s - skipped`);
    return;
  }
  const state = getState(conversationId); // TTL-swept; fresh after 24h idle
  state.userToken = userToken;
  await processQuestion(context, state, question, conversationId, convId);
}, AUTH_HANDLERS);

// Run ONE user message end-to-end: front-door triage (/ack), then the unified
// agent (/agent) in the background with proactive delivery. Shared by the
// message handler AND a tapped "next step" option, so a tapped option behaves
// exactly like the user typing that request - and its reply produces a fresh
// next-steps card, continuing the chain.
async function processQuestion(
  context: TurnContext,
  state: ConversationState,
  question: string,
  conversationId: string,
  convId?: string
): Promise<void> {
  remember(state, "user", question);
  state.question = question;
  // Front-door triage: the first hop either ANSWERS outright (greetings,
  // chit-chat, capability questions - final=true, no agent turn needed) or
  // returns the context-aware "working on it" line for real work.
  let ackLine: string | null = "On it - give me a moment.";
  try {
    const a = await bridgePost("/ack", {
      question,
      history: state.history,
      // Full opaque conversation id - truncation risks cross-conversation
      // collisions in server-side progress/memory keyed by this value.
      conversation: conversationId,
    }, state.userToken);
    const line = String(a.text ?? "").trim();
    if (a.final && line) {
      remember(state, "impactiq", line);
      await context.sendActivity(line);
      return; // answered at the front door - no tools could have helped
    }
    ackLine = line || null;
  } catch {
    // ack is best-effort - keep the generic fallback on errors
  }
  if (ackLine) {
    await context.sendActivity(ackLine);
  }

  // Finish the turn in the BACKGROUND and deliver proactively: the inbound
  // HTTP request completes right after the ack, so the channel never times
  // out and redelivers (redelivery surfaces as duplicate answers in Copilot).
  const send = convId
    ? proactiveSender(convId)
    : async (a: any) => {
        await context.sendActivity(a);
      };
  const run = async () => {
    const conv = conversationId; // full id - see the /ack note above
    try {
      // Job/poll: launch the turn on the bridge and poll to completion, streaming
      // the play-by-play. No single long-lived fetch, so host/undici idle
      // timeouts can't abort a minutes-long analysis.
      const res = await runJob(
        "/agent",
        { request: question, history: state.history, conversation: conv },
        conv,
        send,
        state.userToken
      );
      // Final flush: post any milestones emitted in the last poll gap before
      // the answer lands (e.g. "Weighing the verdict…").
      for (const line of await drainProgress(conv, state.userToken)) await send(line).catch(() => {});
      await renderAssistResult(send, state, res);
    } catch (e: any) {
      await send(`❌ ${e.message}`).catch(() => {});
    }
  };
  if (convId) {
    void run(); // handler returns now; results arrive proactively
  } else {
    await run(); // no proactive store - fall back to the in-request path
  }
}

// Render an /agent result: post any text; if the agent convened the deep
// pipeline, capture its validated report + actionable cards (the record-fix
// and notify flows stay identical); if the run paused on a gated mutating
// tool, stash the resume handle and show the Approve/Deny card. A resume can
// pause again, so this is reused on both legs.
async function renderAssistResult(
  send: (activity: any) => Promise<any>,
  state: ConversationState,
  res: any
): Promise<void> {
  const pending: any[] =
    res.status === "pending_approval" && Array.isArray(res.pending_approvals)
      ? res.pending_approvals
      : [];
  // Persistent actions that existed BEFORE this turn - these go in this turn's
  // next-steps card. A proposal shown THIS turn provides its own Apply card,
  // so it's added to pendingActions for FUTURE turns, not duplicated now.
  const priorPending = [...(state.pendingActions || [])];
  // Next-step options. Suppressed only for a bare proposal/confirm card whose
  // own buttons are the entire next step (and carry context a generic option
  // can't): a record-fix proposal, a sandbox fix, a resubmit. A deep impact
  // report is not one of these - its optional "offer" is just one of several
  // next moves, so options still show alongside it. None while paused for
  // approval either. Rendered as an Action.Submit card (see nextStepsCard)
  // sent last, since Teams suggestedActions can't list multiple under a reply.
  const suppressChips =
    !!res.record_fix_card ||
    !!res.sandbox_fix_card ||
    (Array.isArray(res.resubmit_cards) && res.resubmit_cards.length > 0);
  const suggestions: any[] =
    pending.length === 0 && !suppressChips && Array.isArray(res.suggestions)
      ? res.suggestions
      : [];
  if (res.report) {
    state.report = res.report;
    state.offer = res.offer ?? null;
    state.artifactCard = res.artifact_card ?? null;
    state.draftCard = res.draft_card ?? null;
  }
  if (res.text && String(res.text).trim()) {
    remember(state, "impactiq", res.text);
    await send(res.text);
  }
  // Retrieved records render as a swipeable carousel of cards, each deep-
  // linking to the real (editable) Power Apps form. Read-only in chat -
  // record writes stay behind the bounded preview-and-confirm flow.
  if (Array.isArray(res.record_cards) && res.record_cards.length) {
    console.log(`[surface] rendering ${res.record_cards.length} record card(s)`);
    try {
      await send({
        type: "message",
        attachmentLayout: res.record_cards.length > 1 ? "carousel" : "list",
        attachments: res.record_cards.map((c: any) => ({
          contentType: "application/vnd.microsoft.card.adaptive",
          content: c,
        })),
      } as any);
    } catch (e: any) {
      // Carousel activity rejected (channel quirk) - fall back to one card
      // per message rather than showing nothing.
      console.error(`[surface] carousel send failed: ${e?.message}`);
      for (const c of res.record_cards) {
        await send(cardActivity(c));
      }
    }
    remember(state, "impactiq", `(showed ${res.record_cards.length} record card(s))`);
  }
  if (res.report && res.offer) {
    await send(cardActivity(offerCard(res.offer)));
  } else if (res.record_fix_card) {
    // Bounded record-fix proposal (no deep-pipeline offer wrapping it): show
    // the preview-and-confirm card directly; the confirm tap re-gates
    // server-side via /action/remediate exactly as in the report flow.
    await send(cardActivity(res.record_fix_card));
    remember(state, "impactiq", "(proposed a record fix - preview card shown)");
  }
  // A proposed sandbox fix renders as its Apply card - the write happens
  // only behind that tap (fix-only, sandbox-only, role-gated). Also register
  // it as a persistent next-step so the Apply stays one tap away even after
  // the user explores other options.
  if (res.sandbox_fix_card) {
    await send(cardActivity(res.sandbox_fix_card));
    const apply = primaryCardAction(res.sandbox_fix_card);
    if (apply) addPendingAction(state, "sandbox_fix", "Apply the proposed sandbox fix", apply);
    remember(state, "impactiq", "(proposed a sandbox fix - Apply card shown)");
  }
  // Proposed failed-run resubmits: one card per run; the rerun happens only
  // behind the per-run tap.
  if (Array.isArray(res.resubmit_cards) && res.resubmit_cards.length) {
    for (const c of res.resubmit_cards) {
      await send(cardActivity(c));
      const run = primaryCardAction(c);
      if (run) addPendingAction(state, `resubmit:${run.resubmit_id}`, "Resubmit the failed run", run);
    }
    remember(state, "impactiq", "(proposed failed-run resubmit - card shown)");
  }
  // Next-step options as the LAST activity - an Action.Submit card listing
  // persistent pending actions (Apply the fix…) first, then every fresh
  // option under the response (reliable in Teams AND Copilot, unlike
  // suggestedActions). Bare proposal cards suppress the GENERATED options,
  // but the persistent Apply still shows so the prepared action isn't lost.
  {
    const card = nextStepsCard(suggestions, priorPending);
    if (card) await send(cardActivity(card));
  }
  if (pending.length) {
    state.pendingAssist = {
      agent_name: res.agent_name,
      agent_version: res.agent_version ?? null,
      response_id: res.resume_response_id,
      resume_path: res.resume_path || "/agent/approve",
      pending,
    };
    // Full previews as chat messages (proper markdown: bold labels, the
    // email body in a quoted block - like a real mail client preview), then
    // one compact decision card.
    for (const p of pending) {
      await send(describeAction(p));
    }
    await send(cardActivity(approvalCard(pending, "")));
    return;
  }
  state.pendingAssist = null;
  const showedSomething =
    (Array.isArray(res.record_cards) && res.record_cards.length) || res.report;
  if ((!res.text || !String(res.text).trim()) && !showedSomething) {
    // Rare (the agent loop nudges the model to answer) - when it still
    // happens, be honest rather than send a bare "Done.".
    await send(
      "Hmm - I finished the lookups but didn't compose an answer. Could you ask that again?"
    );
  }
}

