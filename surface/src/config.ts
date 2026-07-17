const config = {
  // The local ImpactIQ Python bridge. The Custom Engine Agent is a thin
  // surface: all analysis, bounded-write gates, and the audit chain live on
  // the Python side.
  bridgeUrl: process.env.IMPACTIQ_BRIDGE_URL || "http://127.0.0.1:8787",
  // The /agent run is fire-and-forget with proactive delivery (see the
  // `void run()` path in agent.ts), so the inbound channel turn returns after
  // the ack and never times out - this fetch timeout is ONLY a safety net
  // against a genuinely hung bridge, not a budget for a slow one. A healthy
  // turn that merely runs long (a lengthy context search + a transient 5xx
  // retry + sequential synthesis) must NOT be aborted: the bridge always
  // completes and the heartbeat covers the wait. A tighter limit could clip
  // such turns and discard the finished report, so give generous headroom;
  // the bridge's own per-call retries + specialist budget bound the true
  // worst case well under this.
  bridgeTimeoutMs: Number(process.env.IMPACTIQ_BRIDGE_TIMEOUT_MS || 600000),
  // Shared secret for the bridge auth guard. Sent as X-ImpactIQ-Key on every
  // bridge call. Empty locally (guard is a no-op); set in production on BOTH
  // the surface and bridge App Services so only the surface can reach the API.
  bridgeKey: process.env.IMPACTIQ_BRIDGE_KEY || "",
  // Azure Bot OAuth connection name for the delegated (On-Behalf-Of) sign-in.
  // When set (production), every message turn requires a one-time sign-in and
  // the resulting per-user token is forwarded to the bridge as
  // X-ImpactIQ-User-Token for the On-Behalf-Of flow. Empty locally → no auth
  // wired.
  oauthConnectionName: process.env.IMPACTIQ_OAUTH_CONNECTION_NAME || "",
};

export default config;
