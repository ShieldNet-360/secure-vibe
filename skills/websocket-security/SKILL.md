---
id: websocket-security
version: "1.0.0"
title: "WebSocket Security"
description: "Secure WebSocket endpoints: Origin validation, auth on handshake, message size/rate limits, wss-only, reconnection backoff"
category: prevention
severity: high
applies_to:
  - "when generating a WebSocket / Socket.IO / SignalR server"
  - "when wiring real-time messaging, presence, or collaborative editing"
  - "when reviewing /ws or wss:// endpoint exposure"
languages: ["javascript", "typescript", "python", "go", "java", "csharp", "ruby", "elixir"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "cors-security", "auth-security"]
last_updated: "2026-06-20"
sources:
  - "OWASP WebSocket Security Cheat Sheet"
  - "RFC 6455 — The WebSocket Protocol"
  - "CWE-1385: Missing Origin Validation in WebSockets"
  - "CWE-770: Allocation of Resources Without Limits or Throttling"
---

# WebSocket Security

## Rules (for AI agents)

### ALWAYS
- Validate the **`Origin` header** on the WebSocket upgrade handshake
  against an allowlist. CORS does **not** apply to WebSockets — the
  browser will happily upgrade cross-origin and let JavaScript on
  `attacker.com` open `wss://api.example.com/ws` with the user's
  cookies (Cross-Site WebSocket Hijacking).
- Require authentication **on the handshake** itself, not as the first
  message after connect. Either:
  1. Cookie-based auth on the HTTP upgrade (and CSRF-protect by
     verifying Origin), or
  2. A short-lived signed token (5–10 minute lifetime) in the
     `Sec-WebSocket-Protocol` subprotocol header, or
  3. A signed query parameter token.
  Never trust a `subscribe` / `auth` message after the upgrade — by
  that point the connection has already been opened with the
  authenticated cookie context.
- Use **`wss://`** only in production. Plain `ws://` over the open
  internet exposes session tokens, message contents, and CSRF
  primitives to any on-path observer.
- Enforce **max message size** at the server (typical: 32 KiB for
  chat, 256 KiB for collaborative editing, much higher only when the
  use case demands it and the auth bar is high). Without a limit, a
  single open socket can OOM the server.
- Enforce a **message rate limit** per connection (e.g. 60
  messages/minute) and a **connection rate limit** per source IP /
  per authenticated user. Real-time abuse (chat spam, presence
  ping flood) is a frequent DoS source.
- Implement **ping / pong heartbeats** (every 20–30 s) and close the
  connection on missed pong. Half-open TCP sockets accumulate behind
  load balancers otherwise.
- On the client side, use **bounded exponential backoff** for
  reconnection (e.g. base 1 s, factor 2, max 60 s, jitter ±20%).
  A naïve `setTimeout(connect, 0)` reconnect loop melts the server
  during outages.
- Treat each WebSocket message as a separate request for the
  purposes of **input validation** and **authorization**. The user's
  permissions can change after the socket is open (logout, role
  change, account lock) — re-check on each privileged action.

### NEVER
- Skip Origin validation because "it's a WebSocket, CORS doesn't
  apply." That's exactly why you have to do it yourself. The
  documented attack is Cross-Site WebSocket Hijacking, demonstrated
  publicly in 2013 and still common in 2024 bug-bounty reports.
- Use a session cookie as a long-lived WebSocket token. If the WS
  connection is supposed to survive multiple tabs / pages, issue a
  refreshable short-lived JWT in the subprotocol; don't rely on the
  cookie sticking around forever.
- Allow arbitrary `subprotocols` from the client to influence
  server-side routing without an allowlist. Subprotocol negotiation
  is attacker-controlled.
- Run WebSocket handlers in the same process / thread pool as HTTP
  request handlers without sizing limits — a slow-loris-style
  WebSocket can starve all HTTP work.
- Expose internal cluster topology in WebSocket messages (e.g.
  `{"server_id": "pod-prod-42"}`). Internal IDs are reconnaissance
  material on a chatty real-time channel.

### KNOWN FALSE POSITIVES
- Public chat / presence endpoints that are intentionally open to any
  origin must still enforce per-connection rate limits and a
  per-source-IP cap; they may legitimately permit `Origin: null` for
  desktop / mobile clients.
- Mobile / desktop native clients send no `Origin` header. Decide
  upfront whether to allow them (and apply a different auth mode like
  device-cert + bearer token) or to reject them outright.
- Service-to-service WebSockets (e.g. Kafka WebSocket bridge,
  Apache Pulsar) inside a private VPC may legitimately use `ws://`
  with mTLS handled at the network layer.

## Context (for humans)

WebSockets are the long-lived sibling of HTTP. Most of the controls
HTTP gets for free (CORS, CSP, per-request auth) do not apply
out-of-the-box, and frameworks that wrap WebSockets behind a higher-
level API (Socket.IO, SignalR, Phoenix Channels) hide the upgrade
mechanism enough that developers forget to harden it.

The two recurring incident classes are:
1. **Cross-Site WebSocket Hijacking** — missing Origin check + cookie
   auth → attacker.com opens a WS with the user's cookies and reads
   their stream.
2. **Resource exhaustion** — no size / rate / connection limit + a
   chatty protocol → trivial DoS.

Both are simple fixes, but both are easy to forget when generating
a quick chat / collab feature. This skill mirrors the OWASP cheat
sheet plus the operational must-haves (heartbeats, backoff).


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (probe the handshake and the first messages).** Replay the
   WebSocket upgrade with a hostile context: send a foreign `Origin:
   https://attacker.example` header (and the victim's session cookie if cookie
   auth is in play), and separately try the upgrade with no token / an expired
   token. Real if the socket reaches OPEN and starts streaming data — CSWSH is
   confirmed when a cross-origin page can establish the connection and read the
   user's stream; broken handshake-auth is confirmed when an unauthenticated
   upgrade succeeds and only a later `auth`/`subscribe` message gates access. For
   resource limits, hold one socket open and fire an oversized frame and a rapid
   message burst — real if neither is rejected (no size cap, no per-connection
   rate limit). A false positive: the upgrade is refused (4xx / close) for the
   disallowed Origin and the missing/expired token, and oversized or floods are
   dropped.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call):
   assert a handshake carrying a disallowed `Origin` is rejected and one without a
   valid token is rejected, while an allowlisted Origin + valid token connects;
   assert a frame over the max size and a burst past the rate limit are closed/dropped,
   and that each privileged message is re-authorized (a revoked/role-changed user is
   denied) — plus a benign case: legitimate origin, valid token, normal-sized message
   at normal cadence still succeeds. Commit it to CI so the guard can't be silently
   dropped in a later refactor.

## References

- `rules/websocket_hardening.json`
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Cheat_Sheet.html).
- [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html).
- [Cross-Site WebSocket Hijacking explainer](https://christian-schneider.net/CrossSiteWebSocketHijacking.html).
- [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455).
