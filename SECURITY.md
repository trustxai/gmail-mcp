# Security Policy

This server holds a Google OAuth **refresh token** for one Gmail mailbox. Anyone who has that
token can read the whole mailbox until it is revoked. The server runs over stdio only, so the
token never leaves the machine that runs it. This page covers the safety model, how to report
a vulnerability, what counts as one, and what to do if a token leaks.

## The safety model

- **Read-only by construction.** The only scope the login asks for is
  `https://www.googleapis.com/auth/gmail.readonly`. Google has no drafts-only scope:
  `gmail.compose` and `gmail.modify` can both send mail. So:
  - the HTTP client refuses every method other than GET before anything is sent;
  - at every token refresh the granted scopes are checked, and a token that can do more than
    `gmail.readonly` (plus the identity scopes `openid`, `email`, `userinfo.email`) makes the
    server refuse to run.
- **One mailbox per process, pinned.** `GMAIL_ACCOUNT` names the mailbox. Before the first
  API call the server reads `users/me/profile` and compares its `emailAddress`; a mismatch
  disables every tool and nothing else is fetched.
- **The project scope is a filter, not a boundary.** `GMAIL_SCOPE_LABEL` / `GMAIL_SCOPE_QUERY`
  narrow what the tools show. Search queries that could break out of the scope's parentheses
  are refused, and every fetch by id is re-checked after the fetch. It still is not a
  security boundary: a project that needs one needs its own Google account.
- **No credential in any output.** Error messages, tool results and log lines are scrubbed
  of anything token-shaped (`ya29.…`, `1//…`, `Bearer …`, `refresh_token` values, client
  secrets) and of the configured secrets, including what the MCP SDK says on the server's
  behalf.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion.** Report privately through
GitHub:

1. Open the repository's **Security** tab → **Report a vulnerability**
   (direct link: <https://github.com/trustxai/gmail-mcp/security/advisories/new>).
2. Include:
   - the version you ran (the PyPI release, e.g. `0.1.0`, or the commit SHA);
   - the settings involved — variable **names** only, e.g. whether `GMAIL_SCOPE_LABEL` or
     `GMAIL_SCOPE_QUERY` was set;
   - the tool calls and steps to reproduce, and what an attacker gains.

**Never include real credentials or mail** — no tokens, client secrets, addresses or
message ids you would not publish. Build proofs of concept with mocked responses (the test
suite uses `httpx.MockTransport`). If a live token ends up in a report anyway, treat it as
leaked (see below).

### What to expect

The project has a single maintainer, so these are targets, not guarantees:

| Step | Target |
|---|---|
| Acknowledge the report | 3 business days |
| Confirm or rule out the issue, with a severity assessment | 10 business days |
| Release a fix or mitigation | 90 days from the report — sooner for anything that leaks mail or a token |

Once the fix is on PyPI, a GitHub Security Advisory is published (with a CVE when
warranted) and the CHANGELOG entry links to it. Reporters are credited in the advisory
unless they ask not to be. Please keep the details private until the advisory is out.

## Supported versions

Only the latest release on PyPI receives fixes.

## What counts as a vulnerability

- Any request other than GET reaching the Gmail API, or any change to a mailbox.
- The server running with a token granted more than `gmail.readonly` (plus identity scopes).
- Any tool reading a mailbox other than `GMAIL_ACCOUNT`.
- A token, client secret or authorization code appearing in any tool output, error
  message or log line.
- A message outside the configured scope being returned by a fetch by id, or a search
  query escaping the scope's parentheses. (The scope is a filter, so this is a bug with a
  lower severity than the items above, but it is still a bug.)
- An attachment written outside `GMAIL_ATTACHMENT_DIR`, or with permissions wider than 0600.

## If the token leaks

A refresh token reads the mailbox until it is revoked, so, in this order:

1. **Revoke it**: <https://myaccount.google.com/permissions> → the app → remove access (or,
   for a Workspace account, the admin can revoke it from the Admin console).
2. **Mint a new one** with `amazing-gmail-mcp-login` and update it wherever it is stored
   (secret manager, MCP client configs).
3. Review the account's recent security activity for access you do not recognise.
