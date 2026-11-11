# Gmail MCP Server (amazing-gmail-mcp)

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server for **one** Gmail
mailbox, built on the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
(FastMCP) and the [Gmail REST API](https://developers.google.com/workspace/gmail/api/reference/rest).
It holds a `gmail.readonly` refresh token, sends only GET requests to the Gmail API, and checks
before its first call that the token belongs to the mailbox it was configured for. It can search, read messages
and threads, list labels and save attachments to disk. It cannot send, draft, label, archive or
delete anything.

The setup below is written for **Google Workspace** accounts: one Google Cloud project per
company, with an *Internal* OAuth app and a *Desktop* client ([Prerequisites](#prerequisites--one-google-cloud-project-per-company)).
You log in **once per company** with `amazing-gmail-mcp-login`, keep the refresh token in a
secret manager, and give each machine the token through the environment
([Log in once per company](#log-in-once-per-company)). The server runs over **stdio only**: there
is no HTTP transport, so a token that reads a whole mailbox never leaves the machine that runs
the server.

> The PyPI distribution and the console script are both **`amazing-gmail-mcp`**. The bare
> `gmail-mcp` name on PyPI belongs to an unrelated package, so always run
> `uvx amazing-gmail-mcp`, never `uvx gmail-mcp`.

## Safety model

The rails live in the HTTP client, the token check and the scope module, not in the tools, so
no tool can forget them:

- **Read-only by construction.** The login asks Google for `gmail.readonly` and nothing else.
  At every token refresh the server reads the scopes Google reports for the token. A token that
  can do more than `gmail.readonly` (plus the identity scopes `openid`, `email` and
  `userinfo.email`), such as `gmail.modify`, `gmail.compose` or `https://mail.google.com/`,
  makes the server refuse to run for the life of the process. A token response that does not
  report its scopes is refused for that call (the next call refreshes again). Google has no
  drafts-only scope: `gmail.compose` and `gmail.modify` can both send mail. On top of that, the
  Gmail API client only sends GET: any other method is refused before a token is read or a
  request goes out. The only POSTs go to Google's token endpoint: the server's refresh of the
  access token, and the login's code exchange.
- **One mailbox per process, pinned.** `GMAIL_ACCOUNT` names the mailbox. Before the first API
  call the server reads `users/me/profile` and compares its `emailAddress` with
  `GMAIL_ACCOUNT`, ignoring case. A mismatch disables every tool for the life of the process,
  and nothing else is fetched. The API host is fixed and every request path is a `users/me/…`
  path. Two companies are two entries, each with its own token, so they cannot read each
  other's mailbox.
- **The project scope is a filter, not a security boundary.** `GMAIL_SCOPE_LABEL` and
  `GMAIL_SCOPE_QUERY` narrow what the tools show
  ([Project scope](#project-scope)). Every fetch by id is checked against the scope again
  *after* the fetch, so a known id cannot skip it, and anything out of scope gets the same
  "not found" answer as an id that does not exist. It is still only a filter: the token itself
  can read the whole mailbox. A project that needs a real boundary needs its own Google account.
- **Spam and trash are never shown.** Every search runs with `includeSpamTrash=false` and
  `-in:spam -in:trash` appended, whatever the query says (`in:anywhere`, `in:spam` and
  `in:trash` included). On top of that, `gmail_search_messages` drops a hit whose labels carry
  `SPAM` or `TRASH`, and counts the dropped hits in one line. A message labelled `SPAM` or
  `TRASH` is refused when read by id, and a thread is shown, and checked against the scope,
  without its spam and trash messages.
- **Bounded output.** A body is capped at `GMAIL_BODY_MAX_CHARS` characters per call and paged
  with `offset`. A thread page caps each message and the page as a whole. Every header, label
  list and attachment list is capped, and no response is larger than 900,000 bytes. Requests
  are bounded too: both queries are capped, and every list request is measured before it is
  sent, so it fits Gmail's limit on the request URL ([Project scope](#project-scope)).
- **Attachments go to a file, never into the conversation.** `gmail_get_attachment` takes the
  message id and the attachment's `partId`, which is stable across reads. Gmail is reported to
  issue a new `attachmentId` on every read, so the server never takes one from the caller. It fetches the
  message again, checks it against the scope, and refuses *before downloading* when Gmail
  reports no size or a size over `GMAIL_ATTACHMENT_MAX_BYTES`. Then it downloads with the
  `attachmentId` of that same fetch and saves the file under
  `GMAIL_ATTACHMENT_DIR/<message_id>/` (directories `0700`, the file `0600`, a safe file name,
  never overwriting: a second copy gets a numbered suffix). The result is the path, size,
  mimeType and sha256: never the bytes, never base64, never an `attachmentId`.
- **No credential in any output.** Tool results, tool errors, log lines and what the MCP SDK
  says on the server's behalf (an argument it rejects is not echoed back) are scrubbed of the
  configured secrets, of every access token as it is minted, and of anything shaped like a
  Google credential (`ya29.…` access tokens, `1//…` refresh tokens, `GOCSPX-…` client secrets,
  authorization codes, `Bearer …`, and `refresh_token` / `access_token` / `id_token` /
  `client_secret` values). The HTTP library's one-line-per-request logs are silenced. An error
  is one line, the cause and then the fix, never a traceback. The access token lives in memory
  only.
- **Text from other people is data, not instructions.** Anyone who can email the mailbox can
  write what the tools return. The server fences message bodies (a code fence in
  `gmail_get_message`, a blockquote in `gmail_get_thread`) so a mail cannot pose as the tool's
  own output, but do not let your agent follow instructions found in mail.

The server stores nothing on disk except the attachments you ask it to save.

Found a way around one of these rails? Report it privately: see [SECURITY.md](SECURITY.md).

## Features

**7 tools**, all read-only. They are listed below by group, and every one is in the
[table](#available-tools).

- **Health.** `gmail_health` takes no arguments. It refreshes the access token (which runs the
  `gmail.readonly` check), reads the profile, checks the pin, resolves the project scope, and
  reports the server version, the mailbox (`messagesTotal`, `threadsTotal`), the granted scopes,
  the active scope and the body and attachment caps. Call it first.
- **Messages.** `gmail_search_messages` takes Gmail's own query syntax (`query`), `max_results`
  (1–100, default 20) and `page_token`. Per hit it shows the subject, sender, date (UTC), `id`,
  `threadId`, label ids and snippet, read with `format=metadata`, at most 10 requests at a time.
  `gmail_get_message` takes `message_id` and `offset`: the From, To, Cc, Date, Subject and
  Message-ID headers, the body (the `text/plain` part, else the HTML turned into text, decoded
  with the declared charset, then UTF-8, then cp1252), and the attachment list (filename,
  mimeType, size, `partId`).
- **Threads.** `gmail_search_threads` takes the same `query`, `max_results` and `page_token`,
  reads no body, and shows per thread its subject, `threadId`, message count, last date,
  participants (the first 10) and snippet. `gmail_get_thread` takes `thread_id`, `offset` (a
  message index, 0 = the oldest) and `max_messages` (1–100, default 20). Each message's body
  is cut at 5,000 characters (or `GMAIL_BODY_MAX_CHARS`, if smaller) and a page holds at most
  `GMAIL_BODY_MAX_CHARS` body characters in total. A cut body is read on with the same tool:
  pass the printed `message_id` and `body_offset`.
- **Labels.** `gmail_list_labels` takes no arguments and lists every label's id, name and type
  (`system` or `user`), marking the label `GMAIL_SCOPE_LABEL` resolved to. Label names are not
  filtered by the scope: a label definition is not a message.
- **Attachments.** `gmail_get_attachment` takes `message_id` and `part_id`, as
  `gmail_get_message` and `gmail_get_thread` list them, and saves the file
  ([Safety model](#safety-model)).

Every tool but the two without arguments takes one `params` object, and unknown fields are
refused. Search results print `page_token` when there is a next page; pass it back with the same
`query`.

## Available Tools

<!-- TOOL TABLE START -->
All **7 tools**, grouped by module. Every tool is read-only: the server holds a gmail.readonly token and only ever sends GET.

| Tool | Description |
|---|---|
| **Health** | |
| `gmail_health` | Check the token, the pinned mailbox, the granted scopes and the active project scope. |
| **Messages — search and read** | |
| `gmail_get_message` | Read one message: its headers, the text body (capped, paged with `offset`) and its attachment list. |
| `gmail_search_messages` | Search messages with Gmail's query syntax and list each hit's metadata (the project scope applied). |
| **Threads — search and read whole conversations** | |
| `gmail_get_thread` | Read a whole conversation: every message in order, with headers and capped text bodies. |
| `gmail_search_threads` | Search whole conversations (threads) in the mailbox scope and summarize each one. |
| **Labels** | |
| `gmail_list_labels` | List the mailbox's labels — id, name and type (system/user) — marking the scope label. |
| **Attachments — saved to a file, never inlined** | |
| `gmail_get_attachment` | Save one attachment of a message to a local file and return its path, size, type and sha256. |
<!-- TOOL TABLE END -->

The table is generated from the code (`scripts/gen_tool_table.py`). Each row is the first line
of that tool's docstring.

## Prerequisites — one Google Cloud project per company

You need [uv](https://docs.astral.sh/uv/) (or Python 3.13+), and for each company a Google
Workspace account for the mailbox plus a Cloud project in that company's organization. Do this
once per company, in the [Google Cloud console](https://console.cloud.google.com):

1. **Create a project inside the company's organization.** In the project picker → **New
   project**, set **Organization** to the company's domain (`example.com`). The project has to
   belong to the organization for the *Internal* audience of step 3 to be available.
2. **Enable the Gmail API**: **APIs & Services** → **Library** → **Gmail API** → **Enable** (or
   `gcloud services enable gmail.googleapis.com --project <PROJECT_ID>`).
3. **Configure the OAuth consent screen** (**Google Auth Platform**): under **Branding**, an app
   name and a support email; under **Audience**, user type **Internal**. An Internal app is
   usable only by accounts of the organization, and it needs no Google verification. Under
   **Data Access** you can list `https://www.googleapis.com/auth/gmail.readonly`, the only scope
   the login asks for.
4. **Create a Desktop OAuth client**: **Clients** → **Create client** → application type
   **Desktop app**, any name → **Create**, then **Download JSON**. Do **not** tick *Use this
   client for an AI-powered agent*: that mark is for clients of Google's own hosted MCP servers,
   and this server calls the Gmail REST API directly, where it grants nothing. The downloaded
   JSON has an `installed` key; that is what `GMAIL_CLIENT_SECRET_FILE` expects (a Web client or
   a service-account key is refused). Keep it outside any repository, e.g.
   `~/.config/amazing-gmail-mcp/client_secret_acme.json` (`client_secret*.json` and `*.token.json` are
   in this repo's `.gitignore`).
5. **If Google answers "blocked by your administrator"** when you log in, a Workspace admin of
   that organization opens the [Admin console](https://admin.google.com) → **Security** →
   **Access and data control** → **API controls** and either trusts this OAuth client ID
   (**Manage Third-Party App Access** → configure the app by its client ID → access
   **Trusted**), or ticks **Trust internal apps**, which trusts every app the organization owns.
   Trusting the one client ID is the narrower choice.

An Internal client only signs in accounts of its own organization, so a second company needs its
own project and its own client.

## Log in once per company

`amazing-gmail-mcp-login` mints the `gmail.readonly` refresh token for one mailbox and writes it
to a JSON file. Run it on a machine with a browser (your laptop): Google redirects back to
`127.0.0.1` of the machine that runs the login.

```sh
uvx --from amazing-gmail-mcp amazing-gmail-mcp-login \
  --account you@acme.example.com \
  --client-secret-file ~/.config/amazing-gmail-mcp/client_secret_acme.json \
  --out ~/.config/amazing-gmail-mcp/acme.token.json
```

| Flag | Required | Meaning |
|---|---|---|
| `--account` | yes | The mailbox to log in as. Google's profile must be this address (ignoring case), or nothing is written. |
| `--client-secret-file` | yes | The Desktop client JSON of the company's Cloud project ([step 4](#prerequisites--one-google-cloud-project-per-company)). |
| `--out` | yes | The token file to write. Refused if it is a directory, if it is inside a git work tree (checked on the path as written and resolved), or if it exists and `--force` is not given. Missing parent directories are created `0700`. |
| `--force` | no | Replace `--out` if it already exists. |

What it does, in order:

1. Checks the account's shape, the client JSON and `--out` **before** the browser opens, so a
   bad flag costs neither a consent nor one of Google's refresh-token slots (below).
2. Opens a listener on `127.0.0.1` with a random free port, and opens the browser on Google's
   consent page (it also prints the URL to stderr, in case no browser opens). The request uses
   PKCE (S256) and a random `state`, asks for `gmail.readonly` only, with `access_type=offline`,
   `prompt=consent` and the account as `login_hint`. It waits up to 300 s for the redirect and
   refuses one whose `state` does not match or that carries an error.
3. Exchanges the code. The granted scopes must pass the same rule the server applies at every
   refresh, the response must carry a refresh token, and `users/me/profile` must be `--account`.
4. Writes `{"account", "client_id", "refresh_token", "scope", "created_at"}` to `--out`, mode
   `0600`, atomically.

stdout gets two lines and nothing else: the path and an 8-hex fingerprint (the first 8 hex
characters of the token's sha256), which tells tokens apart without revealing them:

```text
wrote /Users/you/.config/amazing-gmail-mcp/acme.token.json
refresh token fingerprint sha256:0a1b2c3d
```

The refresh token, the access token, the authorization code and the PKCE verifier never reach
stdout, stderr or a log. Exit codes:

| Code | Meaning |
|---|---|
| `0` | The token file was written. |
| `1` | Refused or failed. stderr has one line, `amazing-gmail-mcp-login: <cause>: <fix>`. |
| `2` | Usage: a required flag is missing or a flag is unknown. |
| `130` | Cancelled with Ctrl-C (`cancelled: nothing was written`). |

On **any** failure nothing is written.

**Log in once per company, never once per machine.** Google keeps at most 100 refresh tokens per
account per OAuth client, and when a new one goes past that it invalidates the oldest without
notice. Every run of the login mints a new token (`prompt=consent`), so a login per machine, or
per session, burns slots and eventually kills a token another machine still uses. Log in once,
keep the token in a secret manager, and let every machine read it from there. Log in again only
when the server tells you to (see [Troubleshooting](#troubleshooting)).

### Move the token into a secret manager

Pipe the token from the file into the secret manager, so it never appears on a terminal, in a
command line or in shell history. With the [1Password CLI](https://developer.1password.com/docs/cli/)
and [jq](https://jqlang.org), for a vault named `Private`:

```sh
TOKEN_FILE=~/.config/amazing-gmail-mcp/acme.token.json
jq '{title: "gmail-acme", category: "PASSWORD",
     fields: [{id: "refresh_token", label: "refresh_token", type: "CONCEALED", value: .refresh_token}]}' \
  "$TOKEN_FILE" | op item create --vault Private - > /dev/null
```

Check that the stored value is the one the login wrote (both lines must print the fingerprint
the login printed), then delete the file:

```sh
jq -j .refresh_token "$TOKEN_FILE" | shasum -a 256 | cut -c1-8   # sha256sum on Linux
op read --no-newline op://Private/gmail-acme/refresh_token | shasum -a 256 | cut -c1-8
rm "$TOKEN_FILE"
```

The server then receives it as `GMAIL_REFRESH_TOKEN` without it ever being written to a config
file: set `GMAIL_REFRESH_TOKEN` to the reference `op://Private/gmail-acme/refresh_token` and
start the server through `op run -- uvx amazing-gmail-mcp`, which swaps in the secret only in
the server's environment ([Client configuration](#client-configuration)). Any other secret
manager works the same way if it reads the value from stdin and can inject it into a
subprocess's environment.

## Quickstart

1. Do the [Google Cloud setup](#prerequisites--one-google-cloud-project-per-company) and
   [log in](#log-in-once-per-company) for the company.
2. Put the settings where the server can read them: real environment variables, or a `.env` file
   in the server's working directory (real variables win over `.env`). This `.env` is for trying
   the server out from a terminal; with a client, put the settings in each entry's `env`
   ([below](#client-configuration)):

   ```sh
   # .env (never commit it)
   GMAIL_ACCOUNT=you@acme.example.com
   GMAIL_REFRESH_TOKEN=op://Private/gmail-acme/refresh_token
   GMAIL_CLIENT_SECRET_FILE=~/.config/amazing-gmail-mcp/client_secret_acme.json
   ```

3. Run it with no install:

   ```sh
   op run --env-file .env -- uvx amazing-gmail-mcp
   ```

   (Without a secret manager, put the token itself in `.env` and run `uvx amazing-gmail-mcp`.)
   It is a stdio server, so in a bare terminal it just waits for an MCP client on stdin. Stop it
   with Ctrl-C and point a client at it instead ([below](#client-configuration)). A
   misconfigured entry does not wait: it prints one line naming the variables at fault and exits
   with status 2.

4. Call **`gmail_health`** first. It shows the mailbox, `pin: OK`, the granted scopes and the
   active scope. Without a client, use the [MCP Inspector](#mcp-inspector).

## Client configuration

Every client starts the server as a subprocess and passes settings through `env`. **One entry per
company**: same package, its own `GMAIL_ACCOUNT`, its own token, its own client JSON. Name the
entries `gmail-<company>`; the examples use `gmail-acme` and `gmail-globex`. The entries keep
`op://` references, not tokens, so the token never sits in a config file. Without 1Password use
`"command": "uvx", "args": ["amazing-gmail-mcp"]` and pass the token by variable expansion
where the client supports it.

A server the client launches also reads `./.env` in its working directory, which for Claude Code
is the project directory. So a `.env` at a project's root reaches **every** entry started there,
`gmail-acme` and `gmail-globex` alike: a scope or a cap in it applies to all of them, and a
`GMAIL_CLIENT_SECRET_FILE` in it conflicts with an entry that sets `GMAIL_CLIENT_ID` +
`GMAIL_CLIENT_SECRET` (both forms at once are refused). Keep `GMAIL_` settings out of a
project's `.env` and in each entry's `env`.

### Claude Code

A project's `.mcp.json`, one entry per company:

```json
{
  "mcpServers": {
    "gmail-acme": {
      "type": "stdio",
      "command": "op",
      "args": ["run", "--", "uvx", "amazing-gmail-mcp"],
      "env": {
        "GMAIL_ACCOUNT": "you@acme.example.com",
        "GMAIL_REFRESH_TOKEN": "op://Private/gmail-acme/refresh_token",
        "GMAIL_CLIENT_SECRET_FILE": "~/.config/amazing-gmail-mcp/client_secret_acme.json"
      }
    },
    "gmail-globex": {
      "type": "stdio",
      "command": "op",
      "args": ["run", "--", "uvx", "amazing-gmail-mcp"],
      "env": {
        "GMAIL_ACCOUNT": "you@globex.example.com",
        "GMAIL_REFRESH_TOKEN": "op://Private/gmail-globex/refresh_token",
        "GMAIL_CLIENT_SECRET_FILE": "~/.config/amazing-gmail-mcp/client_secret_globex.json"
      }
    }
  }
}
```

For every project at once, add the same entry with
`claude mcp add-json gmail-acme '<the gmail-acme object above>' --scope user`. Without
1Password, a project `.mcp.json` can write `"GMAIL_REFRESH_TOKEN": "${ACME_GMAIL_REFRESH_TOKEN}"`
and Claude Code expands it from the environment it was started in. The variable must not start
with `GMAIL_`: that environment reaches the server too, and an unknown `GMAIL_` name stops it
([Environment variables](#environment-variables)).

### A project-scoped entry

To let an agent see only one project's mail, add an entry with a scope in that project's
`.mcp.json`. It reuses the company's token: same account, same login, only the scope differs.

```json
{
  "mcpServers": {
    "gmail-acme-rollout": {
      "type": "stdio",
      "command": "op",
      "args": ["run", "--", "uvx", "amazing-gmail-mcp"],
      "env": {
        "GMAIL_ACCOUNT": "you@acme.example.com",
        "GMAIL_REFRESH_TOKEN": "op://Private/gmail-acme/refresh_token",
        "GMAIL_CLIENT_SECRET_FILE": "~/.config/amazing-gmail-mcp/client_secret_acme.json",
        "GMAIL_SCOPE_LABEL": "Projects/Rollout"
      }
    }
  }
}
```

`gmail_health` then reports `scope: label` and the label's id. Every search is limited to the
label, and a message, thread or attachment read by id must pass the same check (a thread passes
when any of its messages carries the label). Remember that the scope is a filter: the token
behind this entry can still read the whole mailbox.

### Cursor

`~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per project), one entry per company:

```json
{
  "mcpServers": {
    "gmail-acme": {
      "command": "uvx",
      "args": ["amazing-gmail-mcp"],
      "env": {
        "GMAIL_ACCOUNT": "you@acme.example.com",
        "GMAIL_REFRESH_TOKEN": "${env:ACME_GMAIL_REFRESH_TOKEN}",
        "GMAIL_CLIENT_SECRET_FILE": "~/.config/amazing-gmail-mcp/client_secret_acme.json"
      }
    }
  }
}
```

Cursor expands `${env:NAME}` from the environment it was started in; the `op run` form of the
Claude Code example works here too.

### Claude Desktop

Settings → Developer → Edit Config opens `claude_desktop_config.json` (on macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`). Add the same `mcpServers`
block, in the `op run` form: Desktop's config file is not documented to expand environment
variables. Quit Desktop *before* you edit the file (a running Desktop has been seen to write its
in-memory copy back over edits), and restart it afterwards. If Desktop cannot find `uvx` or
`op`, use their absolute paths (`which uvx`, `which op`). Each entry adds 7 tools to Desktop's
tool count.

### MCP Inspector

From a directory with a `.env` (the server reads it from its working directory):

```sh
npx @modelcontextprotocol/inspector uvx amazing-gmail-mcp
```

The Inspector starts the server itself, so this `.env` has to hold the token, not an `op://`
reference; or make `op run --env-file .env -- uvx amazing-gmail-mcp` the command the Inspector
starts.

Open the Tools tab and run `gmail_health`. From a clone,
`npx @modelcontextprotocol/inspector uv run amazing-gmail-mcp` does the same against your
working tree.

## Environment variables

Settings are read once, when the server starts, so restart the client after changing one. A
misconfigured entry exits at once with status 2 and one line on stderr naming the variables at
fault, never a secret's value (a path such as `GMAIL_CLIENT_SECRET_FILE`'s is shown). Values are
whitespace-stripped; a blank string setting counts as unset, and a blank number
(`GMAIL_BODY_MAX_CHARS`, `GMAIL_ATTACHMENT_MAX_BYTES`) is refused. Real environment variables
win over `.env`, which is read from the server's working directory.

| Variable | Default | Limit / rule | Meaning |
|---|---|---|---|
| `GMAIL_ACCOUNT` | *(none)* | **Required.** An email address. | The one mailbox this process serves. The token's profile must match it, ignoring case (the pin). |
| `GMAIL_REFRESH_TOKEN` | *(none)* | **Required.** No whitespace inside the value. | The `gmail.readonly` refresh token from `amazing-gmail-mcp-login`. Never logged or echoed. |
| `GMAIL_CLIENT_SECRET_FILE` | *(none)* | A Desktop client JSON (`installed` key); `~` is expanded. Not together with the two below. | The OAuth client the token was minted with. |
| `GMAIL_CLIENT_ID` | *(none)* | Together with `GMAIL_CLIENT_SECRET`, instead of the file. | The same client, inline. |
| `GMAIL_CLIENT_SECRET` | *(none)* | Together with `GMAIL_CLIENT_ID`. | The same client, inline. Never logged or echoed. |
| `GMAIL_SCOPE_LABEL` | *(none: no label scope)* | Must name a label of the mailbox: its exact id, its exact name, or a name unique ignoring case. Resolved at the first tool call. | Every search is limited to this label, and every fetch by id must carry it ([Project scope](#project-scope)). |
| `GMAIL_SCOPE_QUERY` | *(none: no query scope)* | At most 1,500 characters and 6,000 once percent-encoded; valid UTF-8; refused at start-up when it could break out of its parentheses (see [the rules](#project-scope)). A refusal names the size, never the value. | A Gmail query ANDed with every search, as `(<scope>) (<your query>)`. |
| `GMAIL_BODY_MAX_CHARS` | `20000` | 100 to 150000. | Body characters per call: one message's body, or a thread page's bodies in total. |
| `GMAIL_ATTACHMENT_DIR` | `~/Downloads/gmail-mcp` | `~` is expanded. | Where `gmail_get_attachment` saves files, under one directory per message id. |
| `GMAIL_ATTACHMENT_MAX_BYTES` | `26214400` (25 MiB) | 1 to 1073741824 (1 GiB). | The largest attachment saved. A larger one, or one of unknown size, is refused before downloading. |

You set **either** `GMAIL_CLIENT_SECRET_FILE` **or** `GMAIL_CLIENT_ID` + `GMAIL_CLIENT_SECRET`;
both forms at once are refused, because they could name different clients.

**Any other `GMAIL_` variable refuses to load.** A `GMAIL_` name in the server's environment, or
in `./.env`, that is not one of the ten above stops the server at start-up: a misspelt
`GMAIL_LABEL_SCOPE` would otherwise start it with the whole mailbox in view. That includes a
variable you define only so the client can expand it into an entry's `env`: the client's
environment reaches the server, so name such variables without the `GMAIL_` prefix
(`ACME_GMAIL_REFRESH_TOKEN`, not `GMAIL_ACME_REFRESH_TOKEN`).

## Project scope

Both settings are optional and combine. They narrow what the tools show; they do not narrow what
the token can read.

- **`GMAIL_SCOPE_LABEL`** is resolved to its label id once, with one `labels.list`. It goes on
  every list call as `labelIds`, a separate API parameter, so no query text can undo it. A label
  that does not exist makes every tool fail ([Troubleshooting](#troubleshooting)). Nested labels
  are named `Parent/Child`, as in Gmail.
- **`GMAIL_SCOPE_QUERY`** is a Gmail query, sent as `(<scope>) (<your query>) -in:spam -in:trash`.
  The scope query (at start-up) and every search query (at each call) are refused when they could
  close the scope's group: a `)` or `}` that closes a group never opened, a `)` that closes a `{`
  (or the reverse), a group or a double quote left open, a backslash before a double quote, and
  typographic quotes (`“ ”`, `« »`, …).

Both queries ride in the URL of every search and of every query-scope check, and Gmail refuses a
request URL (path and query) longer than 16,384 characters. So each is capped twice: at 1,500
characters, and at 6,000 characters once percent-encoded as it is sent (an ASCII letter or a
space counts 1, ASCII punctuation 3, a non-ASCII character 6 to 12: about 660 CJK characters or
500 emoji). A `GMAIL_SCOPE_QUERY` past either cap, or one that is not valid UTF-8 text, refuses
to load, naming its size and never its value. A search `query` past either cap is refused
before anything is sent; it is also one line (whitespace is collapsed), with no control
characters. On top of the caps, every list request is measured as it would be sent, and one
over 15,360 characters is refused (`the search is refused: its URL would be … characters, …`).

Every fetch by id (`gmail_get_message`, `gmail_get_thread`, `gmail_get_attachment`) is checked
after the fetch. With a label scope the message must carry the label. With a query scope a
search for the scope query plus the message's `Message-ID` header must find that very message,
so a message without a usable `Message-ID` is out of scope. A thread is in scope when any of its
messages outside spam and trash is. Any error during the check counts as out of scope. Out of
scope gets the same answer as an id that does not exist, without the message's headers:
`… was not found in this mailbox scope`.

## Running the tests

```sh
uv sync --group dev
uv run pytest -m "not live"   # the gate: never touches Google
uv run pytest -m live         # read-only smoke against the real mailbox
```

- The default tier mocks every HTTP call, strips your real `GMAIL_*` settings and runs from an
  empty temporary directory, so it runs anywhere.
- `live` runs only when `GMAIL_REFRESH_TOKEN` is set, in the shell or in `.env`, together with
  `GMAIL_ACCOUNT` and the client. Otherwise those tests are skipped. Every Gmail API call they
  make is a GET (one test checks that a POST is refused before it is sent), so they read the
  mailbox but never change it, and no assertion prints a header, a body or a token. With
  1Password: `op run --env-file .env -- uv run pytest -m live`.
- Measured on 2026-11-11 against a real Workspace mailbox: the login, the read-only scope, the
  account pin, `gmail_health`, the label list, a scoped search, the post-fetch scope check and
  the POST refusal all work live.

## Troubleshooting

The server's errors reach the model as one line, `Error executing tool <tool>: ` followed by
the cause and the fix.
A start-up error is one line on stderr, `amazing-gmail-mcp: configuration error: …`, and status 2.
A client usually reports only that the server failed to start (or shows the line in its MCP log),
so run the entry's command in a terminal with the same environment to read it.

- **`the refresh token for you@acme.example.com is no longer valid (revoked, password changed, unused 6 months, or the 100-token cap): run amazing-gmail-mcp-login on the Mac and update 1Password`.**
  Google answered `invalid_grant`. A refresh token dies when its access is removed (at
  <https://myaccount.google.com/permissions>, or by a Workspace admin), when it goes unused for
  6 months, when the account's password changes, when it is the oldest of more than 100 tokens
  minted for the same account and client, or when the admin restricts the service. Run the
  login again (on any machine with a browser, whatever the message says), replace the token in your secret manager,
  and restart the client. The server does not retry: it remembers the failure, so every tool
  fails with this line until the restart.
- **Google says the app is "blocked by your administrator".** The Workspace admin has not trusted
  this client: see [step 5](#prerequisites--one-google-cloud-project-per-company). Google shows
  it on its own page during the login. When Google sends the browser back, the login prints
  `Google refused the authorization (admin_policy_enforced): the Workspace admin blocks this client: Admin console → Security → API controls → trust the client ID (or 'Trust internal apps'), then run the login again`;
  when it does not, the login stops after 300 s with
  `no redirect from Google within 300 s: run the login again and finish the consent in the browser`.
  When the block shows up as a 403 from the Gmail API instead, the login prints
  `could not read the Gmail profile (HTTP 403 …; the Workspace admin may block this client (Admin console → Security → API controls)): nothing was written`,
  and a server error for a 403 such as `domainPolicy` ends with
  `the Workspace admin or the Cloud project blocks this client: enable the Gmail API in the project and trust the client ID (Admin console → Security → API controls).`
  The login's version of a disabled Gmail API (`accessNotConfigured`) says
  `enable the Gmail API in the client's Cloud project and run the login again`: that is
  [step 2](#prerequisites--one-google-cloud-project-per-company).
- **`Google refused the authorization (org_internal): the client is Internal to another Workspace organization: …`.**
  You signed in with an account of another company. Choose the right account, or use that
  company's client JSON.
- **`this server is pinned to GMAIL_ACCOUNT=you@acme.example.com, but the refresh token belongs to other@acme.example.com: every tool is disabled. Mint a token for you@acme.example.com with amazing-gmail-mcp-login, or fix GMAIL_ACCOUNT`.**
  The entry has another mailbox's token. Fix `GMAIL_ACCOUNT` or the
  token reference, and restart the client. The login has the same check: `Google signed in
  other@acme.example.com, not you@acme.example.com: nothing was written; run again and choose
  you@acme.example.com in Google's account chooser`.
- **`GMAIL_SCOPE_LABEL=Projects/Rollout matches no label in you@acme.example.com: this entry refuses to run. Fix the label name (or id), or create the label in Gmail`.**
  Every tool fails with it, `gmail_health` and `gmail_list_labels` included. Check the label's
  exact name in Gmail (nested labels are `Parent/Child`), or remove the variable, run
  `gmail_list_labels`, and set the label's id. Restart the client after the change.
- **`amazing-gmail-mcp: configuration error: GMAIL_LABEL_SCOPE is not a known variable (did you mean GMAIL_SCOPE_LABEL?): a misspelt setting is refused, so a typo can never leave the whole mailbox in view or a bound unset`.**
  A `GMAIL_` variable that is not a setting, in the entry's `env`, in the environment the client
  passes on, or in `./.env`. Fix the spelling, or unset a `GMAIL_` variable that belongs to
  something else. A variable the client only expands into `env`, such as
  `GMAIL_ACME_REFRESH_TOKEN`, trips it too (`did you mean GMAIL_REFRESH_TOKEN?`): rename it
  without the prefix, e.g. `ACME_GMAIL_REFRESH_TOKEN`. When no setting is close, the message
  lists them all (`the settings are GMAIL_ACCOUNT, …`).
- **`amazing-gmail-mcp: configuration error: GMAIL_SCOPE_QUERY is refused: it is 1,501 characters, the most is 1,500. It goes into the URL of every search and of every scope check: fix or shorten it, or scope by a label with GMAIL_SCOPE_LABEL`.**
  The same refusal names the encoded size instead (`it is 7,200 characters once percent-encoded
  for the URL, the most is 6,000 …`) for a query heavy in non-ASCII text, and says
  `it is not valid UTF-8 text` for a value that is not text. Shorten the query, or scope by a
  label. A search `query` past the same caps fails the call with `query is refused: …`.
- **`message 18c2f0e9a1b2c3d4 was not found in this mailbox scope. Check the id (search for it first) and the active scope (gmail_health).`**
  (or `thread …`, or `attachment partId "1" of message …`). The id does not exist, or the message
  is outside `GMAIL_SCOPE_LABEL` / `GMAIL_SCOPE_QUERY`, or it is in spam or trash; for an
  attachment, the `partId` is not one of the message's listed attachments. The answers look the
  same on purpose. Tools take Gmail's `id`, the one a search prints, not the `Message-ID` header.
  Search for the message first, and check the scope with `gmail_health`.
- **`this entry is read-only; its token can do more (…): mint a gmail.readonly token with amazing-gmail-mcp-login`.**
  The token was minted with more than `gmail.readonly` (by another tool, or another login). Mint
  one with `amazing-gmail-mcp-login`, which asks for `gmail.readonly` only and refuses to save a
  broader grant.
- **`Google rejected the OAuth client (invalid_client): GMAIL_CLIENT_SECRET_FILE (or GMAIL_CLIENT_ID + GMAIL_CLIENT_SECRET) must be the Desktop client the refresh token was minted with`.**
  The client JSON is not the one the token came from. Each company's token goes with that
  company's client.
- **`GMAIL_CLIENT_SECRET_FILE (…) is not a Desktop OAuth client: it is a web credential. …`.**
  Create a client of type **Desktop app** ([step 4](#prerequisites--one-google-cloud-project-per-company))
  and download its JSON.
- **`attachment partId "1" of message … is … over GMAIL_ATTACHMENT_MAX_BYTES (…): it was not downloaded. …`.**
  Raise `GMAIL_ATTACHMENT_MAX_BYTES` for that entry (up to 1073741824), or open it in Gmail.
- **`uvx gmail-mcp` installs something else.** That name belongs to an unrelated PyPI package.
  This one is `uvx amazing-gmail-mcp`.

## Contributing

```sh
uv sync --group dev
uv run pytest -m "not live"
uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/
uv run mypy src/
uv run python scripts/gen_tool_table.py --check   # --write after adding or renaming a tool
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org) (`feat(messages): …`,
`fix(scope): …`). Releases and the changelog are cut by release-please. Every Gmail API request
goes through `src/gmail_mcp/client.py`, which sends GET only (the token endpoint's POSTs live in
`auth.py` and `login.py`); every list call goes through
`scope.apply()` and every fetch by id through the scope's fetch helpers. Security issues go
through [SECURITY.md](SECURITY.md), never a public issue.

## License

Apache-2.0 — see [LICENSE](LICENSE).
