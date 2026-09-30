# Claude Code integration

This directory holds a Claude Code subagent, `tegata-login`, that logs in through tegata on behalf of the main session. A small model drives `login_begin` and `login_step` screen by screen and returns only a short JSON result, so the main session never handles the intermediate snapshots. Use it for sites whose login steps are not known in advance or span several screens.

The subagent is not packaged as a plugin. Registering the tegata MCP server differs per environment, so bundling it would mislead. See [Linux setup](../../docs/setup-linux.md#connecting-an-agent) and [Windows + WSL setup](../../docs/setup-windows-wsl.md) for registering the server.

## Install

1. Copy `agents/tegata-login.md` to `~/.claude/agents/` (or to a project's `.claude/agents/`).
2. If you registered the MCP server under a name other than `tegata`, replace `mcp__tegata__` in the `tools:` line with `mcp__<your-name>__`.
3. Optional: allow `login_step` without prompting in `settings.json`:

   ```json
   {
     "permissions": {
       "allow": ["mcp__tegata__login_step"]
     }
   }
   ```

   Do not allow `login_begin`. It runs once per login and is the only client-side point where the user can see which credential is about to log in to which site. `login_step` only acts on a `login_id` that has already been started, so allowing it grants no new permission.
4. `model: haiku` is the default. For difficult sites, change it to `sonnet` or another model in the frontmatter.

## Using it

The main session picks the credential (for example with `list_credentials`) and delegates with `cred_id`, `target_url`, and `success_selector`, optionally `failure_selector` and `exclusive`. The subagent has no `list_credentials` access.

It replies with exactly one JSON block:

- Success: `{"ok": true, "session_id", "target_id", "endpoint"}`. Connect to `endpoint` over CDP.
- Failure: `{"ok": false, "error", "url", "title", "text", "elements"}`, where `error` is a tegata error code, `ABORTED`, or `MISSING_INPUT`, and the page fields describe the last snapshot (`text` is cut to 500 characters, `elements` to 10).

On failure, do not retry; report the JSON to the user. The only exception is when `error` is `ABORTED` and a mismatched `success_selector` is suspected: fix the selector and delegate once more, only once. For any other failure, such as `RATE_LIMITED` or a failed `login_begin`, only report it to the user.
