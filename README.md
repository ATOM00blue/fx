```
 ⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⢰⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⣠⣶⣿⣿⣷⣶⡶⣶⣶⣆⠀⠀⠀⣴⣶⣶⠆             X1 — fast, native coding agent.
 ⠀⠀⠀⠉⢹⣿⣿⠉⠉⠀⠘⢿⣿⣧⣀⣾⣿⡿⠃⠀
 ⠀⠀⠀⠀⣼⣿⡏⠀⠀⠀⠀⠀⠻⣿⣿⣿⠟⠀⠀⠀             curl -fsSL https://layerx1.com/setup.sh | bash
 ⠀⠀⠀⢀⣿⣿⠃⠀⠀⠀⠀⢠⣦⠘⢿⣿⣷⡀⠀⠀
 ⠀⠀⠀⣸⣿⡟⠀⠀⠀⠀⣰⣿⣿⠗⠀⠻⣿⣿⣄⠀             ⚠ Status: Experimental. Use at your own risk.
 ⠀⠀⠀⣿⣿⠇⠀⠀⠀⠾⠿⠿⠋⠀⠀⠀⠘⠿⠿⠦
  ⠀⣸⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```

x1 is a coding agent harness and CLI written in Zig, optimized for research and embeddability as part of larger systems.

It focuses on minimalism and performance across the board, from system prompt design to its tools, feature set, and small binary.

For end users, its CLI output style and form factor aim to be closer to a Unix shell than a heavy "IDE in the terminal" TUI.

It's open source (Apache-2.0) and runs on the X1 platform.

Windows x86_64 is a native target with the same core workflow as macOS and Linux: LayerX1 login, model inference, file tools, sessions, and terminal rendering. Commands run through PowerShell (pwsh, then Windows PowerShell) or `cmd.exe`, with Job Objects keeping timeouts and cleanup from orphaning child processes. Background processes, clipboard, notification sounds, resize handling, and self-upgrade work natively; creation-time process identity tokens protect against PID reuse the way the POSIX boot-id tokens do. The tmux-backed interactive terminal sessions (`terminal.start`) remain macOS/Linux-only until a ConPTY backend lands.

## Install

macOS and Linux:

```bash
curl -fsSL https://layerx1.com/setup.sh | bash
```

Windows PowerShell:

```powershell
irm https://layerx1.com/setup.ps1 | iex
```

## Run x1

Sign in with your X1 account:

```bash
x1 login
x1
```

Inside x1, `/model` or `/models` loads the current LayerX1 catalog and lets you choose a model and its supported reasoning effort. Use `/credits` for plan and balance details, `/usage` for local token and spend history, and `/logout` to remove the subscription session.

The X1 route uses subscription access directly and never sends its OAuth token to third parties. The session is stored privately under `~/.x1/` and refreshed when needed. `/credits` shows your plan, remaining balance, and usage.

Run x1 from a project:

```bash
cd your_project
x1
```

The current directory becomes the primary workspace. Enter a prompt, or run `/help` to browse interactive commands.

The status line hides the workspace path and Git branch by default. Enable the `Status line workspace` option in `/settings`, run `/statusline workspace`, or set it in `~/.x1/settings.json`:

```json
{
  "statusLine": {
    "workspace": true
  }
}
```

List saved sessions with `x1 sessions`. Resume the latest session for the current workspace, or select an exact session ID, through the same command group:

```bash
x1 session resume last
x1 session resume --id <id>
```

Each interactive session names its terminal tab. The title prefers the session name, falls back to the workspace name, and keeps the active model as secondary context. Renaming or resuming a session updates the tab, and exiting clears the x1-owned title. Noninteractive commands do not emit terminal-title controls.

Run `/trace` to create a private Markdown diagnostic with logs, session context, runtime state, permissions, and recent activity. On macOS, x1 copies the `.md` file to the clipboard; on other platforms, it saves the file and prints its path. Review and redact the trace before sharing it.

Use `x1 ask` for a single request:

```bash
x1 ask "explain the changes in this repository"
```

With `--json`, `output` contains accumulated assistant Markdown across the request, while `final_output` contains only a completed final assistant response and is `""` for interrupted, failed, background, or otherwise absent final responses.

Foreground terminal commands run with an explicit finite deadline. x1 uses durable terminal sessions for services, watchers, GUI applications, and other long-lived work, and keeps captured foreground output available through an opaque bounded-read handle for the active session or `--no-save` process.

x1 starts in `auto` permission mode. Routine understood development actions run directly. Each unresolved action receives one narrow safety review based on the current user request and the exact pending action. A clear result authorizes only that action. A caution or unavailable review holds the action and returns advice to the agent without opening a permission prompt or ending the turn.

JSON and quiet requests stay noninteractive by default. Add `--prompt-permissions` to allow configured approval prompts when stdin is a TTY. Automatic safety review never opens that prompt. Prompt text is written to stderr, so JSON stdout stays parseable and quiet stdout stays empty. Piped or redirected stdin remains noninteractive and fails instead of waiting for approval.

Inside a saved session, `/permissions remember <allow|deny> <tool-name> <arguments-json>` stores an exact confirmed rule without running the action. `/permissions` lists stable rule IDs, and `/permissions revoke <rule-id>` removes a stored rule even when its original workspace or file state has changed.

## Embed x1

x1 builds as a native binary or WebAssembly. Applications embedding x1 can provide network transport, session storage, configuration, permission handling, and terminal I/O.

| Surface | Use |
| --- | --- |
| `x1 acp` | Connect the native agent to editors and other Agent Client Protocol clients. |
| `createX1Agent()` | Embed the agent core in a JavaScript host with `x1-core.wasm`. |
| `createX1Terminal()` | Embed the interactive terminal with `x1-term.wasm`. |

The WebAssembly SDK is experimental. See the [WebAssembly SDK](sdk/README.md).

## Extend x1

Add reusable instructions with skills, connect external tools through MCP, or delegate independent work to subagents. Inside x1, `/mcp add <name> <command> [args...]` saves a local server and `/mcp add --transport http <name> <url>` saves a remote Streamable HTTP server. Project instruction files may link within their scope, and read-only workspace or compatibility skill directories and their primary `SKILL.md` files may link within their owning workspace or home; managed skills, secondary resources, and escaping links remain no-follow. Skills installed via symlinks that resolve outside home or workspace (e.g. Nix store paths) are loaded when their resolved target is inside a directory listed in the `X1_SKILL_SYMLINK_AUTHORITIES` environment variable (colon-separated absolute paths). `x1 status` and `x1 doctor` report an invalid trusted MCP profile without starting its servers.

## Build from source

Building x1 requires [Zig 0.16.0+](https://ziglang.org/download/):

```bash
git clone <x1 repository>
cd x1
zig build -Doptimize=ReleaseSafe
./zig-out/bin/x1
```

Run the test suite with `zig build test`. See [CONTRIBUTING.md](CONTRIBUTING.md) for development and contribution guidelines.

## Compatibility exceptions

These formats stay on purpose so existing X1 user state is not stranded:

- Session files remain `~/.x1/layerx1-auth.json`. Older FX/Vercel files at `~/.x1/auth.json` and the unused keychain item `X1_OAUTH_SESSION_V1` are never migrated.
- Replay recordings keep the `.fxtape` extension.
- Historical usage records may still store `https://ai-gateway.vercel.sh` as an origin string. New live traffic uses `https://api.layerx1.com`.
- E2E harnesses may still seed `AI_GATEWAY_API_KEY` and then convert it into a LayerX1 session. The product binary does not read that environment variable.

## License

[Apache-2.0](LICENSE)

Third-party licenses and attributions are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
