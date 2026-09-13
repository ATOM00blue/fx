const std = @import("std");
const builtin = @import("builtin");
const contracts = @import("contracts.zig");
const command_environment = @import("../execution/command_environment.zig");
const io_mod = @import("../shared/io.zig");

const Allocator = std.mem.Allocator;

pub const ResolveError = error{
    MissingLoginShell,
    RelativeShellPath,
    UnsupportedShell,
};

pub const Profile = command_environment.Profile;
pub const Environment = command_environment.Environment;

const ShellKind = enum { bash, zsh, powershell, cmd };

/// Capacity for PATH-join candidates during Windows shell discovery. Entries
/// that do not fit are skipped rather than treated as errors.
const windows_shell_search_buffer_len = 1024;

fn shellKind(path: []const u8) ?ShellKind {
    const basename = std.fs.path.basename(path);
    if (comptime builtin.os.tag == .windows) {
        return windowsShellKind(basename);
    }
    if (std.mem.eql(u8, basename, "bash")) return .bash;
    if (std.mem.eql(u8, basename, "zsh")) return .zsh;
    return null;
}

/// Windows basename classification: case-insensitive, with or without the
/// `.exe` extension. Pure string logic, so it stays testable on every target.
fn windowsShellKind(basename: []const u8) ?ShellKind {
    const stem = if (std.ascii.endsWithIgnoreCase(basename, ".exe"))
        basename[0 .. basename.len - ".exe".len]
    else
        basename;
    if (std.ascii.eqlIgnoreCase(stem, "pwsh")) return .powershell;
    if (std.ascii.eqlIgnoreCase(stem, "powershell")) return .powershell;
    if (std.ascii.eqlIgnoreCase(stem, "cmd")) return .cmd;
    if (std.ascii.eqlIgnoreCase(stem, "bash")) return .bash;
    if (std.ascii.eqlIgnoreCase(stem, "zsh")) return .zsh;
    return null;
}

/// The flag each shell uses to run a single command string.
fn commandFlagFor(kind: ShellKind) []const u8 {
    return switch (kind) {
        .bash, .zsh => "-c",
        .powershell => "-Command",
        .cmd => "/C",
    };
}

var windows_fallback_shell_buffer: [windows_shell_search_buffer_len]u8 = undefined;

fn fallbackLoginShell() []const u8 {
    if (comptime builtin.os.tag == .windows) {
        return windowsDefaultShellInto(&windows_fallback_shell_buffer) orelse "cmd";
    }
    return if (builtin.os.tag == .macos) "/bin/zsh" else "/bin/bash";
}

/// Windows default shell discovery, in order of preference: PowerShell 7
/// (`pwsh.exe`), Windows PowerShell (`powershell.exe`), Git-for-Windows
/// `bash.exe`, then the COMSPEC environment variable (normally `cmd.exe`).
/// The result is written into `out` when a shell is found.
fn windowsDefaultShellInto(out: []u8) ?[]const u8 {
    if (windowsResolveExecutable("pwsh.exe", out)) |shell| return shell;
    if (windowsResolveExecutable("powershell.exe", out)) |shell| return shell;
    if (windowsResolveExecutable("bash.exe", out)) |shell| return shell;
    const comspec = io_mod.getenv("COMSPEC") orelse return null;
    if (comspec.len == 0 or comspec.len > out.len) return null;
    @memcpy(out[0..comspec.len], comspec);
    return out[0..comspec.len];
}

/// Absolute path of the first PowerShell found on PATH (PowerShell 7, then
/// Windows PowerShell), for Windows machinery that requires it. The result is
/// written into `out` and returned when found.
pub fn windowsPowerShellPath(out: []u8) ?[]const u8 {
    if (comptime builtin.os.tag != .windows) return null;
    if (windowsResolveExecutable("pwsh.exe", out)) |shell| return shell;
    return windowsResolveExecutable("powershell.exe", out);
}

/// Resolves a bare executable `name` against PATH on Windows, trying the name
/// as given and, when it has no extension, with `.exe` appended. The winning
/// candidate is written into `out`; entries that do not fit are skipped.
fn windowsResolveExecutable(name: []const u8, out: []u8) ?[]const u8 {
    if (name.len == 0) return null;
    var names: [2][]const u8 = undefined;
    var names_len: usize = 0;
    names[names_len] = name;
    names_len += 1;
    var extension_buffer: [windows_shell_search_buffer_len]u8 = undefined;
    if (std.mem.lastIndexOfScalar(u8, name, '.') == null) {
        if (std.fmt.bufPrint(&extension_buffer, "{s}.exe", .{name})) |extended| {
            names[names_len] = extended;
            names_len += 1;
        } else |_| {}
    }
    const path_env = io_mod.getenv("PATH") orelse return null;
    var directories = std.mem.splitScalar(u8, path_env, std.fs.path.delimiter);
    while (directories.next()) |directory| {
        if (directory.len == 0) continue;
        for (names[0..names_len]) |candidate_name| {
            const candidate = std.fmt.bufPrint(
                out,
                "{s}" ++ std.fs.path.sep_str ++ "{s}",
                .{ directory, candidate_name },
            ) catch continue;
            if (windowsFileExists(candidate)) return candidate;
        }
    }
    return null;
}

fn windowsFileExists(path: []const u8) bool {
    std.Io.Dir.accessAbsolute(io_mod.getIo(), path, .{}) catch return false;
    return true;
}

fn supportedLoginShell(
    alloc: Allocator,
    configured_login_shell: ?[]const u8,
) (ResolveError || Allocator.Error)![]const u8 {
    if (comptime builtin.os.tag == .windows) {
        return windowsSupportedLoginShell(alloc, configured_login_shell);
    }
    const path = configured_login_shell orelse return error.MissingLoginShell;
    if (!std.fs.path.isAbsolute(path)) return error.RelativeShellPath;
    if (shellKind(path) != null) return path;
    return fallbackLoginShell();
}

/// Windows login-shell selection: absolute configured shells are used as on
/// POSIX, bare names such as `pwsh` resolve through PATH, and an absent or
/// unsupported configuration falls back to the discovered default shell.
fn windowsSupportedLoginShell(
    alloc: Allocator,
    configured_login_shell: ?[]const u8,
) (ResolveError || Allocator.Error)![]const u8 {
    const configured = configured_login_shell orelse return fallbackLoginShell();
    if (std.fs.path.isAbsolute(configured)) {
        if (shellKind(configured) != null) return configured;
        return fallbackLoginShell();
    }
    var buffer: [windows_shell_search_buffer_len]u8 = undefined;
    const resolved = windowsResolveExecutable(configured, &buffer) orelse
        return error.RelativeShellPath;
    if (shellKind(resolved) != null) return try alloc.dupe(u8, resolved);
    return fallbackLoginShell();
}

pub const Invocation = struct {
    path: []const u8,
    /// The flag this shell uses to execute one command string; set by
    /// `resolveAlloc` from the resolved shell kind.
    command_flag: []const u8 = "-c",
    values: [6][]const u8 = @splat(""),
    len: usize = 0,

    pub fn argv(self: *const Invocation) []const []const u8 {
        return self.values[0..self.len];
    }

    fn append(self: *Invocation, value: []const u8) void {
        self.values[self.len] = value;
        self.len += 1;
    }

    pub fn setCommand(self: *Invocation, command: []const u8) void {
        self.append(self.command_flag);
        self.append(command);
    }
};

/// Scratch storage behind the no-allocator `resolve` wrapper used by callers
/// predating allocator threading. Windows PATH resolutions are duped here, so
/// a result stays valid until the next `resolve` call. Twice the search
/// capacity covers every dupe the resolution path can request.
var resolve_fallback_buffer: [windows_shell_search_buffer_len * 2]u8 = undefined;

pub fn resolve(
    configured_login_shell: ?[]const u8,
    shell: contracts.ShellSpec,
) ResolveError!Invocation {
    var fba = std.heap.FixedBufferAllocator.init(&resolve_fallback_buffer);
    return resolveAlloc(fba.allocator(), configured_login_shell, shell) catch |err| switch (err) {
        // The fixed buffer is at least as large as every PATH candidate the
        // resolver can produce, so allocation failure is unreachable; map it
        // to the nearest resolver error to keep the legacy signature.
        error.OutOfMemory => error.RelativeShellPath,
        error.MissingLoginShell => error.MissingLoginShell,
        error.RelativeShellPath => error.RelativeShellPath,
        error.UnsupportedShell => error.UnsupportedShell,
    };
}

pub fn resolveAlloc(
    alloc: Allocator,
    configured_login_shell: ?[]const u8,
    shell: contracts.ShellSpec,
) (ResolveError || Allocator.Error)!Invocation {
    const Selection = struct {
        path: []const u8,
        clean_start: bool,
    };
    const selection: Selection = switch (shell) {
        .user_login => .{
            .path = try supportedLoginShell(alloc, configured_login_shell),
            .clean_start = false,
        },
        .executable => |value| .{
            .path = value.path,
            .clean_start = value.clean_start,
        },
    };
    const kind_path = try absoluteShellPath(alloc, selection.path);

    const kind = shellKind(kind_path) orelse return error.UnsupportedShell;

    var result = Invocation{
        .path = kind_path,
        .command_flag = commandFlagFor(kind),
    };
    result.append(kind_path);
    appendKindArguments(&result, kind, selection.clean_start);
    return result;
}

/// Requires an absolute shell path, except on Windows where configured bare
/// names such as `pwsh` are resolved through PATH instead of rejected.
fn absoluteShellPath(
    alloc: Allocator,
    path: []const u8,
) (ResolveError || Allocator.Error)![]const u8 {
    if (comptime builtin.os.tag == .windows) {
        if (std.fs.path.isAbsolute(path)) return path;
        var buffer: [windows_shell_search_buffer_len]u8 = undefined;
        const resolved = windowsResolveExecutable(path, &buffer) orelse
            return error.RelativeShellPath;
        return try alloc.dupe(u8, resolved);
    }
    if (!std.fs.path.isAbsolute(path)) return error.RelativeShellPath;
    return path;
}

/// Per-kind interactive argv flags, shared by resolution and tests.
fn appendKindArguments(result: *Invocation, kind: ShellKind, clean_start: bool) void {
    switch (kind) {
        .bash => {
            if (clean_start) {
                result.append("--noprofile");
                result.append("--norc");
            } else {
                result.append("--login");
            }
            result.append("-i");
        },
        .zsh => {
            if (clean_start) {
                result.append("-f");
            } else {
                result.append("-l");
            }
            result.append("-i");
        },
        .powershell => {
            // `--NonInteractive` suppresses interactive prompts while the
            // shell keeps reading commands; `--NoProfile` is added only for
            // clean starts so login sessions load the user profile.
            result.append("--NoLogo");
            result.append("--NonInteractive");
            if (clean_start) result.append("--NoProfile");
        },
        .cmd => {},
    }
}

pub fn configuredLoginShellInto(buffer: []u8) ?[]const u8 {
    if (comptime builtin.os.tag == .windows) {
        var discovery: [windows_shell_search_buffer_len]u8 = undefined;
        const shell = windowsDefaultShellInto(&discovery) orelse return null;
        if (shell.len > buffer.len) return null;
        @memcpy(buffer[0..shell.len], shell);
        return buffer[0..shell.len];
    }
    if (comptime !builtin.link_libc or builtin.os.tag == .wasi) {
        return null;
    }
    var entry: std.c.passwd = undefined;
    var scratch: [4096]u8 = undefined;
    var found: ?*std.c.passwd = null;
    if (std.c.getpwuid_r(
        std.c.getuid(),
        &entry,
        &scratch,
        scratch.len,
        &found,
    ) != 0) return null;
    const record = found orelse return null;
    const shell_ptr = record.shell orelse return null;
    const shell = std.mem.span(shell_ptr);
    if (shell.len == 0 or shell.len > buffer.len) return null;
    @memcpy(buffer[0..shell.len], shell);
    return buffer[0..shell.len];
}

pub fn environment(
    alloc: Allocator,
    configured_login_shell: ?[]const u8,
    profile: ?Profile,
) (ResolveError || Allocator.Error)!Environment {
    const selected = profile orelse .user;
    const path = try supportedLoginShell(alloc, configured_login_shell);
    _ = try resolveAlloc(alloc, null, switch (selected) {
        .clean => .{ .executable = .{ .path = path, .clean_start = true } },
        .user => .{ .executable = .{ .path = path } },
    });
    return switch (selected) {
        .clean => .{ .clean = try alloc.dupe(u8, path) },
        .user => .{ .user = try alloc.dupe(u8, path) },
    };
}

pub fn profileShell(
    alloc: Allocator,
    configured_login_shell: ?[]const u8,
    profile: Profile,
) (ResolveError || Allocator.Error)!contracts.ShellSpec {
    return switch (profile) {
        .clean => blk: {
            const path = try supportedLoginShell(alloc, configured_login_shell);
            _ = try resolveAlloc(alloc, null, .{ .executable = .{ .path = path, .clean_start = true } });
            break :blk .{ .executable = .{
                .path = try alloc.dupe(u8, path),
                .clean_start = true,
            } };
        },
        .user => blk: {
            const configured = configured_login_shell orelse
                break :blk .user_login;
            const path = try supportedLoginShell(alloc, configured);
            if (std.mem.eql(u8, path, configured)) break :blk .user_login;
            break :blk .{ .executable = .{
                .path = try alloc.dupe(u8, path),
            } };
        },
    };
}

const captured_zsh_user_prelude = "\\builtin trap - TERM; ";

pub fn capturedInvocation(
    alloc: Allocator,
    environment_value: Environment,
    command: []const u8,
) (ResolveError || Allocator.Error)!Invocation {
    switch (environment_value) {
        .legacy, .workspace_clean => return error.UnsupportedShell,
        .clean => |path| {
            var invocation = try resolveAlloc(alloc, null, .{ .executable = .{
                .path = path,
                .clean_start = true,
            } });
            // Only the POSIX shells carry an interactive flag to drop;
            // powershell and cmd build non-interactive argv already.
            if (shellKind(path)) |kind| {
                if (kind == .bash or kind == .zsh) removeInteractiveFlag(&invocation);
            }
            invocation.setCommand(command);
            return invocation;
        },
        .user => |path| {
            var invocation = try resolveAlloc(alloc, path, .user_login);
            const kind = shellKind(path);
            if (kind == .bash) {
                removeInteractiveFlag(&invocation);
                invocation.append("-O");
                invocation.append("expand_aliases");
            }
            const effective_command = if (kind == .zsh)
                try std.mem.concat(alloc, u8, &.{ captured_zsh_user_prelude, command })
            else
                command;
            invocation.setCommand(effective_command);
            return invocation;
        },
    }
}

/// Invocation of the Windows default shell running one captured command
/// (powershell when discoverable, otherwise the COMSPEC shell). Returns null
/// when no shell resolves so callers can fall back to a literal `cmd /C`.
pub fn defaultShellCommandInvocation(
    alloc: Allocator,
    command: []const u8,
) Allocator.Error!?Invocation {
    if (comptime builtin.os.tag != .windows) return null;
    var discovery: [windows_shell_search_buffer_len]u8 = undefined;
    const shell = windowsDefaultShellInto(&discovery) orelse return null;
    var invocation = resolveAlloc(alloc, null, .{ .executable = .{ .path = shell } }) catch
        return null;
    invocation.setCommand(command);
    return invocation;
}

pub fn formatInvocationCommand(
    alloc: Allocator,
    invocation: *const Invocation,
) Allocator.Error![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(alloc);
    for (invocation.argv(), 0..) |word, index| {
        if (index != 0) try output.append(alloc, ' ');
        try appendShellWord(&output, alloc, word);
    }
    return output.toOwnedSlice(alloc);
}

fn removeInteractiveFlag(invocation: *Invocation) void {
    std.debug.assert(invocation.len > 0);
    std.debug.assert(std.mem.eql(u8, invocation.values[invocation.len - 1], "-i"));
    invocation.len -= 1;
}

pub fn buildBootstrap(
    alloc: Allocator,
    executable: []const u8,
    control_path: []const u8,
    nonce: []const u8,
    command_path: ?[]const u8,
) Allocator.Error![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(alloc);

    try output.appendSlice(alloc, "set +x; ");
    if (command_path) |path| {
        try output.appendSlice(alloc, "x1_terminal_command=$(< ");
        try appendShellWord(&output, alloc, path);
        try output.appendSlice(alloc, ") || exit 125; ");
    }
    try appendMarker(&output, alloc, executable, control_path, nonce, "shell-ready");
    if (command_path) |_| {
        try output.appendSlice(alloc, " || exit 125; ");
        try appendMarker(
            &output,
            alloc,
            executable,
            control_path,
            nonce,
            "command-started",
        );
        try output.appendSlice(
            alloc,
            " || exit 125; builtin eval -- \"$x1_terminal_command\"; " ++
                "x1_terminal_status=$?; exit \"$x1_terminal_status\"\n",
        );
    } else {
        try output.appendSlice(alloc, " || exit 125\n");
    }
    return output.toOwnedSlice(alloc);
}

pub fn buildSourceCommand(
    alloc: Allocator,
    bootstrap_path: []const u8,
) Allocator.Error![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(alloc);
    try output.appendSlice(alloc, ". ");
    try appendShellWord(&output, alloc, bootstrap_path);
    try output.append(alloc, '\n');
    return output.toOwnedSlice(alloc);
}

fn appendMarker(
    output: *std.ArrayList(u8),
    alloc: Allocator,
    executable: []const u8,
    control_path: []const u8,
    nonce: []const u8,
    event: []const u8,
) Allocator.Error!void {
    try appendShellWord(output, alloc, executable);
    inline for (.{
        "--x1-internal-terminal-control",
        control_path,
        nonce,
        event,
    }) |word| {
        try output.append(alloc, ' ');
        try appendShellWord(output, alloc, word);
    }
}

fn appendShellWord(
    output: *std.ArrayList(u8),
    alloc: Allocator,
    word: []const u8,
) Allocator.Error!void {
    try output.append(alloc, '\'');
    for (word) |byte| {
        if (byte == '\'') {
            try output.appendSlice(alloc, "'\"'\"'");
        } else {
            try output.append(alloc, byte);
        }
    }
    try output.append(alloc, '\'');
}

test "resolver builds Bash and zsh interactive argv" {
    const bash = try resolve("/bin/bash", .user_login);
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "/bin/bash", "--login", "-i" },
        bash.argv(),
    );

    const zsh = try resolve(
        null,
        .{ .executable = .{ .path = "/bin/zsh" } },
    );
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "/bin/zsh", "-l", "-i" },
        zsh.argv(),
    );
}

test "resolver makes clean startup explicit" {
    const bash = try resolve(
        null,
        .{ .executable = .{ .path = "/usr/local/bin/bash", .clean_start = true } },
    );
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "/usr/local/bin/bash", "--noprofile", "--norc", "-i" },
        bash.argv(),
    );

    const zsh = try resolve(
        null,
        .{ .executable = .{ .path = "/bin/zsh", .clean_start = true } },
    );
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "/bin/zsh", "-f", "-i" },
        zsh.argv(),
    );
}

test "resolver rejects missing relative and unsupported shells" {
    try std.testing.expectError(
        error.MissingLoginShell,
        resolve(null, .user_login),
    );
    if (builtin.os.tag != .windows) {
        // POSIX keeps exact basename matching, so a bare name stays relative.
        try std.testing.expectError(
            error.RelativeShellPath,
            resolve(null, .{ .executable = .{ .path = "zsh" } }),
        );
    }
    try std.testing.expectError(
        error.UnsupportedShell,
        resolve(null, .{ .executable = .{ .path = "/bin/fish" } }),
    );
}

test "windows shell kind classification is case-insensitive with optional exe suffix" {
    try std.testing.expectEqual(ShellKind.powershell, windowsShellKind("pwsh"));
    try std.testing.expectEqual(ShellKind.powershell, windowsShellKind("PWSH.EXE"));
    try std.testing.expectEqual(ShellKind.powershell, windowsShellKind("powershell"));
    try std.testing.expectEqual(ShellKind.powershell, windowsShellKind("PowerShell.exe"));
    try std.testing.expectEqual(ShellKind.cmd, windowsShellKind("cmd"));
    try std.testing.expectEqual(ShellKind.cmd, windowsShellKind("CMD.EXE"));
    try std.testing.expectEqual(ShellKind.bash, windowsShellKind("bash.exe"));
    try std.testing.expectEqual(ShellKind.bash, windowsShellKind("BASH"));
    try std.testing.expectEqual(ShellKind.zsh, windowsShellKind("zsh.EXE"));
    try std.testing.expectEqual(@as(?ShellKind, null), windowsShellKind("fish"));
    try std.testing.expectEqual(@as(?ShellKind, null), windowsShellKind("fish.exe"));
    // Only the `.exe` extension is stripped; other suffixes stay unsupported.
    try std.testing.expectEqual(@as(?ShellKind, null), windowsShellKind("pwsh.cmd"));
}

test "interactive argv table covers every shell kind" {
    const Case = struct {
        kind: ShellKind,
        clean_start: bool,
        expected: []const []const u8,
    };
    const cases = [_]Case{
        .{ .kind = .bash, .clean_start = false, .expected = &.{ "--login", "-i" } },
        .{ .kind = .bash, .clean_start = true, .expected = &.{ "--noprofile", "--norc", "-i" } },
        .{ .kind = .zsh, .clean_start = false, .expected = &.{ "-l", "-i" } },
        .{ .kind = .zsh, .clean_start = true, .expected = &.{ "-f", "-i" } },
        .{ .kind = .powershell, .clean_start = false, .expected = &.{ "--NoLogo", "--NonInteractive" } },
        .{ .kind = .powershell, .clean_start = true, .expected = &.{ "--NoLogo", "--NonInteractive", "--NoProfile" } },
        .{ .kind = .cmd, .clean_start = false, .expected = &.{} },
        .{ .kind = .cmd, .clean_start = true, .expected = &.{} },
    };
    for (cases) |case| {
        var invocation = Invocation{
            .path = "shell",
            .command_flag = commandFlagFor(case.kind),
        };
        invocation.append("shell");
        appendKindArguments(&invocation, case.kind, case.clean_start);
        try std.testing.expectEqualSlices([]const u8, case.expected, invocation.argv()[1..]);
    }
}

test "command flags map per shell kind" {
    const expectations = [_]struct {
        kind: ShellKind,
        flag: []const u8,
    }{
        .{ .kind = .bash, .flag = "-c" },
        .{ .kind = .zsh, .flag = "-c" },
        .{ .kind = .powershell, .flag = "-Command" },
        .{ .kind = .cmd, .flag = "/C" },
    };
    for (expectations) |expectation| {
        var invocation = Invocation{
            .path = "shell",
            .command_flag = commandFlagFor(expectation.kind),
        };
        invocation.append("shell");
        appendKindArguments(&invocation, expectation.kind, false);
        invocation.setCommand("printf ok");
        const expected_tail = [_][]const u8{ expectation.flag, "printf ok" };
        try std.testing.expectEqualSlices(
            []const u8,
            &expected_tail,
            invocation.argv()[invocation.argv().len - 2 ..],
        );
    }

    // Invocations built without resolution keep the historical POSIX default.
    var legacy = Invocation{ .path = "/bin/bash" };
    legacy.setCommand("echo hi");
    try std.testing.expectEqualStrings("-c", legacy.argv()[0]);
}

test "login shell resolution falls back without accepting explicit unsupported shells" {
    const fallback = try resolve("/opt/homebrew/bin/fish", .user_login);
    try std.testing.expectEqualStrings(fallbackLoginShell(), fallback.path);
    if (builtin.os.tag == .macos) {
        try std.testing.expectEqualSlices(
            []const u8,
            &.{ "/bin/zsh", "-l", "-i" },
            fallback.argv(),
        );
    } else {
        try std.testing.expectEqualSlices(
            []const u8,
            &.{ "/bin/bash", "--login", "-i" },
            fallback.argv(),
        );
    }

    try std.testing.expectError(
        error.UnsupportedShell,
        resolve(null, .{ .executable = .{ .path = "/opt/homebrew/bin/fish" } }),
    );
}

test "captured profiles use exact non-PTY argv" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const bash_clean = try capturedInvocation(arena, .{ .clean = "/bin/bash" }, "printf clean");
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "/bin/bash", "--noprofile", "--norc", "-c", "printf clean" },
        bash_clean.argv(),
    );
    const bash_user = try capturedInvocation(arena, .{ .user = "/bin/bash" }, "printf user");
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "/bin/bash", "--login", "-O", "expand_aliases", "-c", "printf user" },
        bash_user.argv(),
    );
    const zsh_clean = try capturedInvocation(arena, .{ .clean = "/bin/zsh" }, "printf clean");
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "/bin/zsh", "-f", "-c", "printf clean" },
        zsh_clean.argv(),
    );
    const zsh_user = try capturedInvocation(arena, .{ .user = "/bin/zsh" }, "printf user");
    const expected_zsh_user = [_][]const u8{
        "/bin/zsh",
        "-l",
        "-i",
        "-c",
        "\\builtin trap - TERM; printf user",
    };
    try std.testing.expectEqual(expected_zsh_user.len, zsh_user.argv().len);
    for (&expected_zsh_user, zsh_user.argv()) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
    }
}

test "captured invocation provider projection shell-quotes every argv word" {
    const invocation = try capturedInvocation(std.testing.allocator, .{ .clean = "/bin/zsh" }, "printf '%s' ok");
    const command = try formatInvocationCommand(std.testing.allocator, &invocation);
    defer std.testing.allocator.free(command);
    try std.testing.expectEqualStrings(
        "'/bin/zsh' '-f' '-c' 'printf '\"'\"'%s'\"'\"' ok'",
        command,
    );
}

test "profile normalization defaults captured and persistent execution to user" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expect((try environment(arena, "/bin/bash", null)).eql(.{ .user = "/bin/bash" }));
    try std.testing.expect((try environment(arena, "/bin/zsh", null)).eql(.{ .user = "/bin/zsh" }));
    try std.testing.expect((try environment(arena, "/bin/zsh", .clean)).eql(.{ .clean = "/bin/zsh" }));
    try std.testing.expect((try environment(arena, "/bin/zsh", .user)).eql(.{ .user = "/bin/zsh" }));
    try std.testing.expectEqual(contracts.ShellSpec.user_login, try profileShell(arena, "/bin/zsh", .user));
    try std.testing.expectEqualStrings(
        "/bin/zsh",
        (try profileShell(arena, "/bin/zsh", .clean)).executable.path,
    );
}

test "unsupported login shell profiles fall back for captured and persistent execution" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const fallback = fallbackLoginShell();
    const user_environment = try environment(arena, "/opt/homebrew/bin/fish", .user);
    const clean_environment = try environment(arena, "/opt/homebrew/bin/fish", .clean);
    try std.testing.expect(user_environment.eql(.{ .user = fallback }));
    try std.testing.expect(clean_environment.eql(.{ .clean = fallback }));

    const user_invocation = try capturedInvocation(arena, user_environment, "printf user");
    const clean_invocation = try capturedInvocation(arena, clean_environment, "printf clean");
    try std.testing.expectEqualStrings(fallback, user_invocation.path);
    try std.testing.expectEqualStrings(fallback, clean_invocation.path);

    try std.testing.expectEqualStrings(
        fallback,
        (try profileShell(arena, "/opt/homebrew/bin/fish", .user)).executable.path,
    );
    try std.testing.expectEqualStrings(
        fallback,
        (try profileShell(arena, "/opt/homebrew/bin/fish", .clean)).executable.path,
    );
}

test "bootstrap quotes private paths and separates command completion" {
    const commandless = try buildBootstrap(
        std.testing.allocator,
        "/tmp/x1'bin",
        "/tmp/control",
        "nonce",
        null,
    );
    defer std.testing.allocator.free(commandless);
    try std.testing.expectEqualStrings(
        "set +x; '/tmp/x1'\"'\"'bin' '--x1-internal-terminal-control' " ++
            "'/tmp/control' 'nonce' 'shell-ready' || exit 125\n",
        commandless,
    );

    const command = try buildBootstrap(
        std.testing.allocator,
        "/tmp/x1",
        "/tmp/control",
        "nonce",
        "/tmp/command",
    );
    defer std.testing.allocator.free(command);
    try std.testing.expect(
        std.mem.find(u8, command, "'command-started'") != null,
    );
    try std.testing.expect(
        std.mem.find(u8, command, "builtin eval --") != null,
    );
    try std.testing.expect(
        std.mem.find(u8, command, "exit \"$x1_terminal_status\"") != null,
    );

    const source = try buildSourceCommand(
        std.testing.allocator,
        "/tmp/bootstrap'file",
    );
    defer std.testing.allocator.free(source);
    try std.testing.expectEqualStrings(
        ". '/tmp/bootstrap'\"'\"'file'\n",
        source,
    );
}

fn checkBootstrapAllocationFailures(alloc: Allocator) !void {
    const bootstrap = try buildBootstrap(
        alloc,
        "/tmp/x1",
        "/tmp/control",
        "nonce",
        "/tmp/command",
    );
    defer alloc.free(bootstrap);
    const source = try buildSourceCommand(alloc, "/tmp/bootstrap");
    defer alloc.free(source);
}

test "bootstrap construction cleans every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkBootstrapAllocationFailures,
        .{},
    );
}
