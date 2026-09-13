const std = @import("std");
const builtin = @import("builtin");
const credentials = @import("credentials.zig");
const layerx1_session = @import("layerx1_session.zig");
const debug_trace = @import("../shared/debug_trace.zig");
const host = @import("../hosts/host.zig");
const host_target = @import("../hosts/target.zig");
const io_mod = @import("../shared/io.zig");
const oauth = @import("oauth.zig");
const oauth_transport = @import("oauth_transport.zig");
const secret = @import("secret.zig");
const test_builtin_gateway = if (builtin.is_test)
    @import("../../builtins/x1.zig")
else
    struct {};

const Allocator = std.mem.Allocator;
const poll_wait_slice_ms: u64 = 100;
pub const poll_request_timeout_ms: i64 = 15_000;
const max_poll_interval_ms = std.math.maxInt(u64) / std.time.ns_per_ms;

pub const LoginError = error{
    LoginTimedOut,
    NoRefreshToken,
};

pub const SignInState = enum {
    idle,
    polling,
    succeeded,
    failed,
    cancelled,
};

pub const SignInSnapshot = struct {
    state: SignInState = .idle,
    verification_uri: []const u8 = "",
    verification_uri_complete: ?[]const u8 = null,
    user_code: []const u8 = "",
    accepts_manual_code: bool = false,
};

pub const max_manual_code_bytes: usize = 4096;

/// Empty placeholders so unused picker stages compile. X1 does not select
/// Vercel teams; LayerX1 login is the only account path.
pub const Team = struct {
    id: []u8 = &.{},
    slug: []u8 = &.{},
    name: []u8 = &.{},

    pub fn deinit(self: *Team, alloc: Allocator) void {
        if (self.id.len > 0) alloc.free(self.id);
        if (self.slug.len > 0) alloc.free(self.slug);
        if (self.name.len > 0) alloc.free(self.name);
        self.* = undefined;
    }
};

pub const TeamSelection = struct {
    teams: std.ArrayList(Team) = .empty,

    pub fn deinit(self: *TeamSelection, alloc: Allocator) void {
        for (self.teams.items) |*team| team.deinit(alloc);
        self.teams.deinit(alloc);
        self.* = .{};
    }

    pub fn take(self: *TeamSelection) TeamSelection {
        const selection = self.*;
        self.* = .{};
        return selection;
    }

    pub fn currentTeam(_: *const TeamSelection) ?[]const u8 {
        return null;
    }
};

pub const SignInCompletion = struct {
    session: layerx1_session.Session,

    pub fn deinit(self: *SignInCompletion, alloc: Allocator) void {
        self.session.deinit(alloc);
        self.* = undefined;
    }

    pub fn take(self: *SignInCompletion) SignInCompletion {
        const completion = self.*;
        self.session = .{
            .access_token = &.{},
            .refresh_token = &.{},
            .expires_at_ms = 0,
            .account_id = &.{},
        };
        return completion;
    }
};

pub const SignInTransition = union(enum) {
    none,
    succeeded: SignInCompletion,
    failed: anyerror,
    cancelled,
};

pub const PreparedLogin = struct {
    metadata: oauth.Metadata,
    device: oauth.DeviceAuthorization,
    client_id: []u8,

    pub fn deinit(self: *PreparedLogin, alloc: Allocator) void {
        self.metadata.deinit(alloc);
        self.device.deinit(alloc);
        alloc.free(self.client_id);
        self.* = undefined;
    }
};

pub const CompleteSignInFn = *const fn (
    ?*anyopaque,
    Allocator,
    []const u8,
    []const u8,
    *oauth.TokenSet,
) anyerror!SignInCompletion;
pub const SaveSignInFn = *const fn (?*anyopaque, Allocator, SignInCompletion) anyerror!void;
pub const DeinitSignInContextFn = *const fn (?*anyopaque, Allocator) void;
pub const SubmitManualCodeFn = *const fn (?*anyopaque, Allocator, []const u8) anyerror!void;

pub const SignInRuntimeDeps = struct {
    ctx: ?*anyopaque = null,
    deinit_ctx: ?DeinitSignInContextFn = null,
    oauth_transport: oauth_transport.Provider = oauth_transport.unavailable_provider,
    poll: LoginPollDeps = .{},
    complete: CompleteSignInFn = unsupportedCompleteSignIn,
    save: SaveSignInFn = unsupportedSaveSignIn,
    submit_manual_code: ?SubmitManualCodeFn = null,
};

pub const SignInRuntime = struct {
    const Self = @This();

    mutex: std.Io.Mutex = .init,
    thread: ?std.Thread = null,
    cancel_requested: std.atomic.Value(bool) = .init(false),
    state: SignInState = .idle,
    flow: ?PreparedLogin = null,
    completion: ?SignInCompletion = null,
    failure: ?anyerror = null,
    poll_state: ?LoginPollState = null,
    deps: SignInRuntimeDeps = .{},

    pub fn startPrepared(
        self: *Self,
        alloc: Allocator,
        prepared: PreparedLogin,
        deps: SignInRuntimeDeps,
    ) !bool {
        return self.startPreparedWithMode(alloc, prepared, deps, host_target.is_wasm);
    }

    fn startPreparedCooperative(
        self: *Self,
        alloc: Allocator,
        prepared: PreparedLogin,
        deps: SignInRuntimeDeps,
    ) !bool {
        return self.startPreparedWithMode(alloc, prepared, deps, true);
    }

    fn startPreparedWithMode(
        self: *Self,
        alloc: Allocator,
        prepared: PreparedLogin,
        deps: SignInRuntimeDeps,
        comptime cooperative: bool,
    ) !bool {
        const poll_state = if (cooperative)
            LoginPollState.init(deps.poll, prepared.device) catch |err| {
                var rejected = prepared;
                rejected.deinit(alloc);
                if (deps.deinit_ctx) |deinit_ctx| deinit_ctx(deps.ctx, alloc);
                return err;
            }
        else
            null;
        self.mutex.lockUncancelable(io_mod.getIo());
        if (self.thread != null or self.state == .polling or self.completion != null) {
            self.mutex.unlock(io_mod.getIo());
            var rejected = prepared;
            rejected.deinit(alloc);
            if (deps.deinit_ctx) |deinit_ctx| deinit_ctx(deps.ctx, alloc);
            return false;
        }
        self.state = .polling;
        self.failure = null;
        self.flow = prepared;
        self.poll_state = poll_state;
        self.deps = deps;
        self.deps.poll.cancel_flag = &self.cancel_requested;
        self.cancel_requested.store(false, .seq_cst);
        self.mutex.unlock(io_mod.getIo());

        if (cooperative) return true;
        self.thread = std.Thread.spawn(.{}, workerMain, .{ self, alloc }) catch |err| {
            self.mutex.lockUncancelable(io_mod.getIo());
            self.state = .idle;
            self.mutex.unlock(io_mod.getIo());
            self.clearFlow(alloc);
            return err;
        };
        return true;
    }

    pub fn cancel(self: *Self, alloc: Allocator) bool {
        self.cancel_requested.store(true, .seq_cst);
        self.mutex.lockUncancelable(io_mod.getIo());
        const cancelled = self.state == .polling;
        if (cancelled) self.state = .cancelled;
        const thread = self.thread;
        self.thread = null;
        self.mutex.unlock(io_mod.getIo());

        if (comptime !host_target.is_wasm) {
            if (thread) |handle| handle.join();
        }
        self.clearFlow(alloc);
        return cancelled;
    }

    pub fn deinit(self: *Self, alloc: Allocator) void {
        _ = self.cancel(alloc);
        if (self.completion) |*selection| selection.deinit(alloc);
        self.completion = null;
        self.failure = null;
        self.state = .idle;
    }

    pub fn snapshot(self: *const Self) SignInSnapshot {
        const mutable = @constCast(self);
        mutable.mutex.lockUncancelable(io_mod.getIo());
        defer mutable.mutex.unlock(io_mod.getIo());
        const flow = self.flow orelse return .{ .state = self.state };
        return .{
            .state = self.state,
            .verification_uri = flow.device.verification_uri,
            .verification_uri_complete = flow.device.verification_uri_complete,
            .user_code = flow.device.user_code,
            .accepts_manual_code = self.deps.submit_manual_code != null,
        };
    }

    pub fn submitManualCode(self: *Self, alloc: Allocator, code: []const u8) !bool {
        self.mutex.lockUncancelable(io_mod.getIo());
        defer self.mutex.unlock(io_mod.getIo());
        if (self.state != .polling) return false;
        const submit = self.deps.submit_manual_code orelse return false;
        try submit(self.deps.ctx, alloc, code);
        return true;
    }

    pub fn browserUrlAlloc(self: *Self, alloc: Allocator) !?[]u8 {
        self.mutex.lockUncancelable(io_mod.getIo());
        defer self.mutex.unlock(io_mod.getIo());
        const flow = self.flow orelse return null;
        const url = flow.device.verification_uri_complete orelse flow.device.verification_uri;
        return try alloc.dupe(u8, url);
    }

    pub fn pollTransition(self: *Self, alloc: Allocator) SignInTransition {
        self.mutex.lockUncancelable(io_mod.getIo());
        const terminal = switch (self.state) {
            .succeeded, .failed, .cancelled => true,
            .idle, .polling => false,
        };
        const thread = if (terminal) self.thread else null;
        if (terminal) self.thread = null;
        self.mutex.unlock(io_mod.getIo());
        if (!terminal) return .none;

        if (comptime !host_target.is_wasm) {
            if (thread) |handle| handle.join();
        }
        self.clearFlow(alloc);

        self.mutex.lockUncancelable(io_mod.getIo());
        defer self.mutex.unlock(io_mod.getIo());
        const state = self.state;
        self.state = .idle;
        return switch (state) {
            .succeeded => blk: {
                const completion = self.completion orelse break :blk .{ .failed = error.LoginCompletionMissing };
                self.completion = null;
                break :blk .{ .succeeded = completion };
            },
            .failed => blk: {
                const failure = self.failure orelse error.OAuthRequestFailed;
                self.failure = null;
                break :blk .{ .failed = failure };
            },
            .cancelled => .cancelled,
            .idle, .polling => .none,
        };
    }

    fn workerMain(self: *Self, alloc: Allocator) void {
        const flow = if (self.flow) |*prepared| prepared else return;
        var prompt = BrowserOpenPrompt{ .url = flow.device.verification_uri };
        var token = pollForTokenWithDeps(
            alloc,
            self.deps.oauth_transport,
            flow.metadata,
            flow.client_id,
            flow.device,
            &prompt,
            self.deps.poll,
        ) catch |err| {
            self.publishFailure(err);
            return;
        };
        defer token.deinit(alloc);

        self.completeToken(alloc, &token);
    }

    pub fn pulse(self: *Self, alloc: Allocator) void {
        if (comptime !host_target.is_wasm) return;
        self.pulseCooperative(alloc);
    }

    fn pulseCooperative(self: *Self, alloc: Allocator) void {
        if (self.state != .polling) return;
        const flow = if (self.flow) |*prepared| prepared else return;
        const poll_state = if (self.poll_state) |*state| state else {
            self.publishFailure(error.LoginPollStateMissing);
            return;
        };
        const step = pollTokenStep(
            alloc,
            self.deps.oauth_transport,
            flow.metadata,
            flow.client_id,
            flow.device,
            self.deps.poll,
            poll_state,
        ) catch |err| {
            self.publishFailure(err);
            return;
        };
        switch (step) {
            .waiting => {},
            .succeeded => |token| {
                var owned = token;
                defer owned.deinit(alloc);
                self.completeToken(alloc, &owned);
            },
        }
    }

    fn completeToken(self: *Self, alloc: Allocator, token: *oauth.TokenSet) void {
        const flow = if (self.flow) |*prepared| prepared else {
            self.publishFailure(error.LoginFlowMissing);
            return;
        };
        if (self.cancel_requested.load(.seq_cst)) {
            debug_trace.logf("auth", "sign-in discarded token after cancel", .{});
            return;
        }
        var completion = self.deps.complete(
            self.deps.ctx,
            alloc,
            flow.metadata.issuer,
            flow.client_id,
            token,
        ) catch |err| {
            self.publishFailure(err);
            return;
        };
        defer completion.deinit(alloc);

        self.mutex.lockUncancelable(io_mod.getIo());
        defer self.mutex.unlock(io_mod.getIo());
        if (self.state != .polling or self.cancel_requested.load(.seq_cst)) {
            debug_trace.logf("auth", "sign-in discarded session after cancel state={t}", .{self.state});
            return;
        }
        self.deps.save(self.deps.ctx, alloc, completion) catch |err| {
            debug_trace.logf("auth", "sign-in session save failed err={s}", .{@errorName(err)});
            self.failure = err;
            self.state = .failed;
            return;
        };
        self.completion = completion.take();
        self.state = .succeeded;
    }

    fn publishFailure(self: *Self, err: anyerror) void {
        self.mutex.lockUncancelable(io_mod.getIo());
        defer self.mutex.unlock(io_mod.getIo());
        if (self.state != .polling or self.cancel_requested.load(.seq_cst)) {
            debug_trace.logf(
                "auth",
                "sign-in suppressed post-cancel failure err={s} state={t}",
                .{ @errorName(err), self.state },
            );
            return;
        }
        if (err == error.Cancelled) {
            self.state = .cancelled;
            return;
        }
        self.failure = err;
        self.state = .failed;
    }

    fn clearFlow(self: *Self, alloc: Allocator) void {
        self.mutex.lockUncancelable(io_mod.getIo());
        var flow = self.flow;
        const deps = self.deps;
        self.flow = null;
        self.poll_state = null;
        self.deps = .{};
        self.mutex.unlock(io_mod.getIo());
        if (flow) |*prepared| prepared.deinit(alloc);
        if (deps.deinit_ctx) |deinit_ctx| deinit_ctx(deps.ctx, alloc);
    }
};

fn unsupportedCompleteSignIn(
    _: ?*anyopaque,
    _: Allocator,
    _: []const u8,
    _: []const u8,
    _: *oauth.TokenSet,
) !SignInCompletion {
    return error.InvalidSignInCompletion;
}

fn unsupportedSaveSignIn(_: ?*anyopaque, _: Allocator, _: SignInCompletion) !void {
    return error.InvalidSignInCompletion;
}

fn pollForTokenWithPrompt(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    metadata: oauth.Metadata,
    client_id: []const u8,
    device: oauth.DeviceAuthorization,
    prompt: *BrowserOpenPrompt,
    url_opener: host.UrlOpener,
) !oauth.TokenSet {
    return pollForTokenWithDeps(alloc, transport, metadata, client_id, device, prompt, .{
        .url_opener = url_opener,
    });
}

pub const LoginPollDeps = struct {
    ctx: ?*anyopaque = null,
    now_ms: *const fn (?*anyopaque) i64 = realNowMs,
    poll_device_token: *const fn (
        ?*anyopaque,
        Allocator,
        oauth_transport.Provider,
        oauth.Metadata,
        []const u8,
        []const u8,
        *std.atomic.Value(bool),
        std.Io.Clock.Timestamp,
    ) anyerror!oauth.PollResult = realPollDeviceToken,
    sleep_ms: *const fn (?*anyopaque, u64) void = realSleepMs,
    wait_for_enter: *const fn (?*anyopaque, u64) bool = if (host_target.is_wasm or builtin.os.tag == .windows)
        unavailableWaitForEnter
    else
        realWaitForEnter,
    url_opener: host.UrlOpener = host.unavailable_url_opener,
    is_cancelled: *const fn (?*anyopaque) bool = neverCancelled,
    cancel_flag: ?*std.atomic.Value(bool) = null,
    request_timeout_ms: i64 = poll_request_timeout_ms,
};

const LoginPollState = struct {
    expires_at_ms: i64,
    interval_ms: u64,
    next_poll_at_ms: i64,

    fn init(deps: LoginPollDeps, device: oauth.DeviceAuthorization) !LoginPollState {
        const now_ms = deps.now_ms(deps.ctx);
        return .{
            .expires_at_ms = try oauth.expiry_timestamp_ms(now_ms, device.expires_in),
            .interval_ms = try poll_interval_ms(device.interval),
            .next_poll_at_ms = now_ms,
        };
    }

    fn scheduleNext(self: *LoginPollState, now_ms: i64) !void {
        const interval_ms = std.math.cast(i64, self.interval_ms) orelse
            return oauth.OAuthError.InvalidOAuthResponse;
        self.next_poll_at_ms = std.math.add(i64, now_ms, interval_ms) catch
            return oauth.OAuthError.InvalidOAuthResponse;
    }

    fn waitMs(self: LoginPollState, now_ms: i64) u64 {
        if (now_ms >= self.next_poll_at_ms) return 0;
        return @intCast(self.next_poll_at_ms - now_ms);
    }
};

const LoginPollStep = union(enum) {
    waiting,
    succeeded: oauth.TokenSet,
};

fn pollForTokenWithDeps(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    metadata: oauth.Metadata,
    client_id: []const u8,
    device: oauth.DeviceAuthorization,
    prompt: *BrowserOpenPrompt,
    deps: LoginPollDeps,
) !oauth.TokenSet {
    var state = try LoginPollState.init(deps, device);
    while (true) {
        switch (try pollTokenStep(alloc, transport, metadata, client_id, device, deps, &state)) {
            .succeeded => |token| return token,
            .waiting => {
                const wait_ms = state.waitMs(deps.now_ms(deps.ctx));
                if (wait_ms > 0) try waitBetweenPolls(alloc, prompt, deps, wait_ms);
            },
        }
    }
}

fn pollTokenStep(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    metadata: oauth.Metadata,
    client_id: []const u8,
    device: oauth.DeviceAuthorization,
    deps: LoginPollDeps,
    state: *LoginPollState,
) !LoginPollStep {
    const now_ms = deps.now_ms(deps.ctx);
    if (now_ms >= state.expires_at_ms) return LoginError.LoginTimedOut;
    if (pollCancelled(deps)) return error.Cancelled;
    if (now_ms < state.next_poll_at_ms) return .waiting;

    var local_cancel_flag = std.atomic.Value(bool).init(false);
    const cancel_flag = deps.cancel_flag orelse &local_cancel_flag;
    const deadline = std.Io.Clock.Timestamp.fromNow(io_mod.getIo(), .{
        .clock = .awake,
        .raw = .fromMilliseconds(deps.request_timeout_ms),
    });
    switch (try deps.poll_device_token(
        deps.ctx,
        alloc,
        transport,
        metadata,
        client_id,
        device.device_code,
        cancel_flag,
        deadline,
    )) {
        .success => |token| {
            if (pollCancelled(deps)) {
                var owned = token;
                owned.deinit(alloc);
                debug_trace.logf("auth", "sign-in poll discarded granted token after cancel", .{});
                return error.Cancelled;
            }
            return .{ .succeeded = token };
        },
        .pending => {},
        .slow_down => {
            state.interval_ms = std.math.add(u64, state.interval_ms, 5 * std.time.ms_per_s) catch
                return oauth.OAuthError.InvalidOAuthResponse;
            if (state.interval_ms > max_poll_interval_ms) return oauth.OAuthError.InvalidOAuthResponse;
        },
    }
    try state.scheduleNext(deps.now_ms(deps.ctx));
    return .waiting;
}

fn poll_interval_ms(interval_seconds: i64) oauth.OAuthError!u64 {
    const seconds = @max(interval_seconds, 1);
    const signed_interval_ms = std.math.mul(i64, seconds, std.time.ms_per_s) catch
        return oauth.OAuthError.InvalidOAuthResponse;
    const interval_ms = std.math.cast(u64, signed_interval_ms) orelse
        return oauth.OAuthError.InvalidOAuthResponse;
    if (interval_ms > max_poll_interval_ms) return oauth.OAuthError.InvalidOAuthResponse;
    return interval_ms;
}

fn waitBetweenPolls(
    alloc: Allocator,
    prompt: *BrowserOpenPrompt,
    deps: LoginPollDeps,
    interval_ms: u64,
) error{Cancelled}!void {
    var remaining_ms = interval_ms;
    while (remaining_ms > 0) {
        if (pollCancelled(deps)) return error.Cancelled;
        const slice_ms = @min(remaining_ms, poll_wait_slice_ms);
        if (prompt.enabled and !prompt.opened) {
            if (deps.wait_for_enter(deps.ctx, slice_ms)) {
                prompt.opened = true;
                _ = deps.url_opener.open(alloc, prompt.url) catch false;
            }
        } else {
            deps.sleep_ms(deps.ctx, slice_ms);
        }
        remaining_ms -= slice_ms;
    }
    if (pollCancelled(deps)) return error.Cancelled;
}

fn pollCancelled(deps: LoginPollDeps) bool {
    if (deps.is_cancelled(deps.ctx)) return true;
    const flag = deps.cancel_flag orelse return false;
    return flag.load(.seq_cst);
}

const BrowserOpenPrompt = struct {
    url: []const u8,
    enabled: bool = false,
    opened: bool = false,

    fn init(url: []const u8) !BrowserOpenPrompt {
        const stdin_is_tty = try std.Io.File.stdin().isTty(io_mod.getIo());
        return .{
            .url = url,
            .enabled = browserOpenEnabled(io_mod.getenv("X1_NO_OPEN_BROWSER") != null, stdin_is_tty, host.current()),
        };
    }

    fn writeWaitingMessage(self: BrowserOpenPrompt) !void {
        if (self.enabled) {
            try writeStdout("Waiting for authentication. Press Enter to open this in your browser, or use the URL manually.\n");
        } else {
            try writeStdout("Waiting for authentication...\n");
        }
    }
};

fn browserOpenEnabled(no_open_browser: bool, stdin_is_tty: bool, host_capabilities: host.Capabilities) bool {
    return !no_open_browser and stdin_is_tty and host_capabilities.native_url_open;
}

fn realNowMs(_: ?*anyopaque) i64 {
    return io_mod.milliTimestamp();
}

fn realPollDeviceToken(
    _: ?*anyopaque,
    alloc: Allocator,
    transport: oauth_transport.Provider,
    metadata: oauth.Metadata,
    client_id: []const u8,
    device_code: []const u8,
    cancel_flag: *std.atomic.Value(bool),
    deadline: std.Io.Clock.Timestamp,
) !oauth.PollResult {
    return oauth.pollDeviceTokenBounded(
        alloc,
        transport,
        metadata,
        client_id,
        device_code,
        cancel_flag,
        deadline,
    );
}

fn neverCancelled(_: ?*anyopaque) bool {
    return false;
}

fn realSleepMs(_: ?*anyopaque, ms: u64) void {
    io_mod.sleep(ms *| std.time.ns_per_ms);
}

fn unavailableWaitForEnter(_: ?*anyopaque, _: u64) bool {
    return false;
}

fn realWaitForEnter(_: ?*anyopaque, timeout_ms: u64) bool {
    var fds = [_]std.posix.pollfd{.{
        .fd = std.posix.STDIN_FILENO,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const timeout: i32 = @intCast(@min(timeout_ms, @as(u64, @intCast(std.math.maxInt(i32)))));
    const ready = std.posix.poll(&fds, timeout) catch return false;
    if (ready == 0 or (fds[0].revents & std.posix.POLL.IN) == 0) return false;
    discardStdinLine();
    return true;
}

fn discardStdinLine() void {
    var buf: [256]u8 = undefined;
    while (true) {
        const n = std.posix.read(std.posix.STDIN_FILENO, &buf) catch return;
        if (n == 0) return;
        if (std.mem.findScalar(u8, buf[0..n], '\n') != null) return;
    }
}

fn readLine(alloc: Allocator) ![]u8 {
    var read_buf: [1024]u8 = undefined;
    var reader = std.Io.File.stdin().reader(io_mod.getIo(), &read_buf);
    const line = reader.interface.takeDelimiter('\n') catch return try alloc.dupe(u8, "");
    return try alloc.dupe(u8, line orelse "");
}

fn writeStdout(text: []const u8) !void {
    try std.Io.File.stdout().writeStreamingAll(io_mod.getIo(), text);
}

fn writeStdoutFmt(comptime fmt: []const u8, args: anytype) !void {
    var buf: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf, fmt, args);
    try writeStdout(text);
}

const ScriptedPollResult = enum {
    pending,
    slow_down,
    success,
};

const LoginPollTestState = struct {
    alloc: Allocator,
    results: []const ScriptedPollResult,
    poll_index: usize = 0,
    sleep_calls: std.ArrayList(u64) = .empty,
    wait_calls: std.ArrayList(u64) = .empty,
    enter_on_wait: ?usize = null,
    open_count: usize = 0,
    opened_url: ?[]const u8 = null,
    open_available: bool = true,
    open_error: bool = false,
    now_ms: i64 = 0,

    fn init(alloc: Allocator, results: []const ScriptedPollResult) LoginPollTestState {
        return .{ .alloc = alloc, .results = results };
    }

    fn deinit(self: *LoginPollTestState) void {
        self.sleep_calls.deinit(self.alloc);
        self.wait_calls.deinit(self.alloc);
    }

    fn deps(self: *LoginPollTestState) LoginPollDeps {
        return .{
            .ctx = self,
            .now_ms = testNowMs,
            .poll_device_token = testPollDeviceToken,
            .sleep_ms = testSleepMs,
            .wait_for_enter = testWaitForEnter,
            .url_opener = .{
                .context = self,
                .open_fn = testOpenBrowser,
            },
        };
    }

    fn testNowMs(raw: ?*anyopaque) i64 {
        const self = testState(raw);
        return self.now_ms;
    }

    fn testPollDeviceToken(
        raw: ?*anyopaque,
        alloc: Allocator,
        _: oauth_transport.Provider,
        _: oauth.Metadata,
        _: []const u8,
        _: []const u8,
        _: *std.atomic.Value(bool),
        _: std.Io.Clock.Timestamp,
    ) !oauth.PollResult {
        const self = testState(raw);
        if (self.poll_index >= self.results.len) return error.TestUnexpectedDevicePoll;
        const result = self.results[self.poll_index];
        self.poll_index += 1;
        return switch (result) {
            .pending => .pending,
            .slow_down => .slow_down,
            .success => .{ .success = try testTokenSet(alloc) },
        };
    }

    fn testSleepMs(raw: ?*anyopaque, ms: u64) void {
        const self = testState(raw);
        self.sleep_calls.append(self.alloc, ms) catch unreachable;
        self.now_ms += @intCast(ms);
    }

    fn testWaitForEnter(raw: ?*anyopaque, timeout_ms: u64) bool {
        const self = testState(raw);
        self.wait_calls.append(self.alloc, timeout_ms) catch unreachable;
        self.now_ms += @intCast(timeout_ms);
        return if (self.enter_on_wait) |index| self.wait_calls.items.len == index else false;
    }

    fn testOpenBrowser(
        raw: ?*anyopaque,
        _: Allocator,
        url: []const u8,
    ) host.UrlOpenError!bool {
        const self = testState(raw);
        self.open_count += 1;
        self.opened_url = url;
        if (self.open_error) return error.OutOfMemory;
        return self.open_available;
    }

    fn testState(raw: ?*anyopaque) *LoginPollTestState {
        return @ptrCast(@alignCast(raw.?));
    }
};

fn takeLayerX1TestCompletion(alloc: Allocator, token: *oauth.TokenSet) !SignInCompletion {
    const refresh = token.refresh_token orelse return LoginError.NoRefreshToken;
    const account_id = try alloc.dupe(u8, "cust_test");
    errdefer alloc.free(account_id);
    const completion: SignInCompletion = .{
        .session = .{
            .access_token = token.access_token,
            .refresh_token = refresh,
            .expires_at_ms = 0,
            .account_id = account_id,
        },
    };
    token.access_token = &.{};
    token.refresh_token = null;
    return completion;
}

fn testMetadata() oauth.Metadata {
    return .{
        .issuer = @constCast("https://oauth.test"),
        .device_authorization_endpoint = @constCast("https://oauth.test/device"),
        .token_endpoint = @constCast("https://oauth.test/token"),
    };
}

fn testDevice() oauth.DeviceAuthorization {
    return .{
        .device_code = @constCast("device"),
        .user_code = @constCast("USER-CODE"),
        .verification_uri = @constCast("https://oauth.test/oauth/device"),
        .expires_in = 60,
        .interval = 1,
    };
}

fn testTokenSet(alloc: Allocator) !oauth.TokenSet {
    return .{
        .access_token = try alloc.dupe(u8, "access"),
        .refresh_token = try alloc.dupe(u8, "refresh"),
        .expires_in = 3600,
        .scope = try alloc.dupe(u8, oauth.default_scope),
        .token_type = try alloc.dupe(u8, "Bearer"),
    };
}

const SignInTestPollMode = enum {
    pending_then_wait,
    in_flight,
    success,
};

const SignInTestState = struct {
    mode: SignInTestPollMode,
    poll_started: std.atomic.Value(bool) = .init(false),
    poll_count: std.atomic.Value(usize) = .init(0),
    complete_count: std.atomic.Value(usize) = .init(0),
    save_count: std.atomic.Value(usize) = .init(0),

    fn deps(self: *@This()) SignInRuntimeDeps {
        return .{
            .ctx = self,
            .poll = .{
                .ctx = self,
                .poll_device_token = poll,
            },
            .complete = complete,
            .save = save,
        };
    }

    fn poll(
        raw: ?*anyopaque,
        alloc: Allocator,
        _: oauth_transport.Provider,
        _: oauth.Metadata,
        _: []const u8,
        _: []const u8,
        cancel_flag: *std.atomic.Value(bool),
        _: std.Io.Clock.Timestamp,
    ) !oauth.PollResult {
        const self = state(raw);
        _ = self.poll_count.fetchAdd(1, .seq_cst);
        self.poll_started.store(true, .seq_cst);
        return switch (self.mode) {
            .pending_then_wait => .pending,
            .in_flight => {
                while (!cancel_flag.load(.seq_cst)) blockingSleep(1);
                return error.Cancelled;
            },
            .success => .{ .success = try testTokenSet(alloc) },
        };
    }

    fn complete(
        raw: ?*anyopaque,
        alloc: Allocator,
        issuer_url: []const u8,
        client_id: []const u8,
        token: *oauth.TokenSet,
    ) !SignInCompletion {
        const self = state(raw);
        _ = self.complete_count.fetchAdd(1, .seq_cst);
        _ = issuer_url;
        _ = client_id;
        return try takeLayerX1TestCompletion(alloc, token);
    }

    fn save(raw: ?*anyopaque, _: Allocator, _: SignInCompletion) !void {
        const self = state(raw);
        _ = self.save_count.fetchAdd(1, .seq_cst);
    }

    fn state(raw: ?*anyopaque) *@This() {
        return @ptrCast(@alignCast(raw.?));
    }
};

const CooperativeSignInTestState = struct {
    poll: LoginPollTestState,
    complete_count: usize = 0,
    save_count: usize = 0,
    fail_save: bool = false,

    fn init(alloc: Allocator, results: []const ScriptedPollResult) @This() {
        return .{ .poll = LoginPollTestState.init(alloc, results) };
    }

    fn deinit(self: *@This()) void {
        self.poll.deinit();
    }

    fn deps(self: *@This()) SignInRuntimeDeps {
        return .{
            .ctx = self,
            .poll = self.poll.deps(),
            .complete = complete,
            .save = save,
        };
    }

    fn complete(
        raw: ?*anyopaque,
        alloc: Allocator,
        issuer_url: []const u8,
        client_id: []const u8,
        token: *oauth.TokenSet,
    ) !SignInCompletion {
        const self = state(raw);
        self.complete_count += 1;
        _ = issuer_url;
        _ = client_id;
        return try takeLayerX1TestCompletion(alloc, token);
    }

    fn save(raw: ?*anyopaque, _: Allocator, _: SignInCompletion) !void {
        const self = state(raw);
        self.save_count += 1;
        if (self.fail_save) return error.TestStoreCommitFailed;
    }

    fn state(raw: ?*anyopaque) *@This() {
        return @ptrCast(@alignCast(raw.?));
    }
};

fn makeTestPreparedLogin(alloc: Allocator) !PreparedLogin {
    var metadata = try oauth.parseMetadata(
        alloc,
        "{\"issuer\":\"https://oauth.test\",\"device_authorization_endpoint\":\"https://oauth.test/device\",\"token_endpoint\":\"https://oauth.test/token\"}",
    );
    errdefer metadata.deinit(alloc);
    var device = try oauth.parseDeviceAuthorization(
        alloc,
        "{\"device_code\":\"device\",\"user_code\":\"USER-CODE\",\"verification_uri\":\"https://oauth.test/oauth/device\",\"verification_uri_complete\":\"https://oauth.test/oauth/device?code=USER-CODE\",\"expires_in\":60,\"interval\":1}",
    );
    errdefer device.deinit(alloc);
    return .{
        .metadata = metadata,
        .device = device,
        .client_id = try alloc.dupe(u8, "client"),
    };
}

fn blockingSleep(milliseconds: u64) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    threaded.io().sleep(.fromMilliseconds(@intCast(milliseconds)), .real) catch {};
}

fn waitForAtomic(flag: *std.atomic.Value(bool), timeout_ms: u64) bool {
    var remaining_ms = timeout_ms;
    while (remaining_ms > 0) : (remaining_ms -= 1) {
        if (flag.load(.seq_cst)) return true;
        blockingSleep(1);
    }
    return flag.load(.seq_cst);
}

fn waitForSignInTransition(
    runtime: *SignInRuntime,
    alloc: Allocator,
    timeout_ms: u64,
) SignInTransition {
    var remaining_ms = timeout_ms;
    while (remaining_ms > 0) : (remaining_ms -= 1) {
        const transition = runtime.pollTransition(alloc);
        if (transition != .none) return transition;
        blockingSleep(1);
    }
    return runtime.pollTransition(alloc);
}

test "sign-in runtime releases an owned provider context exactly once" {
    const Cleanup = struct {
        fn run(raw: ?*anyopaque, _: Allocator) void {
            const count: *usize = @ptrCast(@alignCast(raw.?));
            count.* += 1;
        }
    };

    const alloc = std.testing.allocator;
    var cleanup_count: usize = 0;
    var runtime: SignInRuntime = .{};
    try std.testing.expect(try runtime.startPreparedCooperative(
        alloc,
        try makeTestPreparedLogin(alloc),
        .{
            .ctx = &cleanup_count,
            .deinit_ctx = Cleanup.run,
        },
    ));
    try std.testing.expect(runtime.cancel(alloc));
    runtime.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), cleanup_count);
}

const WithholdingTokenFixture = struct {
    io_backend: std.Io.Threaded = .init_single_threaded,
    server: std.Io.net.Server,
    thread: ?std.Thread = null,
    server_open: bool = true,
    stopping: std.atomic.Value(bool) = .init(false),
    accepted: std.atomic.Value(bool) = .init(false),
    failure: ?anyerror = null,

    fn init() !@This() {
        var fixture: @This() = .{ .server = undefined };
        var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        fixture.server = try address.listen(fixture.io(), .{ .reuse_address = true });
        return fixture;
    }

    fn start(self: *@This()) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn deinit(self: *@This()) void {
        if (!self.server_open) return;
        const zio = self.io();
        self.stopping.store(true, .seq_cst);
        if (self.thread) |thread| {
            const listener = std.Io.net.Stream{ .socket = self.server.socket };
            listener.shutdown(zio, .both) catch {};
            self.wakeAccept();
            thread.join();
            self.thread = null;
        }
        self.server.deinit(zio);
        self.server_open = false;
    }

    fn tokenEndpoint(self: *@This(), alloc: Allocator) ![]u8 {
        return std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/oauth/token", .{
            self.server.socket.address.getPort(),
        });
    }

    fn io(self: *@This()) std.Io {
        return self.io_backend.io();
    }

    fn wakeAccept(self: *@This()) void {
        var wake_backend: std.Io.Threaded = .init_single_threaded;
        const zio = wake_backend.io();
        const address = std.Io.net.IpAddress{
            .ip4 = .loopback(self.server.socket.address.getPort()),
        };
        var stream = address.connect(zio, .{ .mode = .stream }) catch return;
        stream.close(zio);
    }

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            if (self.stopping.load(.seq_cst) and err == error.SocketNotListening) return;
            self.failure = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        const zio = self.io();
        var stream = try self.server.accept(zio);
        defer stream.close(zio);
        if (self.stopping.load(.seq_cst)) return;
        self.accepted.store(true, .seq_cst);
        while (!self.stopping.load(.seq_cst)) blockingSleep(10);
    }
};

fn makeLoopbackPreparedLogin(alloc: Allocator, token_endpoint: []const u8) !PreparedLogin {
    const issuer = try alloc.dupe(u8, token_endpoint[0..std.mem.lastIndexOfScalar(u8, token_endpoint, '/').?]);
    errdefer alloc.free(issuer);
    const device_endpoint = try std.fmt.allocPrint(alloc, "{s}/device", .{issuer});
    errdefer alloc.free(device_endpoint);
    const owned_token_endpoint = try alloc.dupe(u8, token_endpoint);
    errdefer alloc.free(owned_token_endpoint);
    var device = try oauth.parseDeviceAuthorization(
        alloc,
        "{\"device_code\":\"device\",\"user_code\":\"USER-CODE\",\"verification_uri\":\"https://oauth.test/oauth/device\",\"expires_in\":60,\"interval\":1}",
    );
    errdefer device.deinit(alloc);
    return .{
        .metadata = .{
            .issuer = issuer,
            .device_authorization_endpoint = device_endpoint,
            .token_endpoint = owned_token_endpoint,
        },
        .device = device,
        .client_id = try alloc.dupe(u8, "client"),
    };
}

fn elapsedAwakeMs(started: std.Io.Clock.Timestamp) i64 {
    return started.durationTo(std.Io.Clock.Timestamp.now(io_mod.getIo(), .awake)).raw.toMilliseconds();
}

test "cooperative sign-in polls once per pulse and shares pending and slow_down timing" {
    const alloc = std.testing.allocator;
    var runtime: SignInRuntime = .{};
    defer runtime.deinit(alloc);
    var state = CooperativeSignInTestState.init(alloc, &.{ .pending, .slow_down, .success });
    defer state.deinit();
    try std.testing.expect(try runtime.startPreparedCooperative(
        alloc,
        try makeTestPreparedLogin(alloc),
        state.deps(),
    ));

    runtime.pulseCooperative(alloc);
    try std.testing.expectEqual(@as(usize, 1), state.poll.poll_index);
    try std.testing.expectEqual(@as(i64, 1000), runtime.poll_state.?.next_poll_at_ms);
    runtime.pulseCooperative(alloc);
    try std.testing.expectEqual(@as(usize, 1), state.poll.poll_index);

    state.poll.now_ms = 1000;
    runtime.pulseCooperative(alloc);
    try std.testing.expectEqual(@as(usize, 2), state.poll.poll_index);
    try std.testing.expectEqual(@as(u64, 6000), runtime.poll_state.?.interval_ms);
    try std.testing.expectEqual(@as(i64, 7000), runtime.poll_state.?.next_poll_at_ms);
    state.poll.now_ms = 6999;
    runtime.pulseCooperative(alloc);
    try std.testing.expectEqual(@as(usize, 2), state.poll.poll_index);

    state.poll.now_ms = 7000;
    runtime.pulseCooperative(alloc);
    var transition = runtime.pollTransition(alloc);
    switch (transition) {
        .succeeded => |*selection| selection.deinit(alloc),
        else => return error.TestExpectedSuccessfulSignIn,
    }
    try std.testing.expectEqual(@as(usize, 1), state.complete_count);
    try std.testing.expectEqual(@as(usize, 1), state.save_count);
}

test "cooperative sign-in cancellation publishes no session" {
    const alloc = std.testing.allocator;
    var runtime: SignInRuntime = .{};
    defer runtime.deinit(alloc);
    var state = CooperativeSignInTestState.init(alloc, &.{.pending});
    defer state.deinit();
    try std.testing.expect(try runtime.startPreparedCooperative(
        alloc,
        try makeTestPreparedLogin(alloc),
        state.deps(),
    ));
    runtime.pulseCooperative(alloc);

    try std.testing.expect(runtime.cancel(alloc));
    try std.testing.expectEqual(SignInTransition.cancelled, runtime.pollTransition(alloc));
    try std.testing.expectEqual(@as(usize, 0), state.complete_count);
    try std.testing.expectEqual(@as(usize, 0), state.save_count);
}

test "cooperative sign-in reports device-code expiry without another poll" {
    const alloc = std.testing.allocator;
    var runtime: SignInRuntime = .{};
    defer runtime.deinit(alloc);
    var state = CooperativeSignInTestState.init(alloc, &.{.success});
    defer state.deinit();
    var prepared = try makeTestPreparedLogin(alloc);
    prepared.device.expires_in = 1;
    try std.testing.expect(try runtime.startPreparedCooperative(alloc, prepared, state.deps()));
    state.poll.now_ms = 1000;
    runtime.pulseCooperative(alloc);

    switch (runtime.pollTransition(alloc)) {
        .failed => |err| try std.testing.expectEqual(LoginError.LoginTimedOut, err),
        else => return error.TestExpectedExpiredSignIn,
    }
    try std.testing.expectEqual(@as(usize, 0), state.poll.poll_index);
    try std.testing.expectEqual(@as(usize, 0), state.save_count);
}

test "cooperative sign-in store failure is traced and becomes a recoverable transition" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(root);
    const trace_path = try std.fs.path.join(alloc, &.{ root, "sign-in-store-failure.log" });
    defer alloc.free(trace_path);
    debug_trace.resetForTest();
    defer debug_trace.resetForTest();
    try debug_trace.configureForTestWithScopes(alloc, trace_path, "auth");

    var runtime: SignInRuntime = .{};
    defer runtime.deinit(alloc);
    var state = CooperativeSignInTestState.init(alloc, &.{.success});
    defer state.deinit();
    state.fail_save = true;
    try std.testing.expect(try runtime.startPreparedCooperative(
        alloc,
        try makeTestPreparedLogin(alloc),
        state.deps(),
    ));
    runtime.pulseCooperative(alloc);

    switch (runtime.pollTransition(alloc)) {
        .failed => |err| try std.testing.expectEqual(error.TestStoreCommitFailed, err),
        else => return error.TestExpectedStoreFailure,
    }
    debug_trace.shutdown();
    var trace_file = try std.Io.Dir.openFileAbsolute(std.testing.io, trace_path, .{});
    defer trace_file.close(std.testing.io);
    const trace = try io_mod.readFileToEnd(alloc, &trace_file, 4096);
    defer alloc.free(trace);
    try std.testing.expect(std.mem.find(u8, trace, "sign-in session save failed err=TestStoreCommitFailed") != null);
    try std.testing.expect(std.mem.find(u8, trace, "access") == null);
    try std.testing.expect(std.mem.find(u8, trace, "refresh") == null);
}

test "VT-8(b) cancelling sign-in during the inter-poll wait publishes and saves nothing" {
    const alloc = std.testing.allocator;
    var runtime: SignInRuntime = .{};
    defer runtime.deinit(alloc);
    var state = SignInTestState{ .mode = .pending_then_wait };

    try std.testing.expect(try runtime.startPrepared(
        alloc,
        try makeTestPreparedLogin(alloc),
        state.deps(),
    ));
    try std.testing.expect(waitForAtomic(&state.poll_started, 500));
    try std.testing.expect(runtime.cancel(alloc));

    try std.testing.expectEqual(SignInTransition.cancelled, runtime.pollTransition(alloc));
    try std.testing.expectEqual(@as(usize, 0), state.complete_count.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 0), state.save_count.load(.seq_cst));
    try std.testing.expect(runtime.thread == null);
    try std.testing.expect(runtime.flow == null);
}

test "VT-8(b) cancelling sign-in during an in-flight poll publishes and saves nothing" {
    const alloc = std.testing.allocator;
    var runtime: SignInRuntime = .{};
    defer runtime.deinit(alloc);
    var state = SignInTestState{ .mode = .in_flight };

    try std.testing.expect(try runtime.startPrepared(
        alloc,
        try makeTestPreparedLogin(alloc),
        state.deps(),
    ));
    try std.testing.expect(waitForAtomic(&state.poll_started, 500));
    try std.testing.expect(runtime.cancel(alloc));

    try std.testing.expectEqual(SignInTransition.cancelled, runtime.pollTransition(alloc));
    try std.testing.expectEqual(@as(usize, 0), state.complete_count.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 0), state.save_count.load(.seq_cst));
    try std.testing.expect(runtime.thread == null);
    try std.testing.expect(runtime.flow == null);
}

test "VT-8(c) cancelled sign-in is reaped before a second flow completes" {
    const alloc = std.testing.allocator;
    var runtime: SignInRuntime = .{};
    defer runtime.deinit(alloc);
    var state = SignInTestState{ .mode = .in_flight };

    try std.testing.expect(try runtime.startPrepared(
        alloc,
        try makeTestPreparedLogin(alloc),
        state.deps(),
    ));
    try std.testing.expect(waitForAtomic(&state.poll_started, 500));
    try std.testing.expect(runtime.cancel(alloc));
    try std.testing.expectEqual(SignInTransition.cancelled, runtime.pollTransition(alloc));
    try std.testing.expect(runtime.thread == null);

    state.mode = .success;
    state.poll_started.store(false, .seq_cst);
    try std.testing.expect(try runtime.startPrepared(
        alloc,
        try makeTestPreparedLogin(alloc),
        state.deps(),
    ));
    const transition = waitForSignInTransition(&runtime, alloc, 500);
    switch (transition) {
        .succeeded => |completed| {
            var selection = completed;
            defer selection.deinit(alloc);
        },
        else => try std.testing.expect(false),
    }
    try std.testing.expectEqual(@as(usize, 1), state.complete_count.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 1), state.save_count.load(.seq_cst));
    try std.testing.expect(runtime.thread == null);
}

test "VT-8(d) sign-in deinit cancels and joins a live worker" {
    const alloc = std.testing.allocator;
    var runtime: SignInRuntime = .{};
    var state = SignInTestState{ .mode = .in_flight };

    try std.testing.expect(try runtime.startPrepared(
        alloc,
        try makeTestPreparedLogin(alloc),
        state.deps(),
    ));
    try std.testing.expect(waitForAtomic(&state.poll_started, 500));
    runtime.deinit(alloc);

    try std.testing.expect(runtime.thread == null);
    try std.testing.expect(runtime.flow == null);
    try std.testing.expectEqual(SignInState.idle, runtime.state);
    try std.testing.expectEqual(@as(usize, 0), state.complete_count.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 0), state.save_count.load(.seq_cst));
}

test "VT-8(e) withheld token HTTP poll has bounded timeout cancel restart and deinit" {
    const alloc = std.testing.allocator;

    var timeout_fixture = try WithholdingTokenFixture.init();
    defer timeout_fixture.deinit();
    try timeout_fixture.start();
    const timeout_endpoint = try timeout_fixture.tokenEndpoint(alloc);
    defer alloc.free(timeout_endpoint);
    var timeout_runtime: SignInRuntime = .{};
    defer timeout_runtime.deinit(alloc);
    const timeout_started = std.Io.Clock.Timestamp.now(io_mod.getIo(), .awake);
    try std.testing.expect(try timeout_runtime.startPrepared(
        alloc,
        try makeLoopbackPreparedLogin(alloc, timeout_endpoint),
        .{
            .oauth_transport = test_builtin_gateway.oauth_transport_provider,
            .poll = .{ .request_timeout_ms = 40 },
        },
    ));
    const timeout_transition = waitForSignInTransition(&timeout_runtime, alloc, 1000);
    switch (timeout_transition) {
        .failed => |err| try std.testing.expect(err == error.Timeout),
        else => try std.testing.expect(false),
    }
    try std.testing.expect(waitForAtomic(&timeout_fixture.accepted, 500));
    try std.testing.expect(elapsedAwakeMs(timeout_started) < 500);
    timeout_fixture.deinit();
    if (timeout_fixture.failure) |err| return err;

    var cancel_fixture = try WithholdingTokenFixture.init();
    defer cancel_fixture.deinit();
    try cancel_fixture.start();
    const cancel_endpoint = try cancel_fixture.tokenEndpoint(alloc);
    defer alloc.free(cancel_endpoint);
    var cancel_runtime: SignInRuntime = .{};
    defer cancel_runtime.deinit(alloc);
    try std.testing.expect(try cancel_runtime.startPrepared(
        alloc,
        try makeLoopbackPreparedLogin(alloc, cancel_endpoint),
        .{
            .oauth_transport = test_builtin_gateway.oauth_transport_provider,
            .poll = .{ .request_timeout_ms = 1000 },
        },
    ));
    try std.testing.expect(waitForAtomic(&cancel_fixture.accepted, 500));
    const cancel_started = std.Io.Clock.Timestamp.now(io_mod.getIo(), .awake);
    try std.testing.expect(cancel_runtime.cancel(alloc));
    try std.testing.expect(elapsedAwakeMs(cancel_started) < 500);
    try std.testing.expectEqual(SignInTransition.cancelled, cancel_runtime.pollTransition(alloc));

    var restart_state = SignInTestState{ .mode = .success };
    try std.testing.expect(try cancel_runtime.startPrepared(
        alloc,
        try makeTestPreparedLogin(alloc),
        restart_state.deps(),
    ));
    const restart_transition = waitForSignInTransition(&cancel_runtime, alloc, 500);
    switch (restart_transition) {
        .succeeded => |completed| {
            var selection = completed;
            defer selection.deinit(alloc);
        },
        else => try std.testing.expect(false),
    }
    cancel_fixture.deinit();
    if (cancel_fixture.failure) |err| return err;

    var deinit_fixture = try WithholdingTokenFixture.init();
    defer deinit_fixture.deinit();
    try deinit_fixture.start();
    const deinit_endpoint = try deinit_fixture.tokenEndpoint(alloc);
    defer alloc.free(deinit_endpoint);
    var deinit_runtime: SignInRuntime = .{};
    try std.testing.expect(try deinit_runtime.startPrepared(
        alloc,
        try makeLoopbackPreparedLogin(alloc, deinit_endpoint),
        .{
            .oauth_transport = test_builtin_gateway.oauth_transport_provider,
            .poll = .{ .request_timeout_ms = 1000 },
        },
    ));
    try std.testing.expect(waitForAtomic(&deinit_fixture.accepted, 500));
    const deinit_started = std.Io.Clock.Timestamp.now(io_mod.getIo(), .awake);
    deinit_runtime.deinit(alloc);
    try std.testing.expect(elapsedAwakeMs(deinit_started) < 500);
    try std.testing.expect(deinit_runtime.thread == null);
    try std.testing.expect(deinit_runtime.flow == null);
    deinit_fixture.deinit();
    if (deinit_fixture.failure) |err| return err;
}

test "login polling starts before waiting for browser input" {
    const alloc = std.testing.allocator;
    var state = LoginPollTestState.init(alloc, &.{.success});
    defer state.deinit();
    var prompt = BrowserOpenPrompt{ .url = "https://oauth.test/oauth/device", .enabled = true };

    var token = try pollForTokenWithDeps(alloc, oauth_transport.unavailable_provider, testMetadata(), "client", testDevice(), &prompt, state.deps());
    defer token.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), state.poll_index);
    try std.testing.expectEqual(@as(usize, 0), state.wait_calls.items.len);
    try std.testing.expectEqual(@as(usize, 0), state.sleep_calls.items.len);
    try std.testing.expectEqual(@as(usize, 0), state.open_count);
}

test "login polling opens browser once when enter arrives while waiting" {
    const alloc = std.testing.allocator;
    var state = LoginPollTestState.init(alloc, &.{ .pending, .pending, .success });
    state.enter_on_wait = 1;
    defer state.deinit();
    var prompt = BrowserOpenPrompt{ .url = "https://oauth.test/oauth/device", .enabled = true };

    var token = try pollForTokenWithDeps(alloc, oauth_transport.unavailable_provider, testMetadata(), "client", testDevice(), &prompt, state.deps());
    defer token.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 3), state.poll_index);
    try std.testing.expectEqual(@as(usize, 1), state.open_count);
    try std.testing.expectEqualStrings("https://oauth.test/oauth/device", state.opened_url.?);
    try std.testing.expectEqual(@as(usize, 1), state.wait_calls.items.len);
    try std.testing.expectEqual(@as(usize, 19), state.sleep_calls.items.len);
    for (state.sleep_calls.items) |sleep_ms| {
        try std.testing.expectEqual(@as(u64, 100), sleep_ms);
    }
}

test "login polling continues when the URL opener is unavailable" {
    const alloc = std.testing.allocator;
    var state = LoginPollTestState.init(alloc, &.{ .pending, .pending, .success });
    state.enter_on_wait = 1;
    state.open_available = false;
    defer state.deinit();
    var prompt = BrowserOpenPrompt{ .url = "https://oauth.test/oauth/device", .enabled = true };

    var token = try pollForTokenWithDeps(alloc, oauth_transport.unavailable_provider, testMetadata(), "client", testDevice(), &prompt, state.deps());
    defer token.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 3), state.poll_index);
    try std.testing.expectEqual(@as(usize, 1), state.open_count);
    try std.testing.expect(prompt.opened);
}

test "login polling continues when the URL opener fails" {
    const alloc = std.testing.allocator;
    var state = LoginPollTestState.init(alloc, &.{ .pending, .pending, .success });
    state.enter_on_wait = 1;
    state.open_error = true;
    defer state.deinit();
    var prompt = BrowserOpenPrompt{ .url = "https://oauth.test/oauth/device", .enabled = true };

    var token = try pollForTokenWithDeps(alloc, oauth_transport.unavailable_provider, testMetadata(), "client", testDevice(), &prompt, state.deps());
    defer token.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 3), state.poll_index);
    try std.testing.expectEqual(@as(usize, 1), state.open_count);
    try std.testing.expect(prompt.opened);
}

test "login polling slow_down increases the next interval" {
    const alloc = std.testing.allocator;
    var state = LoginPollTestState.init(alloc, &.{ .slow_down, .success });
    defer state.deinit();
    var prompt = BrowserOpenPrompt{ .url = "https://oauth.test/oauth/device" };

    var token = try pollForTokenWithDeps(alloc, oauth_transport.unavailable_provider, testMetadata(), "client", testDevice(), &prompt, state.deps());
    defer token.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 2), state.poll_index);
    try std.testing.expectEqual(@as(usize, 60), state.sleep_calls.items.len);
    for (state.sleep_calls.items) |sleep_ms| {
        try std.testing.expectEqual(@as(u64, 100), sleep_ms);
    }
}

test "login polling disabled browser prompt still polls immediately" {
    const alloc = std.testing.allocator;
    var state = LoginPollTestState.init(alloc, &.{ .pending, .success });
    state.enter_on_wait = 1;
    defer state.deinit();
    var prompt = BrowserOpenPrompt{ .url = "https://oauth.test/oauth/device", .enabled = false };

    var token = try pollForTokenWithDeps(alloc, oauth_transport.unavailable_provider, testMetadata(), "client", testDevice(), &prompt, state.deps());
    defer token.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 2), state.poll_index);
    try std.testing.expectEqual(@as(usize, 0), state.wait_calls.items.len);
    try std.testing.expectEqual(@as(usize, 0), state.open_count);
    try std.testing.expectEqual(@as(usize, 10), state.sleep_calls.items.len);
    for (state.sleep_calls.items) |sleep_ms| {
        try std.testing.expectEqual(@as(u64, 100), sleep_ms);
    }
}

test "login polling rejects invalid provider timing values" {
    const alloc = std.testing.allocator;
    var state = LoginPollTestState.init(alloc, &.{});
    defer state.deinit();
    var prompt = BrowserOpenPrompt{ .url = "https://oauth.test/oauth/device" };

    var device = testDevice();
    device.expires_in = -1;
    try std.testing.expectError(
        oauth.OAuthError.InvalidOAuthResponse,
        pollForTokenWithDeps(alloc, oauth_transport.unavailable_provider, testMetadata(), "client", device, &prompt, state.deps()),
    );

    device = testDevice();
    device.interval = @intCast(max_poll_interval_ms / std.time.ms_per_s + 1);
    try std.testing.expectError(
        oauth.OAuthError.InvalidOAuthResponse,
        pollForTokenWithDeps(alloc, oauth_transport.unavailable_provider, testMetadata(), "client", device, &prompt, state.deps()),
    );
    try std.testing.expectEqual(@as(usize, 0), state.poll_index);
}

test "login browser opener respects environment tty and platform gates" {
    try std.testing.expect(!browserOpenEnabled(true, true, host.nativeForOs(.macos)));
    try std.testing.expect(!browserOpenEnabled(false, false, host.nativeForOs(.macos)));
    try std.testing.expect(!browserOpenEnabled(false, true, host.nativeForOs(.linux)));
    try std.testing.expect(browserOpenEnabled(false, true, host.nativeForOs(.macos)));
}
