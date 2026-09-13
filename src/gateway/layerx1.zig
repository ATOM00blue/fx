const std = @import("std");
const image_attachments = @import("../core/images/image_attachments.zig");
const layerx1_session = @import("../core/auth/layerx1_session.zig");
const secret = @import("../core/auth/secret.zig");
const stream_provider = @import("../core/agent/stream_provider.zig");
const io_mod = @import("../core/shared/io.zig");
const types = @import("../core/shared/types.zig");
const gateway_client = @import("http_runtime.zig");
const gateway_provider = @import("../core/gateway/gateway_provider.zig");
const output_contracts = @import("../core/output/output_contracts.zig");
const responses_protocol = @import("responses_protocol.zig");
const x1_agent_profile = @import("x1_agent_profile.zig");
const model_tool_schema = @import("../core/tooling/model_tool_schema.zig");
const gateway_error_format = @import("../core/shared/gateway_error_format.zig");

const Allocator = std.mem.Allocator;
const endpoint = "https://api.layerx1.com/v1/responses";
const e2e_endpoint_env = "X1_E2E_LAYERX1_RESPONSES_URL";
const max_error_body_bytes: usize = 256 * 1024;
const max_sse_line_bytes: usize = 1024 * 1024;
const max_sse_aggregate_bytes: usize = 64 * 1024 * 1024;
const max_sse_events: usize = 100_000;
const max_tool_calls: usize = 128;
const max_tool_identity_bytes: usize = 1024;
const max_tool_arguments_bytes: usize = 4 * 1024 * 1024;
const max_provider_state_bytes: usize = 4 * 1024 * 1024;
const transfer_buffer_bytes: usize = 256 * 1024;
const connect_timeout_ms: i64 = 30_000;
pub const max_inference_extra_headers = 3 + x1_agent_profile.max_request_headers;

pub const agent_stream_provider = stream_provider.Provider{
    .stream_fn = streamCompletion,
};

fn validateModel(model: []const u8) !void {
    if (model.len == 0 or model.len > 256) return error.InvalidLayerX1Model;
    for (model) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return error.InvalidLayerX1Model;
    }
}

pub fn buildRequest(
    alloc: Allocator,
    request: stream_provider.RequestData,
) ![]u8 {
    try validateModel(request.model);
    if (request.budget) |budget| {
        if (budget.cancel_flag) |flag| if (flag.load(.seq_cst)) return error.Cancelled;
        _ = budget.deadline;
    }

    var instructions: std.Io.Writer.Allocating = .init(alloc);
    defer instructions.deinit();
    for (request.messages) |message| {
        if (message.role != .system) continue;
        const text = message.content orelse continue;
        if (text.len == 0) continue;
        if (instructions.written().len > 0) try instructions.writer.writeAll("\n\n");
        try instructions.writer.writeAll(text);
    }
    if (instructions.written().len == 0) try instructions.writer.writeAll("You are a helpful assistant.");

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const writer = &out.writer;
    try writer.writeAll("{\"model\":");
    try std.json.Stringify.value(request.model, .{}, writer);
    try writer.writeAll(",\"store\":false,\"stream\":true,\"instructions\":");
    try std.json.Stringify.value(instructions.written(), .{}, writer);
    try writer.writeAll(",\"input\":[");
    try writeResponsesInput(writer, alloc, request.messages, request.verified_images);
    try writer.writeByte(']');

    var selected_tools = request.tools;
    var forced_functions: ?[]model_tool_schema.FunctionSchema = null;
    defer if (forced_functions) |functions| alloc.free(functions);
    if (request.vision_mode != .unavailable and request.tools.advertisedFunction("vision") == null) {
        const vision = request.tools.registry.lookup("vision") orelse
            return error.VisionToolNotRegistered;
        const functions = try alloc.alloc(
            model_tool_schema.FunctionSchema,
            request.tools.additional_functions.len + 1,
        );
        std.mem.copyForwards(
            model_tool_schema.FunctionSchema,
            functions[0..request.tools.additional_functions.len],
            request.tools.additional_functions,
        );
        functions[functions.len - 1] = vision.model_schema;
        forced_functions = functions;
        selected_tools.additional_functions = functions;
    }
    _ = try responses_protocol.writeTools(writer, alloc, selected_tools);
    try writer.writeAll(",\"tool_choice\":");
    if (request.vision_mode == .required) {
        try writer.writeAll("{\"type\":\"function\",\"name\":\"vision\"}");
    } else {
        try std.json.Stringify.value(request.tool_choice.label(), .{}, writer);
    }
    try writer.writeAll(",\"parallel_tool_calls\":true,\"include\":[\"reasoning.encrypted_content\"]");
    try writer.writeAll(",\"text\":{\"verbosity\":\"low\"");
    if (request.response_format) |format| {
        if (format.schema != .object) return error.InvalidStructuredResponseSchema;
        try writer.writeAll(",\"format\":{\"type\":\"json_schema\",\"name\":");
        try std.json.Stringify.value(format.name, .{}, writer);
        try writer.writeAll(",\"description\":");
        try std.json.Stringify.value(format.description, .{}, writer);
        try writer.writeAll(",\"schema\":");
        try std.json.Stringify.value(format.schema, .{}, writer);
        try writer.writeAll(",\"strict\":true}");
    }
    try writer.writeByte('}');

    if (request.provider_options.reasoning) |effort| {
        // `none` is the explicit non-thinking choice. Omitting the Responses
        // reasoning object also keeps hidden reasoning out of the client-visible
        // stream; every other effort opts into the summary stream.
        if (!std.mem.eql(u8, effort.label(), "none")) {
            try writer.writeAll(",\"reasoning\":{\"effort\":");
            try std.json.Stringify.value(effort.label(), .{}, writer);
            try writer.writeAll(",\"summary\":\"auto\"}");
        }
    }
    if (request.max_output_tokens) |limit| try writer.print(",\"max_output_tokens\":{d}", .{limit});
    try writer.writeByte('}');
    return out.toOwnedSlice();
}

fn writeResponsesInput(
    writer: *std.Io.Writer,
    alloc: Allocator,
    messages: []const types.ChatMessage,
    images: ?[]const image_attachments.VerifiedSnapshot,
) !void {
    return responses_protocol.writeInput(writer, alloc, messages, images, .{
        .tool_calls = max_tool_calls,
        .tool_identity_bytes = max_tool_identity_bytes,
        .tool_arguments_bytes = max_tool_arguments_bytes,
        .provider_state_bytes = max_provider_state_bytes,
    }) catch |err| switch (err) {
        error.ProviderStateTooLarge => error.LayerX1ProviderStateTooLarge,
        error.InvalidProviderState => error.InvalidLayerX1ProviderState,
        error.ToolCallLimitExceeded => error.LayerX1ToolCallLimitExceeded,
        error.ToolArgumentsTooLarge => error.LayerX1ToolArgumentsTooLarge,
        else => err,
    };
}

fn streamCompletion(
    _: ?*anyopaque,
    alloc: Allocator,
    request: stream_provider.ModelRequest,
) !stream_provider.Result {
    if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;
    if (request.credential.source != .layerx1_subscription) {
        return error.LayerX1SubscriptionCredentialRequired;
    }
    const account_id = request.credential.account_id orelse
        return error.LayerX1SubscriptionAccountRequired;
    if (!layerx1_session.validAccountId(account_id)) return error.InvalidLayerX1SubscriptionAccount;
    try validateModel(request.model);
    const payload = try buildRequest(alloc, request.data());
    defer alloc.free(payload);
    var result = streamPrepared(alloc, request, payload) catch |err| {
        if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;
        if (requestDeadlineExpired(request)) return error.Timeout;
        request.attempt_evidence.network_failure = gateway_client.networkFailureEvidence(err, request.delivery.load());
        return err;
    };
    if (requestDeadlineExpired(request)) {
        result.deinit(alloc);
        return error.Timeout;
    }
    return result;
}

fn requestDeadlineExpired(request: stream_provider.ModelRequest) bool {
    const deadline = request.deadline orelse return false;
    const now = std.Io.Clock.Timestamp.now(io_mod.getIo(), .awake);
    return !std.Io.Clock.Timestamp.compare(now, .lt, deadline);
}

const OpenedRequest = struct {
    request: ?std.http.Client.Request,

    pub fn deinit(self: *OpenedRequest, _: Allocator) void {
        if (self.request) |*request| request.deinit();
        self.request = null;
    }

    pub fn take(self: *OpenedRequest) std.http.Client.Request {
        const request = self.request.?;
        self.request = null;
        return request;
    }
};

const OpenRequestOperation = struct {
    client: *std.http.Client,
    uri: std.Uri,
    auth_header: []const u8,
    extra_headers: []const std.http.Header,

    pub fn run(self: *@This()) !OpenedRequest {
        return .{ .request = try self.client.request(.POST, self.uri, .{
            .headers = .{
                .content_type = .{ .override = "application/json" },
                .authorization = .{ .override = self.auth_header },
                .accept_encoding = .omit,
                .user_agent = .{ .override = gateway_client.user_agent },
            },
            .extra_headers = self.extra_headers,
            .keep_alive = false,
            .redirect_behavior = .unhandled,
        }) };
    }
};

pub fn inferenceExtraHeaders(
    buf: *[max_inference_extra_headers]std.http.Header,
    account_id: []const u8,
    session_id: ?[]const u8,
    identity: x1_agent_profile.RequestIdentity,
) ![]std.http.Header {
    var count: usize = 0;
    buf[count] = .{ .name = "accept", .value = "text/event-stream" };
    count += 1;
    buf[count] = .{ .name = "x-account-id", .value = account_id };
    count += 1;
    const profile = try x1_agent_profile.requestHeaders(identity);
    for (profile.slice()) |header| {
        buf[count] = .{ .name = header.name, .value = header.value };
        count += 1;
    }
    if (session_id) |id| if (id.len > 0) {
        buf[count] = .{ .name = "x-session-id", .value = id };
        count += 1;
    };
    return buf[0..count];
}

pub fn streamPrepared(
    alloc: Allocator,
    request: stream_provider.ModelRequest,
    payload: []const u8,
) !stream_provider.Result {
    if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;
    const account_id = request.credential.account_id.?;
    const auth_header = try std.fmt.allocPrint(alloc, "Bearer {s}", .{request.credential.secret});
    defer secret.zeroAndFree(alloc, auth_header);
    const request_endpoint = if (io_mod.getenv(e2e_endpoint_env)) |override| endpoint: {
        if (!gateway_client.isLoopbackHttpUrl(override)) return error.InvalidE2ELayerX1Endpoint;
        break :endpoint override;
    } else endpoint;
    const uri = try std.Uri.parse(request_endpoint);

    var extra_headers_buf: [max_inference_extra_headers]std.http.Header = undefined;
    const extra_headers = try inferenceExtraHeaders(
        &extra_headers_buf,
        account_id,
        request.session_id,
        x1_agent_profile.identityForRequest(request),
    );

    var client: std.http.Client = .{ .allocator = alloc, .io = io_mod.getIo() };
    defer client.deinit();
    var open_operation = OpenRequestOperation{
        .client = &client,
        .uri = uri,
        .auth_header = auth_header,
        .extra_headers = extra_headers,
    };
    var connect_deadline = std.Io.Clock.Timestamp.fromNow(io_mod.getIo(), .{
        .clock = .awake,
        .raw = .fromMilliseconds(connect_timeout_ms),
    });
    if (request.deadline) |deadline| {
        if (std.Io.Clock.Timestamp.compare(deadline, .lt, connect_deadline)) {
            connect_deadline = deadline;
        }
    }
    try request.admission.admit();
    var opened = try gateway_client.runBoundedHttpOperation(
        OpenedRequest,
        alloc,
        request.cancel_flag,
        connect_deadline,
        &open_operation,
    );
    var http_request = opened.take();
    defer http_request.deinit();
    var cancel_watch_done = std.atomic.Value(bool).init(false);
    const cancel_watcher = if (http_request.connection) |connection|
        if (request.deadline) |deadline|
            try gateway_client.spawnHttpCancelWatcherBounded(
                &cancel_watch_done,
                request.cancel_flag,
                deadline,
                connection.stream_writer.stream,
            )
        else
            try gateway_client.spawnHttpCancelWatcher(
                &cancel_watch_done,
                request.cancel_flag,
                connection.stream_writer.stream,
            )
    else
        null;
    defer {
        cancel_watch_done.store(true, .seq_cst);
        if (cancel_watcher) |thread| thread.join();
    }
    if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;

    http_request.transfer_encoding = .{ .content_length = payload.len };
    var send_buffer: [8192]u8 = undefined;
    request.delivery.markPossiblySent();
    var body_writer = try http_request.sendBodyUnflushed(&send_buffer);
    try body_writer.writer.writeAll(payload);
    try body_writer.end();
    if (http_request.connection) |connection| try connection.flush();
    if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;

    var response = try http_request.receiveHead(&.{});
    if (response.head.status != .ok) {
        var transfer: [16 * 1024]u8 = undefined;
        const reader = response.reader(&transfer);
        const bounded_body = reader.allocRemaining(alloc, .limited(max_error_body_bytes + 1)) catch |err| switch (err) {
            error.StreamTooLong => try alloc.dupe(u8, "LayerX1 error response exceeded the local limit"),
            else => return err,
        };
        const body = if (bounded_body.len > max_error_body_bytes) body: {
            alloc.free(bounded_body);
            break :body try alloc.dupe(u8, "LayerX1 error response exceeded the local limit");
        } else bounded_body;
        return .{ .failed = .{
            .kind = failureKind(response.head.status),
            .detail = body,
            .ownership = .owned,
        } };
    }

    var transfer_buffer: [transfer_buffer_bytes]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    var events = request.events;
    const completion = try consumeSse(
        alloc,
        reader,
        &events,
        EventBridge.content,
        EventBridge.toolStart,
        EventBridge.reasoning,
        EventBridge.toolInput,
        request.cancel_flag,
        request.content_capture_limit,
    );
    return .{ .completed = .{
        .completion = completion,
        .usage = .{ .unavailable = .possibly_billed },
        .ownership = .owned,
    } };
}

const EventBridge = struct {
    fn sink(raw: *anyopaque) *stream_provider.EventSink {
        return @ptrCast(@alignCast(raw));
    }

    fn content(raw: *anyopaque, chunk: []const u8) void {
        sink(raw).emit(.{ .content_delta = chunk });
    }

    fn reasoning(raw: *anyopaque, chunk: []const u8) void {
        sink(raw).emit(.{ .reasoning_delta = chunk });
    }

    fn toolInput(raw: *anyopaque, chunk: []const u8) void {
        sink(raw).emit(.{ .tool_input_delta = chunk });
    }

    fn toolStart(raw: *anyopaque, id: []const u8, name: []const u8, label: ?[]const u8) void {
        sink(raw).emit(.{ .tool_started = .{ .id = id, .name = name, .label = label } });
    }
};

fn failureKind(status: std.http.Status) stream_provider.FailureKind {
    return switch (status) {
        .bad_request => .invalid_request,
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .payload_too_large => .request_too_large,
        .too_many_requests => .rate_limited,
        .internal_server_error => .server_error,
        .bad_gateway => .bad_gateway,
        .service_unavailable => .unavailable,
        .gateway_timeout => .gateway_timeout,
        else => .provider_error,
    };
}

const SseReader = struct {
    pending_line: std.ArrayList(u8) = .empty,
    aggregate_bytes: usize = 0,

    const Line = struct {
        bytes: []const u8,
        wire_bytes: usize,
    };

    fn deinit(self: *SseReader, alloc: Allocator) void {
        self.pending_line.deinit(alloc);
    }

    fn release(self: *SseReader) void {
        self.pending_line.clearRetainingCapacity();
    }

    fn next(self: *SseReader, alloc: Allocator, reader: anytype) !?[]const u8 {
        while (true) {
            const line = try self.readLine(alloc, reader) orelse return null;
            self.aggregate_bytes = responses_protocol.checkedAccumulatedSize(
                self.aggregate_bytes,
                line.wire_bytes,
                max_sse_aggregate_bytes,
            ) catch return error.LayerX1ResourceLimitExceeded;
            const trimmed = std.mem.trim(u8, line.bytes, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == ':') {
                self.release();
                continue;
            }
            if (!std.mem.startsWith(u8, trimmed, "data:")) {
                self.release();
                continue;
            }
            const data = std.mem.trim(u8, trimmed["data:".len..], " \t");
            if (std.mem.eql(u8, data, "[DONE]")) return null;
            return data;
        }
    }

    fn readLine(self: *SseReader, alloc: Allocator, reader: anytype) !?Line {
        while (true) {
            const fragment = reader.takeDelimiter('\n') catch |err| switch (err) {
                error.StreamTooLong => {
                    const buffered = reader.buffered();
                    if (buffered.len == 0) return error.LayerX1SseReadStalled;
                    if (buffered.len > max_sse_line_bytes - self.pending_line.items.len) {
                        return error.LayerX1SseEventTooLarge;
                    }
                    try self.pending_line.appendSlice(alloc, buffered);
                    reader.tossBuffered();
                    continue;
                },
                error.ReadFailed => return error.ReadFailed,
            } orelse {
                if (self.pending_line.items.len > 0) {
                    return .{
                        .bytes = self.pending_line.items,
                        .wire_bytes = self.pending_line.items.len,
                    };
                }
                return null;
            };
            if (fragment.len > max_sse_line_bytes - self.pending_line.items.len) {
                return error.LayerX1SseEventTooLarge;
            }
            if (self.pending_line.items.len == 0) {
                return .{
                    .bytes = fragment,
                    .wire_bytes = fragment.len + 1,
                };
            }
            try self.pending_line.appendSlice(alloc, fragment);
            return .{
                .bytes = self.pending_line.items,
                .wire_bytes = self.pending_line.items.len + 1,
            };
        }
    }
};

pub fn consumeSse(
    alloc: Allocator,
    reader: anytype,
    events: *stream_provider.EventSink,
    content_fn: *const fn (*anyopaque, []const u8) void,
    tool_start_fn: *const fn (*anyopaque, []const u8, []const u8, ?[]const u8) void,
    reasoning_fn: *const fn (*anyopaque, []const u8) void,
    tool_input_fn: *const fn (*anyopaque, []const u8) void,
    cancel_flag: *std.atomic.Value(bool),
    content_capture_limit: ?usize,
) !types.ModelCompletion {
    var sse: SseReader = .{};
    defer sse.deinit(alloc);
    var reducer = responses_protocol.Reducer.init(alloc);
    defer reducer.deinit(alloc);
    const limits = responses_protocol.StreamLimits{
        .aggregate_bytes = max_sse_aggregate_bytes,
        .count_json_bytes = false,
        .events = max_sse_events,
        .tool_calls = max_tool_calls,
        .tool_identity_bytes = max_tool_identity_bytes,
        .tool_arguments_bytes = max_tool_arguments_bytes,
        .provider_state_bytes = max_provider_state_bytes,
    };
    const callbacks = responses_protocol.StreamCallbacks{
        .context = events,
        .on_content = content_fn,
        .on_tool_start = tool_start_fn,
        .on_reasoning = reasoning_fn,
        .on_tool_input = tool_input_fn,
    };
    while (true) {
        if (cancel_flag.load(.seq_cst)) return error.Cancelled;
        const data = (try sse.next(alloc, reader)) orelse break;
        defer sse.release();
        const decoded = x1_agent_profile.decodeSseData(alloc, data);
        switch (decoded) {
            .not_x1 => {},
            .capability_ack => |ack| {
                try x1_agent_profile.negotiate(ack);
                continue;
            },
            .ignore, .recognized_unmapped => {
                if (x1_agent_profile.mapToHarnessEvent(decoded)) |event| {
                    switch (event) {
                        .reasoning_delta => {},
                        else => events.emit(event),
                    }
                }
                continue;
            },
        }
        const terminal = reducer.applyJson(
            alloc,
            data,
            callbacks,
            cancel_flag,
            content_capture_limit,
            limits,
        ) catch |err| switch (err) {
            error.InvalidEvent => continue,
            else => return err,
        };
        if (terminal) break;
    }
    return reducer.finish(alloc, cancel_flag, limits);
}

// ---------------------------------------------------------------------------
// Account status: plan, limits, and dollar credits for the signed-in X1 user.
// Fetched from the LayerX1 account endpoint with the OAuth access token and
// the account id header, mirroring the inference request's auth shape.
// ---------------------------------------------------------------------------

const account_endpoint = "https://api.layerx1.com/v1/me";
const e2e_account_url_env = "X1_E2E_LAYERX1_ACCOUNT_URL";
const max_account_body_bytes: usize = 256 * 1024;
const account_fetch_timeout_ms: i64 = 30_000;

pub const credits_provider = gateway_provider.CreditsProvider{
    .fetch_fn = fetchAccountCredits,
};

const AccountFetchResponse = struct {
    status: std.http.Status,
    body: []u8,

    pub fn deinit(self: *AccountFetchResponse, alloc: Allocator) void {
        secret.zeroAndFree(alloc, self.body);
        self.* = undefined;
    }
};

const AccountFetchOperation = struct {
    alloc: Allocator,
    url: []const u8,
    credential: []const u8,
    account_id: []const u8,

    pub fn run(self: *@This()) !AccountFetchResponse {
        var client: std.http.Client = .{ .allocator = self.alloc, .io = io_mod.getIo() };
        defer client.deinit();
        const auth_header = try std.fmt.allocPrint(self.alloc, "Bearer {s}", .{self.credential});
        defer secret.zeroAndFree(self.alloc, auth_header);
        const body_buffer = try self.alloc.alloc(u8, max_account_body_bytes + 1);
        defer secret.zeroAndFree(self.alloc, body_buffer);
        var response_writer = std.Io.Writer.fixed(body_buffer);
        var extra_headers_buffer: [2]std.http.Header = undefined;
        extra_headers_buffer[0] = .{ .name = "accept", .value = "application/json" };
        extra_headers_buffer[1] = .{ .name = "x-account-id", .value = self.account_id };
        const result = client.fetch(.{
            .location = .{ .url = self.url },
            .method = .GET,
            .headers = .{
                .authorization = .{ .override = auth_header },
                .user_agent = .{ .override = gateway_client.user_agent },
                .accept_encoding = .omit,
            },
            .extra_headers = extra_headers_buffer[0..2],
            .response_writer = &response_writer,
            .redirect_behavior = .unhandled,
        }) catch return error.LayerX1AccountFetchFailed;
        const body = response_writer.buffered();
        if (body.len > max_account_body_bytes) return error.LayerX1AccountFetchFailed;
        return .{
            .status = result.status,
            .body = try self.alloc.dupe(u8, body),
        };
    }
};

fn accountErrorSnapshot(alloc: Allocator, message: []const u8) output_contracts.CreditsSnapshot {
    return .{
        .err_message = alloc.dupe(u8, message) catch null,
    };
}

fn accountUrl(alloc: Allocator) ![]const u8 {
    const base = io_mod.getenv(e2e_account_url_env) orelse account_endpoint;
    if (io_mod.getenv(e2e_account_url_env) != null and !gateway_client.isLoopbackHttpUrl(base)) {
        return error.InvalidE2ELayerX1AccountEndpoint;
    }
    return alloc.dupe(u8, base);
}

fn fetchAccountCredits(
    _: ?*anyopaque,
    alloc: Allocator,
    input: gateway_provider.CreditsLookupInput,
) output_contracts.CreditsSnapshot {
    if (input.credential_source != .layerx1_subscription) {
        return accountErrorSnapshot(alloc, "Account status is unavailable without an X1 subscription login.");
    }
    const credential = input.credential orelse
        return accountErrorSnapshot(alloc, "Account status is unavailable without an X1 subscription login.");
    const account_id = if (input.account_id) |value|
        alloc.dupe(u8, value) catch return .{ .err_message = null }
    else
        layerx1_session.loadAccountId(alloc) catch |err| switch (err) {
            error.OutOfMemory => return .{ .err_message = null },
            else => return accountErrorSnapshot(alloc, "Account status is unavailable without an X1 subscription login."),
        } orelse return accountErrorSnapshot(alloc, "Account status is unavailable without an X1 subscription login.");
    defer alloc.free(account_id);
    if (!layerx1_session.validAccountId(account_id)) {
        return accountErrorSnapshot(alloc, "Account status is unavailable: the stored X1 account id is invalid.");
    }

    const request_url = accountUrl(alloc) catch {
        return accountErrorSnapshot(alloc, "failed to fetch X1 account status");
    };
    defer alloc.free(request_url);

    var fallback_cancel = std.atomic.Value(bool).init(false);
    const deadline = std.Io.Clock.Timestamp.fromNow(io_mod.getIo(), .{
        .clock = .awake,
        .raw = .fromMilliseconds(account_fetch_timeout_ms),
    });
    var operation = AccountFetchOperation{
        .alloc = alloc,
        .url = request_url,
        .credential = credential,
        .account_id = account_id,
    };
    var response = gateway_client.runBoundedHttpOperation(
        AccountFetchResponse,
        alloc,
        &fallback_cancel,
        deadline,
        &operation,
    ) catch {
        return accountErrorSnapshot(alloc, "failed to fetch X1 account status");
    };
    defer response.deinit(alloc);
    if (response.status != .ok) {
        return accountHttpErrorSnapshot(alloc, response.status, response.body);
    }
    return parseAccountSnapshot(alloc, response.body);
}

fn accountHttpErrorSnapshot(
    alloc: Allocator,
    status: std.http.Status,
    body: []const u8,
) output_contracts.CreditsSnapshot {
    const message = gateway_error_format.formatHttpErrorMessage(alloc, status, body) catch {
        return accountErrorSnapshot(alloc, "X1 account status request failed");
    };
    return .{ .err_message = message };
}

fn parseAccountSnapshot(alloc: Allocator, body: []const u8) output_contracts.CreditsSnapshot {
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch {
        return accountErrorSnapshot(alloc, "X1 account status response was malformed");
    };
    defer parsed.deinit();
    if (parsed.value != .object) {
        return accountErrorSnapshot(alloc, "X1 account status response was malformed");
    }
    const object = parsed.value.object;

    var snapshot = output_contracts.CreditsSnapshot{};
    if (object.get("plan")) |plan| {
        if (plan == .string and plan.string.len > 0) {
            snapshot.plan = alloc.dupe(u8, plan.string) catch null;
        }
    }
    if (object.get("balance_usd")) |balance| {
        if (formatDollars(alloc, balance)) |text| snapshot.balance = text;
    } else if (object.get("credits")) |credits| {
        switch (credits) {
            .object => |credits_obj| {
                if (credits_obj.get("balance")) |balance| {
                    if (formatDollars(alloc, balance)) |text| snapshot.balance = text;
                }
                if (credits_obj.get("used")) |used| {
                    if (formatDollars(alloc, used)) |text| snapshot.used = text;
                }
            },
            else => {
                // A bare numeric/string credits value is the balance.
                if (formatDollars(alloc, credits)) |text| snapshot.balance = text;
            },
        }
    }
    if (object.get("month")) |month| {
        if (month == .object) {
            if (month.object.get("value_usd")) |used| {
                if (formatDollars(alloc, used)) |text| snapshot.used = text;
            }
        }
    }
    return snapshot;
}

fn formatDollars(alloc: Allocator, value: std.json.Value) ?[]const u8 {
    switch (value) {
        .string => |s| {
            // The parsed JSON tree is released before the snapshot escapes,
            // so string values must be copied, never borrowed.
            if (s.len == 0) return null;
            const owned = alloc.dupe(u8, s) catch return null;
            if (owned[0] == '$') return owned;
            const prefixed = std.fmt.allocPrint(alloc, "${s}", .{owned}) catch {
                alloc.free(owned);
                return null;
            };
            alloc.free(owned);
            return prefixed;
        },
        .integer => |i| return std.fmt.allocPrint(alloc, "${d}", .{i}) catch null,
        .float => |f| return std.fmt.allocPrint(alloc, "${d:.2}", .{f}) catch null,
        else => return null,
    }
}

test "X1 account snapshot parses plan and dollar credits" {
    const alloc = std.testing.allocator;
    const body =
        \\{"customer_id":"cust_1","email":"sam@example.com","plan":"pro","balance_usd":42.5,"month":{"requests":12,"tokens":3456,"value_usd":7.25}}
    ;
    var snapshot = parseAccountSnapshot(alloc, body);
    defer snapshot.deinit(alloc);
    try std.testing.expect(snapshot.err_message == null);
    try std.testing.expectEqualStrings("pro", snapshot.plan.?);
    try std.testing.expectEqualStrings("$42.50", snapshot.balance.?);
    try std.testing.expectEqualStrings("$7.25", snapshot.used.?);
}

test "X1 account snapshot accepts a bare credits balance and prefixed dollars" {
    const alloc = std.testing.allocator;
    const body =
        \\{"plan":"free","credits":"$3.00"}
    ;
    var snapshot = parseAccountSnapshot(alloc, body);
    defer snapshot.deinit(alloc);
    try std.testing.expect(snapshot.err_message == null);
    try std.testing.expectEqualStrings("free", snapshot.plan.?);
    try std.testing.expectEqualStrings("$3.00", snapshot.balance.?);
}

test "X1 account snapshot reports malformed responses" {
    const alloc = std.testing.allocator;
    var snapshot = parseAccountSnapshot(alloc, "not json");
    defer snapshot.deinit(alloc);
    try std.testing.expect(snapshot.err_message != null);
}

test "X1 account HTTP denial keeps structured gateway error details" {
    const alloc = std.testing.allocator;
    const body =
        \\{"error":{"code":"credit_card_required","message":"Buy credits to continue."}}
    ;
    var snapshot = accountHttpErrorSnapshot(alloc, .forbidden, body);
    defer snapshot.deinit(alloc);
    try std.testing.expectEqualStrings(
        "API access denied · HTTP 403 · credit_card_required: Buy credits to continue.",
        snapshot.err_message.?,
    );
}

test "consumeSse emits content through EventSink" {
    const alloc = std.testing.allocator;
    const payload =
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n" ++
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_sdk\",\"status\":\"completed\"}}\n\n";
    var reader = std.Io.Reader.fixed(payload);
    const Capture = struct {
        hello: usize = 0,

        fn emit(raw: *anyopaque, event: stream_provider.Event) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            switch (event) {
                .content_delta => |chunk| if (std.mem.eql(u8, chunk, "hello")) {
                    self.hello += 1;
                },
                else => {},
            }
        }
    };
    var capture: Capture = .{};
    var events = stream_provider.EventSink{
        .context = @ptrCast(&capture),
        .emit_fn = Capture.emit,
    };
    var cancel = std.atomic.Value(bool).init(false);
    const completion = try consumeSse(
        alloc,
        &reader,
        &events,
        EventBridge.content,
        EventBridge.toolStart,
        EventBridge.reasoning,
        EventBridge.toolInput,
        &cancel,
        null,
    );
    defer if (completion.content) |content| alloc.free(content);
    defer if (completion.generation_id) |id| alloc.free(id);
    defer if (completion.provider_state_json) |state| alloc.free(state);
    try std.testing.expectEqual(@as(usize, 1), capture.hello);
    try std.testing.expectEqualStrings("hello", completion.content orelse "");
    try std.testing.expectEqualStrings("resp_sdk", completion.generation_id orelse "");
}

fn isStandardResponsesKey(key: []const u8) bool {
    const allowed = [_][]const u8{
        "model",
        "store",
        "stream",
        "instructions",
        "input",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "include",
        "text",
        "reasoning",
        "max_output_tokens",
    };
    for (allowed) |name| {
        if (std.mem.eql(u8, name, key)) return true;
    }
    return false;
}

fn headerValue(headers: []const std.http.Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name)) return header.value;
    }
    return null;
}

const StreamCapture = struct {
    log: std.Io.Writer.Allocating,
    reasoning: usize = 0,

    fn emit(raw: *anyopaque, event: stream_provider.Event) void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        switch (event) {
            .content_delta => |chunk| self.log.writer.print("C:{s}\n", .{chunk}) catch {},
            .reasoning_delta => |chunk| {
                self.reasoning += 1;
                self.log.writer.print("R:{s}\n", .{chunk}) catch {};
            },
            .tool_input_delta => |chunk| self.log.writer.print("I:{s}\n", .{chunk}) catch {},
            .tool_started => |tool| self.log.writer.print("T:{s}\n", .{tool.id}) catch {},
        }
    }
};

fn consumeLogged(alloc: Allocator, payload: []const u8) !struct {
    log: []u8,
    reasoning: usize,
    content: []const u8,
    generation_id: []const u8,
} {
    var reader = std.Io.Reader.fixed(payload);
    var capture = StreamCapture{ .log = .init(alloc) };
    errdefer capture.log.deinit();
    var events = stream_provider.EventSink{
        .context = @ptrCast(&capture),
        .emit_fn = StreamCapture.emit,
    };
    var cancel = std.atomic.Value(bool).init(false);
    const completion = try consumeSse(
        alloc,
        &reader,
        &events,
        EventBridge.content,
        EventBridge.toolStart,
        EventBridge.reasoning,
        EventBridge.toolInput,
        &cancel,
        null,
    );
    defer if (completion.content) |content| alloc.free(content);
    defer if (completion.generation_id) |id| alloc.free(id);
    defer if (completion.provider_state_json) |state| alloc.free(state);
    const content = try alloc.dupe(u8, completion.content orelse "");
    errdefer alloc.free(content);
    const generation_id = try alloc.dupe(u8, completion.generation_id orelse "");
    errdefer alloc.free(generation_id);
    return .{
        .log = try capture.log.toOwnedSlice(),
        .reasoning = capture.reasoning,
        .content = content,
        .generation_id = generation_id,
    };
}

test "X1 Agent Profile Responses JSON body stays schema-compatible without x1 extensions" {
    const alloc = std.testing.allocator;
    const payload = try buildRequest(alloc, .{
        .model = "lx1-test",
        .messages = &.{.{ .role = .user, .content = "hello" }},
        .tool_choice = .auto,
        .provider_options = .{},
    });
    defer alloc.free(payload);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
    try std.testing.expect(parsed.value.object.get("x1") == null);
    var iterator = parsed.value.object.iterator();
    while (iterator.next()) |entry| {
        const key = entry.key_ptr.*;
        try std.testing.expect(!std.mem.startsWith(u8, key, "x1"));
        try std.testing.expect(isStandardResponsesKey(key));
    }
    try std.testing.expect(parsed.value.object.get("model") != null);
    try std.testing.expect(parsed.value.object.get("stream") != null);
    try std.testing.expect(parsed.value.object.get("input") != null);
    try std.testing.expect(parsed.value.object.get("tool_choice") != null);
}

test "X1 Agent Profile native inference headers match the typed profile and omit idempotency" {
    var buf: [max_inference_extra_headers]std.http.Header = undefined;
    const headers = try inferenceExtraHeaders(&buf, "acct_1", "session_1", .{});
    const profile = try x1_agent_profile.requestHeaders(.{});
    for (profile.slice()) |expected| {
        try std.testing.expectEqualStrings(expected.value, headerValue(headers, expected.name) orelse return error.TestExpectedEqual);
    }
    try std.testing.expect(headerValue(headers, x1_agent_profile.header_idempotency_key) == null);
    try std.testing.expectEqualStrings("1", headerValue(headers, x1_agent_profile.header_agent_protocol).?);
}

test "X1 Agent Profile ordinary Responses streams keep the same harness events" {
    const alloc = std.testing.allocator;
    const standard =
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n" ++
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_sdk\",\"status\":\"completed\"}}\n\n";
    const with_x1 =
        "data: {\"type\":\"x1.unknown.foo\",\"route\":\"secret\"}\n" ++
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n" ++
        "data: {\"type\":\"x1.reasoning.delta\",\"delta\":\"HIDDEN_CHAIN_OF_THOUGHT\"}\n" ++
        "data: {\"type\":\"x1.usage\",\"input_tokens\":9,\"cache_read_tokens\":3}\n" ++
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_sdk\",\"status\":\"completed\"}}\n\n";
    const baseline = try consumeLogged(alloc, standard);
    defer alloc.free(baseline.log);
    defer alloc.free(@constCast(baseline.content));
    defer alloc.free(@constCast(baseline.generation_id));
    const mixed = try consumeLogged(alloc, with_x1);
    defer alloc.free(mixed.log);
    defer alloc.free(@constCast(mixed.content));
    defer alloc.free(@constCast(mixed.generation_id));
    try std.testing.expectEqualStrings(baseline.log, mixed.log);
    try std.testing.expectEqualStrings("C:hello\n", baseline.log);
    try std.testing.expectEqual(@as(usize, 0), baseline.reasoning);
    try std.testing.expectEqual(@as(usize, 0), mixed.reasoning);
    try std.testing.expectEqualStrings("hello", mixed.content);
    try std.testing.expect(std.mem.find(u8, mixed.log, "HIDDEN_CHAIN_OF_THOUGHT") == null);
}

test "X1 Agent Profile capability ack without required feature fails closed" {
    const alloc = std.testing.allocator;
    const payload =
        "data: {\"type\":\"x1.capability.ack\",\"capabilities\":\"parallel-tool-calls\"}\n" ++
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n" ++
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_sdk\",\"status\":\"completed\"}}\n\n";
    var reader = std.Io.Reader.fixed(payload);
    const Capture = struct {
        fn emit(_: *anyopaque, _: stream_provider.Event) void {}
    };
    var capture: Capture = .{};
    var events = stream_provider.EventSink{
        .context = @ptrCast(&capture),
        .emit_fn = Capture.emit,
    };
    var cancel = std.atomic.Value(bool).init(false);
    try std.testing.expectError(error.X1RequiredCapabilityMissing, consumeSse(
        alloc,
        &reader,
        &events,
        EventBridge.content,
        EventBridge.toolStart,
        EventBridge.reasoning,
        EventBridge.toolInput,
        &cancel,
        null,
    ));
}

test "X1 Agent Profile acknowledged required capabilities keep standard Responses" {
    const alloc = std.testing.allocator;
    const payload =
        "data: {\"type\":\"x1.capability.ack\",\"capabilities\":\"responses-sse,parallel-tool-calls\"}\n" ++
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n" ++
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_sdk\",\"status\":\"completed\"}}\n\n";
    const result = try consumeLogged(alloc, payload);
    defer alloc.free(result.log);
    defer alloc.free(@constCast(result.content));
    defer alloc.free(@constCast(result.generation_id));
    try std.testing.expectEqualStrings("C:hello\n", result.log);
    try std.testing.expectEqualStrings("hello", result.content);
}
