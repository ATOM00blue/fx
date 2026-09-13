//! Harness-owned X1 Agent Profile.
//!
//! LayerX1 inference keeps the standard OpenAI Responses JSON body and SSE
//! `data:` framing. This module adds versioned, namespaced, opt-in HTTP headers
//! and a decoder contract for future `x1.*` stream events. The LayerX1 server
//! is unchanged; absent acknowledgement degrades to pure Responses.
//!
//! Idempotency is typed here but not sent. `stream_provider.ModelRequest` has
//! `session_id` (multi-turn) and `trace_ctx.turn_id` (process-local telemetry,
//! WASI-constant 1). Neither is a durable per-turn key. Future wiring: add a
//! dedicated `ModelRequest` field once the agent runtime owns a stable per-turn
//! identity, then return it from `identityForRequest`. Do not derive a key from
//! model, prompt, session id, retry count, or `TraceContext.turn_id`.

const std = @import("std");
const build_options = @import("build_options");
const stream_provider = @import("../core/agent/stream_provider.zig");

const Allocator = std.mem.Allocator;

pub const protocol_version: u8 = 1;
pub const protocol_version_text = "1";
pub const client_name = "x1";
pub const client_identity = client_name ++ "/" ++ build_options.app_version;
pub const namespaced_event_prefix = "x1.";

pub const header_agent_protocol = "x-layerx1-agent-protocol";
pub const header_client = "x-layerx1-client";
pub const header_client_capabilities = "x-layerx1-client-capabilities";
pub const header_idempotency_key = "idempotency-key";

pub const max_protocol_bytes: usize = 8;
pub const max_client_identity_bytes: usize = 64;
pub const max_capabilities_bytes: usize = 256;
pub const max_capability_token_bytes: usize = 64;
pub const max_capability_tokens: usize = 16;
pub const max_idempotency_key_bytes: usize = 128;
pub const max_event_type_bytes: usize = 64;
pub const max_request_headers: usize = 4;

pub const FeatureClass = enum { required, optional };

/// Deterministic advertisement order is the enum declaration order, which is
/// sorted by wire name.
pub const Feature = enum {
    encrypted_reasoning_state,
    parallel_tool_calls,
    responses_sse,

    pub fn wireName(self: Feature) []const u8 {
        return switch (self) {
            .encrypted_reasoning_state => "encrypted-reasoning-state",
            .parallel_tool_calls => "parallel-tool-calls",
            .responses_sse => "responses-sse",
        };
    }

    pub fn class(self: Feature) FeatureClass {
        return switch (self) {
            .responses_sse => .required,
            .encrypted_reasoning_state, .parallel_tool_calls => .optional,
        };
    }

    pub fn parse(name: []const u8) ?Feature {
        inline for (std.meta.tags(Feature)) |feature| {
            if (std.mem.eql(u8, feature.wireName(), name)) return feature;
        }
        return null;
    }
};

pub const advertised_capabilities = "encrypted-reasoning-state,parallel-tool-calls,responses-sse";

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const HeaderSet = struct {
    items: [max_request_headers]Header = undefined,
    len: usize = 0,

    pub fn slice(self: *const HeaderSet) []const Header {
        return self.items[0..self.len];
    }

    fn append(self: *HeaderSet, header: Header) void {
        std.debug.assert(self.len < self.items.len);
        self.items[self.len] = header;
        self.len += 1;
    }
};

/// Optional per-request profile identity. `idempotency_key` stays null until a
/// real durable per-turn identity exists on the runtime request.
pub const RequestIdentity = struct {
    idempotency_key: ?[]const u8 = null,
};

pub const Acknowledgement = struct {
    features: std.EnumSet(Feature) = .empty,

    pub fn contains(self: Acknowledgement, feature: Feature) bool {
        return self.features.contains(feature);
    }
};

pub const RecognizedEvent = enum {
    capability_ack,
    reasoning_delta,
    usage,
};

pub const DecodeResult = union(enum) {
    not_x1,
    ignore,
    recognized_unmapped: RecognizedEvent,
    capability_ack: Acknowledgement,
};

comptime {
    if (!isVisibleAsciiToken(protocol_version_text, max_protocol_bytes))
        @compileError("X1 protocol version is not a valid header token");
    if (!isVisibleAsciiToken(client_identity, max_client_identity_bytes))
        @compileError("X1 client identity is not a valid header token");
    if (!isValidCapabilityDeclaration(advertised_capabilities))
        @compileError("X1 capability advertisement is not a valid declaration");
}

pub fn identityForRequest(request: stream_provider.ModelRequest) RequestIdentity {
    // Future wiring point: return `{ .idempotency_key = request.turn_idempotency_key }`
    // once ModelRequest carries a durable per-turn identity owned by the agent
    // runtime. session_id, model, prompt, retry_count, and trace_ctx.turn_id are
    // not that identity.
    _ = request;
    return .{};
}

pub fn requestHeaders(identity: RequestIdentity) !HeaderSet {
    var headers: HeaderSet = .{};
    try validateHeaderValue(protocol_version_text, max_protocol_bytes);
    try validateHeaderValue(client_identity, max_client_identity_bytes);
    try validateHeaderValue(advertised_capabilities, max_capabilities_bytes);
    headers.append(.{ .name = header_agent_protocol, .value = protocol_version_text });
    headers.append(.{ .name = header_client, .value = client_identity });
    headers.append(.{ .name = header_client_capabilities, .value = advertised_capabilities });
    if (identity.idempotency_key) |key| {
        try validateIdempotencyKey(key);
        headers.append(.{ .name = header_idempotency_key, .value = key });
    }
    return headers;
}

pub fn isProfileHeaderName(name: []const u8) bool {
    return std.mem.eql(u8, name, header_agent_protocol) or
        std.mem.eql(u8, name, header_client) or
        std.mem.eql(u8, name, header_client_capabilities) or
        std.mem.eql(u8, name, header_idempotency_key);
}

pub fn validateHeaderValue(value: []const u8, max_len: usize) !void {
    if (!isVisibleAsciiToken(value, max_len)) return error.InvalidX1HeaderValue;
}

pub fn validateIdempotencyKey(value: []const u8) !void {
    try validateHeaderValue(value, max_idempotency_key_bytes);
    for (value) |byte| {
        const allowed = std.ascii.isAlphanumeric(byte) or
            byte == '.' or byte == '_' or byte == '-' or byte == ':';
        if (!allowed) return error.InvalidX1HeaderValue;
    }
}

/// Fail closed only when the server actually acknowledged the profile and a
/// required advertised feature is missing from that acknowledgement. No
/// acknowledgement means standard Responses and must not fail.
pub fn negotiate(ack: ?Acknowledgement) !void {
    const acknowledged = ack orelse return;
    inline for (std.meta.tags(Feature)) |feature| {
        if (feature.class() == .required and !acknowledged.contains(feature)) {
            return error.X1RequiredCapabilityMissing;
        }
    }
}

pub fn advertisedFeatures() []const Feature {
    return std.meta.tags(Feature);
}

pub fn requiredFeatures() []const Feature {
    return &.{.responses_sse};
}

pub fn decodeSseData(alloc: Allocator, json_text: []const u8) DecodeResult {
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, json_text, .{}) catch
        return .not_x1;
    defer parsed.deinit();
    if (parsed.value != .object) return .not_x1;
    const event_type = stringField(parsed.value.object, "type") orelse return .not_x1;
    if (!std.mem.startsWith(u8, event_type, namespaced_event_prefix)) return .not_x1;
    if (!isValidNamespacedEventType(event_type)) return .ignore;

    if (std.mem.eql(u8, event_type, "x1.capability.ack")) {
        const ack = parseAcknowledgement(parsed.value.object) orelse return .ignore;
        return .{ .capability_ack = ack };
    }
    if (std.mem.eql(u8, event_type, "x1.reasoning.delta")) {
        return .{ .recognized_unmapped = .reasoning_delta };
    }
    if (std.mem.eql(u8, event_type, "x1.usage")) {
        return .{ .recognized_unmapped = .usage };
    }
    return .ignore;
}

/// Namespaced events map into `stream_provider.Event` only when a truthful
/// existing variant exists. Hidden reasoning, usage, routing, billing, and
/// cache facts have no such variant and must not be invented.
pub fn mapToHarnessEvent(decoded: DecodeResult) ?stream_provider.Event {
    return switch (decoded) {
        .not_x1, .ignore, .recognized_unmapped, .capability_ack => null,
    };
}

fn parseAcknowledgement(object: std.json.ObjectMap) ?Acknowledgement {
    const value = object.get("capabilities") orelse return Acknowledgement{};
    var ack = Acknowledgement{};
    switch (value) {
        .string => |text| {
            if (!isValidCapabilityDeclaration(text)) return null;
            var it = std.mem.splitScalar(u8, text, ',');
            while (it.next()) |token| {
                if (Feature.parse(token)) |feature| ack.features.insert(feature);
            }
            return ack;
        },
        .array => |items| {
            if (items.items.len == 0) return ack;
            if (items.items.len > max_capability_tokens) return null;
            for (items.items) |item| {
                if (item != .string) return null;
                if (!isValidCapabilityToken(item.string)) return null;
                if (Feature.parse(item.string)) |feature| ack.features.insert(feature);
            }
            return ack;
        },
        else => return null,
    }
}

fn stringField(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    if (value != .string) return null;
    return value.string;
}

fn isVisibleAsciiToken(value: []const u8, max_len: usize) bool {
    if (value.len == 0 or value.len > max_len) return false;
    for (value) |byte| {
        if (byte <= 0x20 or byte >= 0x7f) return false;
    }
    return true;
}

fn isValidCapabilityToken(token: []const u8) bool {
    if (token.len == 0 or token.len > max_capability_token_bytes) return false;
    for (token) |byte| {
        const allowed = (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '-';
        if (!allowed) return false;
    }
    return true;
}

fn isValidCapabilityDeclaration(value: []const u8) bool {
    if (!isVisibleAsciiToken(value, max_capabilities_bytes)) return false;
    var it = std.mem.splitScalar(u8, value, ',');
    var count: usize = 0;
    while (it.next()) |token| {
        if (!isValidCapabilityToken(token)) return false;
        count += 1;
        if (count > max_capability_tokens) return false;
    }
    return count > 0;
}

fn isValidNamespacedEventType(event_type: []const u8) bool {
    if (event_type.len <= namespaced_event_prefix.len or event_type.len > max_event_type_bytes)
        return false;
    if (!std.mem.startsWith(u8, event_type, namespaced_event_prefix)) return false;
    const rest = event_type[namespaced_event_prefix.len..];
    if (rest[0] == '.' or rest[rest.len - 1] == '.') return false;
    for (rest) |byte| {
        const allowed = (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '.' or byte == '_' or byte == '-';
        if (!allowed) return false;
    }
    return true;
}

fn expectHeader(headers: HeaderSet, name: []const u8, value: []const u8) !void {
    for (headers.slice()) |header| {
        if (std.mem.eql(u8, header.name, name)) {
            try std.testing.expectEqualStrings(value, header.value);
            return;
        }
    }
    return error.TestExpectedEqual;
}

fn hasHeader(headers: HeaderSet, name: []const u8) bool {
    for (headers.slice()) |header| {
        if (std.mem.eql(u8, header.name, name)) return true;
    }
    return false;
}

test "X1 Agent Profile advertises deterministic bounded capabilities" {
    try std.testing.expectEqualStrings(
        "encrypted-reasoning-state,parallel-tool-calls,responses-sse",
        advertised_capabilities,
    );
    var expected: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer expected.deinit();
    for (std.meta.tags(Feature), 0..) |feature, index| {
        if (index > 0) try expected.writer.writeByte(',');
        try expected.writer.writeAll(feature.wireName());
    }
    try std.testing.expectEqualStrings(expected.written(), advertised_capabilities);
    try std.testing.expect(isValidCapabilityDeclaration(advertised_capabilities));
    try std.testing.expectEqual(FeatureClass.required, Feature.responses_sse.class());
    try std.testing.expectEqual(FeatureClass.optional, Feature.encrypted_reasoning_state.class());
    try std.testing.expectEqual(FeatureClass.optional, Feature.parallel_tool_calls.class());
}

test "X1 Agent Profile headers include versioned client identity and omit idempotency" {
    const headers = try requestHeaders(.{});
    try std.testing.expectEqual(@as(usize, 3), headers.len);
    try expectHeader(headers, header_agent_protocol, protocol_version_text);
    try expectHeader(headers, header_client, client_identity);
    try expectHeader(headers, header_client_capabilities, advertised_capabilities);
    try std.testing.expect(std.mem.startsWith(u8, client_identity, "x1/"));
    try std.testing.expect(!hasHeader(headers, header_idempotency_key));
}

test "X1 Agent Profile does not send an idempotency key without a real turn identity" {
    const Unused = struct {
        fn emit(_: *anyopaque, _: stream_provider.Event) void {}
    };
    var delivery = stream_provider.DeliveryCertainty.init();
    var attempt_evidence: stream_provider.AttemptEvidence = .{};
    var cancel = std.atomic.Value(bool).init(false);
    var ctx: u8 = 0;
    const request = stream_provider.ModelRequest{
        .credential = .{ .secret = "unused" },
        .session_id = "session-not-a-turn",
        .model = "lx1-test",
        .retry_count = 2,
        .messages = &.{.{ .role = .user, .content = "prompt-not-a-turn-id" }},
        .tool_choice = .auto,
        .provider_options = .{},
        .trace_ctx = .{ .turn_id = 7, .step_id = 3 },
        .content_capture_limit = null,
        .delivery = &delivery,
        .attempt_evidence = &attempt_evidence,
        .events = .{ .context = &ctx, .emit_fn = Unused.emit },
        .cancel_flag = &cancel,
    };
    const headers = try requestHeaders(identityForRequest(request));
    try std.testing.expect(!hasHeader(headers, header_idempotency_key));
}

test "X1 Agent Profile validation rejects injection, control bytes, and oversize values" {
    try std.testing.expectError(error.InvalidX1HeaderValue, validateHeaderValue("x1/1\r\nX-Evil: 1", max_client_identity_bytes));
    try std.testing.expectError(error.InvalidX1HeaderValue, validateHeaderValue("x1/1\n", max_client_identity_bytes));
    try std.testing.expectError(error.InvalidX1HeaderValue, validateHeaderValue("x1/1\x00", max_client_identity_bytes));
    try std.testing.expectError(error.InvalidX1HeaderValue, validateHeaderValue("x1/1\t", max_client_identity_bytes));
    try std.testing.expectError(error.InvalidX1HeaderValue, validateHeaderValue("", max_client_identity_bytes));
    const oversize = "x" ** (max_client_identity_bytes + 1);
    try std.testing.expectError(error.InvalidX1HeaderValue, validateHeaderValue(oversize, max_client_identity_bytes));
    try std.testing.expectError(
        error.InvalidX1HeaderValue,
        requestHeaders(.{ .idempotency_key = "turn\ninject" }),
    );
    try std.testing.expectError(
        error.InvalidX1HeaderValue,
        requestHeaders(.{ .idempotency_key = "turn key" }),
    );
    const oversize_key = "a" ** (max_idempotency_key_bytes + 1);
    try std.testing.expectError(
        error.InvalidX1HeaderValue,
        requestHeaders(.{ .idempotency_key = oversize_key }),
    );
    const accepted = try requestHeaders(.{ .idempotency_key = "turn:01_abc" });
    try expectHeader(accepted, header_idempotency_key, "turn:01_abc");
}

test "X1 Agent Profile negotiation fails closed only after a server acknowledgement" {
    try negotiate(null);
    var missing = Acknowledgement{};
    missing.features.insert(.parallel_tool_calls);
    try std.testing.expectError(error.X1RequiredCapabilityMissing, negotiate(missing));
    var complete = Acknowledgement{};
    complete.features.insert(.responses_sse);
    try negotiate(complete);
}

test "X1 Agent Profile ignores unknown x1 events and does not map hidden reasoning" {
    const alloc = std.testing.allocator;
    try std.testing.expect(decodeSseData(alloc, "not-json") == .not_x1);
    try std.testing.expect(
        decodeSseData(alloc, "{\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}") == .not_x1,
    );
    try std.testing.expect(decodeSseData(alloc, "{\"type\":\"x1.unknown.foo\"}") == .ignore);
    try std.testing.expect(decodeSseData(alloc, "{\"type\":\"x1.FOO\"}") == .ignore);
    try std.testing.expect(decodeSseData(alloc, "{\"type\":\"x1.\"}") == .ignore);
    try std.testing.expect(decodeSseData(alloc, "{\"type\":\"x1.reasoning.delta\\ninject\"}") == .ignore);

    const reasoning = decodeSseData(
        alloc,
        "{\"type\":\"x1.reasoning.delta\",\"delta\":\"HIDDEN_CHAIN_OF_THOUGHT\"}",
    );
    try std.testing.expectEqual(RecognizedEvent.reasoning_delta, reasoning.recognized_unmapped);
    try std.testing.expect(mapToHarnessEvent(reasoning) == null);

    const usage = decodeSseData(alloc, "{\"type\":\"x1.usage\",\"input_tokens\":9}");
    try std.testing.expectEqual(RecognizedEvent.usage, usage.recognized_unmapped);
    try std.testing.expect(mapToHarnessEvent(usage) == null);

    const ack = decodeSseData(alloc, "{\"type\":\"x1.capability.ack\",\"capabilities\":\"responses-sse\"}");
    try std.testing.expect(ack == .capability_ack);
    try std.testing.expect(ack.capability_ack.contains(.responses_sse));
    try std.testing.expect(mapToHarnessEvent(ack) == null);

    const invalid_ack = decodeSseData(
        alloc,
        "{\"type\":\"x1.capability.ack\",\"capabilities\":\"responses-sse\\nX-Evil\"}",
    );
    try std.testing.expect(invalid_ack == .ignore);
}
