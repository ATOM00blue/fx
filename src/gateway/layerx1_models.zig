const std = @import("std");
const credentials = @import("../core/auth/credentials.zig");
const layerx1_session = @import("../core/auth/layerx1_session.zig");
const model_catalog = @import("../core/gateway/model_catalog.zig");
const gateway_provider = @import("../core/gateway/gateway_provider.zig");
const io_mod = @import("../core/shared/io.zig");
const secret = @import("../core/auth/secret.zig");
const types = @import("../core/shared/types.zig");
const gateway_client = @import("http_runtime.zig");

const max_catalog_models: usize = 256;
const max_model_id_bytes: usize = 256;
const max_catalog_bytes: usize = 1024 * 1024;
const fetch_timeout_ms: i64 = 30_000;
const default_models_endpoint = "https://api.layerx1.com/v1/models";
const e2e_models_endpoint_env = "X1_E2E_LAYERX1_MODELS_URL";

pub const model_catalog_provider = model_catalog.Provider{
    .fetch_fn = fetchCatalogForProvider,
};

pub const cli_model_catalog_provider = gateway_provider.CliModelCatalogProvider{
    .fetch_fn = fetchCliModelCatalog,
};

fn fetchCliModelCatalog(
    _: ?*anyopaque,
    alloc: std.mem.Allocator,
    input: gateway_provider.CliModelCatalogInput,
) gateway_provider.CliModelCatalogResult {
    return switch (model_catalog.fetchWithPublicFallback(model_catalog_provider, alloc, .{
        .access = input.access,
        .endpoint = input.endpoint,
        .cancel_flag = input.cancel_flag,
        .view = .full,
    })) {
        .loaded => |loaded| blk: {
            var catalog = loaded.catalog;
            defer model_catalog.freeModelCatalog(alloc, &catalog);
            const ids = model_catalog.projectModelIds(alloc, catalog.items) catch return .{ .failure = .{
                .access = loaded.provenance.access,
                .anonymous_fallback_used = false,
                .failure = .{ .category = .resource_exhausted },
            } };
            break :blk .{ .loaded = .{
                .ids = ids,
                .provenance = loaded.provenance,
            } };
        },
        .failed => |failure| .{ .failure = failure },
    };
}

fn fetchCatalogForProvider(
    _: ?*anyopaque,
    alloc: std.mem.Allocator,
    input: model_catalog.FetchInput,
) std.mem.Allocator.Error!model_catalog.ProviderResult {
    if (input.access.credentialSource() != .layerx1_subscription) {
        return .{ .failure = .{ .category = .authentication, .http_status = .unauthorized } };
    }
    const credential = input.access.authorizationCredential() orelse
        return .{ .failure = .{ .category = .authentication, .http_status = .unauthorized } };
    const account_id = input.access.accountId() orelse
        return .{ .failure = .{ .category = .authentication, .http_status = .unauthorized } };
    if (!layerx1_session.validAccountId(account_id)) {
        return .{ .failure = .{ .category = .authentication, .http_status = .unauthorized } };
    }
    const request_url = modelsUrl(alloc) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return .{ .failure = .{ .category = .runtime } };
    };
    defer alloc.free(request_url);

    var fallback_cancel = std.atomic.Value(bool).init(false);
    const cancel_flag = input.cancel_flag orelse &fallback_cancel;
    const deadline = std.Io.Clock.Timestamp.fromNow(io_mod.getIo(), .{
        .clock = .awake,
        .raw = .fromMilliseconds(fetch_timeout_ms),
    });
    var response = fetchCatalogResponse(
        alloc,
        request_url,
        credential,
        account_id,
        cancel_flag,
        deadline,
    ) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return .{ .failure = catalogFetchFailure(err) };
    };
    defer response.deinit(alloc);
    if (response.status != .ok) {
        return .{ .failure = model_catalog.failureForHttpStatus(response.status) };
    }
    const catalog = parseCatalog(alloc, response.body) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return .{ .failure = .{ .category = .malformed_response, .http_status = .ok } };
    };
    return .{ .catalog = catalog };
}

fn catalogFetchFailure(err: anyerror) model_catalog.Failure {
    if (err == error.Cancelled) return .{ .category = .cancellation };
    if (err == error.LayerX1ModelCatalogTooLarge) return .{ .category = .malformed_response };
    return .{ .category = .transport, .retryable = true };
}

const FetchResponse = struct {
    status: std.http.Status,
    body: []u8,

    pub fn deinit(self: *FetchResponse, alloc: std.mem.Allocator) void {
        secret.zeroAndFree(alloc, self.body);
        self.* = undefined;
    }
};

const FetchOperation = struct {
    alloc: std.mem.Allocator,
    url: []const u8,
    credential: []const u8,
    account_id: []const u8,

    pub fn run(self: *@This()) !FetchResponse {
        var client: std.http.Client = .{ .allocator = self.alloc, .io = io_mod.getIo() };
        defer client.deinit();
        const auth_header = try std.fmt.allocPrint(self.alloc, "Bearer {s}", .{self.credential});
        defer secret.zeroAndFree(self.alloc, auth_header);
        const body_buffer = try self.alloc.alloc(u8, max_catalog_bytes + 1);
        defer secret.zeroAndFree(self.alloc, body_buffer);
        var response_writer = std.Io.Writer.fixed(body_buffer);
        var extra_headers_buffer: [2]std.http.Header = undefined;
        var extra_headers_len: usize = 0;
        extra_headers_buffer[extra_headers_len] = .{ .name = "accept", .value = "application/json" };
        extra_headers_len += 1;
        extra_headers_buffer[extra_headers_len] = .{ .name = "x-account-id", .value = self.account_id };
        extra_headers_len += 1;
        const result = client.fetch(.{
            .location = .{ .url = self.url },
            .method = .GET,
            .headers = .{
                .authorization = .{ .override = auth_header },
                .user_agent = .{ .override = gateway_client.user_agent },
                .accept_encoding = .omit,
            },
            .extra_headers = extra_headers_buffer[0..extra_headers_len],
            .response_writer = &response_writer,
            .redirect_behavior = .unhandled,
        }) catch |err| switch (err) {
            error.WriteFailed => return error.LayerX1ModelCatalogTooLarge,
            else => return err,
        };
        const body = response_writer.buffered();
        try validateCatalogBodySize(body.len);
        return .{
            .status = result.status,
            .body = try self.alloc.dupe(u8, body),
        };
    }
};

fn fetchCatalogResponse(
    alloc: std.mem.Allocator,
    url: []const u8,
    credential: []const u8,
    account_id: []const u8,
    cancel_flag: *std.atomic.Value(bool),
    deadline: std.Io.Clock.Timestamp,
) !FetchResponse {
    var operation = FetchOperation{
        .alloc = alloc,
        .url = url,
        .credential = credential,
        .account_id = account_id,
    };
    return gateway_client.runBoundedHttpOperation(
        FetchResponse,
        alloc,
        cancel_flag,
        deadline,
        &operation,
    );
}

fn modelsUrl(alloc: std.mem.Allocator) ![]u8 {
    const base = io_mod.getenv(e2e_models_endpoint_env) orelse default_models_endpoint;
    if (io_mod.getenv(e2e_models_endpoint_env) != null and !gateway_client.isLoopbackHttpUrl(base)) {
        return error.InvalidE2ELayerX1ModelsEndpoint;
    }
    return alloc.dupe(u8, base);
}

fn validateCatalogBodySize(len: usize) !void {
    if (len > max_catalog_bytes) return error.LayerX1ModelCatalogTooLarge;
}

fn validateCatalogModelCount(count: usize) !void {
    if (count > max_catalog_models) return error.InvalidLayerX1ModelCatalog;
}

fn validateModelId(id: []const u8) !void {
    if (id.len == 0 or id.len > max_model_id_bytes) return error.InvalidLayerX1ModelCatalog;
    for (id) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return error.InvalidLayerX1ModelCatalog;
    }
}

pub fn parseCatalog(
    alloc: std.mem.Allocator,
    json_bytes: []const u8,
) !std.ArrayList(model_catalog.ModelCatalogEntry) {
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, json_bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidLayerX1ModelCatalog;
    const data = parsed.value.object.get("data") orelse
        return error.InvalidLayerX1ModelCatalog;
    if (data != .array) return error.InvalidLayerX1ModelCatalog;
    try validateCatalogModelCount(data.array.items.len);

    var catalog: std.ArrayList(model_catalog.ModelCatalogEntry) = .empty;
    errdefer model_catalog.freeModelCatalog(alloc, &catalog);
    for (data.array.items) |value| {
        if (value != .object) return error.InvalidLayerX1ModelCatalog;
        const object = value.object;

        const raw_id = requiredString(object, "id") catch continue;
        try validateModelId(raw_id);

        // The shared LayerX1 catalog also contains embedding models. x1 is an
        // agent harness, so only language models belong in its model picker.
        if (object.get("tier")) |tier| {
            if (tier == .string and std.mem.eql(u8, tier.string, "embedding")) continue;
        }

        const id = try alloc.dupe(u8, raw_id);
        errdefer alloc.free(id);
        const model_type = try alloc.dupe(u8, "language");
        errdefer alloc.free(model_type);

        const context_window = optionalPositiveU32(object, "context_window");
        const max_output_tokens = blk: {
            const current = optionalPositiveU32(object, "max_output");
            break :blk if (current != 0) current else optionalPositiveU32(object, "max_tokens");
        };

        const capabilities = object.get("capabilities");
        const supports_tools = capabilityEnabled(capabilities, "tools");
        const supports_reasoning = capabilityEnabled(capabilities, "reasoning");
        const supports_vision = capabilityEnabled(capabilities, "vision");
        const supports_documents = capabilityEnabled(capabilities, "documents");

        var reasoning_efforts: std.ArrayList(types.ReasoningEffort) = .empty;
        errdefer reasoning_efforts.deinit(alloc);
        if (supports_reasoning) {
            try appendReasoningEfforts(alloc, &reasoning_efforts, capabilities);
        }

        try catalog.append(alloc, .{
            .id = id,
            .model_type = model_type,
            .has_tool_use = supports_tools,
            .has_reasoning = supports_reasoning,
            .reasoning_efforts = reasoning_efforts,
            .has_vision = supports_vision,
            .has_file_input = supports_vision or supports_documents,
            .context_window = context_window,
            .max_tokens = max_output_tokens,
        });
    }
    return catalog;
}

fn requiredString(object: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const value = object.get(key) orelse return error.InvalidLayerX1ModelCatalog;
    if (value != .string or value.string.len == 0) return error.InvalidLayerX1ModelCatalog;
    return value.string;
}

fn optionalPositiveU32(object: std.json.ObjectMap, key: []const u8) u32 {
    const value = object.get(key) orelse return 0;
    if (value != .integer or value.integer <= 0) return 0;
    if (value.integer > std.math.maxInt(u32)) return 0;
    return @intCast(value.integer);
}

fn capabilityEnabled(capabilities: ?std.json.Value, key: []const u8) bool {
    const value = capabilities orelse return false;
    if (value != .object) return false;
    const enabled = value.object.get(key) orelse return false;
    return enabled == .bool and enabled.bool;
}

fn appendReasoningEfforts(
    alloc: std.mem.Allocator,
    efforts: *std.ArrayList(types.ReasoningEffort),
    capabilities: ?std.json.Value,
) !void {
    try efforts.append(alloc, types.ReasoningEffort.literal("none"));
    const object = capabilities orelse return;
    if (object != .object) return;
    const declared = object.object.get("reasoning_efforts") orelse return;
    if (declared != .array) return;
    for (declared.array.items) |item| {
        if (item != .string) continue;
        const effort = types.ReasoningEffort.parse(item.string) orelse continue;
        if (effort.eql(types.ReasoningEffort.literal("none"))) continue;
        try efforts.append(alloc, effort);
    }
}

test "LayerX1 model catalog parses an OpenAI-compatible response" {
    const response_body =
        \\{"data":[{"id":"lx1-reasoning","tier":"coding","context_window":200000,"max_output":8192,"capabilities":{"tools":true,"reasoning":true,"vision":true,"documents":false,"reasoning_efforts":["low","medium","high","max"]}},{"id":"lx1-mini","tier":"general","context_window":128000,"max_output":4096,"capabilities":{"tools":true,"reasoning":false,"vision":false,"documents":false}},{"id":"lx1-embed","tier":"embedding","context_window":8192,"max_output":null,"capabilities":{"tools":false,"reasoning":false,"vision":false,"documents":false}}]}
    ;
    var catalog = try parseCatalog(std.testing.allocator, response_body);
    defer model_catalog.freeModelCatalog(std.testing.allocator, &catalog);
    try std.testing.expectEqual(@as(usize, 2), catalog.items.len);
    try std.testing.expectEqualStrings("lx1-reasoning", catalog.items[0].id);
    try std.testing.expectEqual(@as(u32, 200_000), catalog.items[0].context_window);
    try std.testing.expectEqual(@as(u32, 8_192), catalog.items[0].max_tokens);
    try std.testing.expect(catalog.items[0].has_tool_use);
    try std.testing.expect(catalog.items[0].has_reasoning);
    try std.testing.expectEqual(@as(usize, 5), catalog.items[0].reasoning_efforts.items.len);
    try std.testing.expectEqualStrings("none", catalog.items[0].reasoning_efforts.items[0].label());
    try std.testing.expect(catalog.items[0].has_vision);
    try std.testing.expectEqualStrings("lx1-mini", catalog.items[1].id);
    try std.testing.expectEqual(@as(u32, 128_000), catalog.items[1].context_window);
    try std.testing.expect(!catalog.items[1].has_vision);
    try std.testing.expect(!catalog.items[1].has_reasoning);
}
