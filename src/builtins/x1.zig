const std = @import("std");
const oauth_transport = @import("../core/auth/oauth_transport.zig");
const secret = @import("../core/auth/secret.zig");
const io_mod = @import("../core/shared/io.zig");
const gateway_provider = @import("../core/gateway/gateway_provider.zig");
const gateway_client = @import("../gateway/http_runtime.zig");
const provider_set = @import("../core/gateway/provider_set.zig");
const provider_catalog = @import("../core/auth/provider_catalog.zig");
const layerx1 = @import("../gateway/layerx1.zig");
const layerx1_models = @import("../gateway/layerx1_models.zig");

const Allocator = std.mem.Allocator;

pub const default_model = "lx1-deepseek-v4-flash";
pub const default_chat_url = "https://api.layerx1.com/v1/responses";
pub const models_path = "https://api.layerx1.com/v1/models";
pub const retry_count: usize = 3;

const oauth_request_timeout_ms: i64 = 15_000;
const oauth_response_max_bytes: usize = 64 * 1024;

pub const oauth_transport_provider = oauth_transport.Provider{
    .execute_fn = executeOAuthRequest,
};

pub const chat_url_provider = gateway_provider.ChatUrlProvider{
    .resolve_fn = resolveChatUrl,
};

pub const provider = gateway_provider.Provider{
    .oauth_transport = oauth_transport_provider,
    .chat_url = chat_url_provider,
};

pub const agent_stream_provider = layerx1.agent_stream_provider;
pub const cli_model_catalog_provider = layerx1_models.cli_model_catalog_provider;
pub const model_catalog_provider = layerx1_models.model_catalog_provider;
pub const credits_provider = layerx1.credits_provider;
pub const buildAgentRequest = layerx1.buildRequest;

pub const provider_bundle = provider_set.Bundle{
    .presentation = provider_catalog.find(.layerx1),
    .auth_strategy = .layerx1,
    .agent_stream = agent_stream_provider,
    .cli_model_catalog = cli_model_catalog_provider,
    .model_catalog = model_catalog_provider,
    .credits = credits_provider,
};

pub fn defaultChatUrl() []const u8 {
    return default_chat_url;
}

fn resolveChatUrl(_: ?*anyopaque, fallback: []const u8) []const u8 {
    return fallback;
}

fn executeOAuthRequest(
    _: ?*anyopaque,
    alloc: Allocator,
    request: oauth_transport.Request,
) !oauth_transport.Response {
    var local_cancel = std.atomic.Value(bool).init(false);
    const cancel_flag = request.cancel_flag orelse &local_cancel;
    const deadline = request.deadline orelse std.Io.Clock.Timestamp.fromNow(io_mod.getIo(), .{
        .clock = .awake,
        .raw = .fromMilliseconds(oauth_request_timeout_ms),
    });
    var operation = OAuthHttpOperation{ .alloc = alloc, .request = request };
    return gateway_client.runBoundedHttpOperation(
        oauth_transport.Response,
        alloc,
        cancel_flag,
        deadline,
        &operation,
    );
}

const OAuthHttpOperation = struct {
    alloc: Allocator,
    request: oauth_transport.Request,

    pub fn run(self: *@This()) !oauth_transport.Response {
        var client: std.http.Client = .{ .allocator = self.alloc, .io = io_mod.getIo() };
        defer client.deinit();

        const response_buffer = try self.alloc.alloc(u8, oauth_response_max_bytes + 1);
        defer secret.zeroAndFree(self.alloc, response_buffer);
        var response_writer = std.Io.Writer.fixed(response_buffer);
        const result = client.fetch(.{
            .location = .{ .url = self.request.url },
            .method = switch (self.request.method) {
                .get => .GET,
                .post_form, .post_json => .POST,
            },
            .payload = self.request.payload,
            .headers = .{
                .content_type = switch (self.request.method) {
                    .get => .default,
                    .post_form => .{ .override = "application/x-www-form-urlencoded" },
                    .post_json => .{ .override = "application/json" },
                },
                .user_agent = .{ .override = gateway_client.user_agent },
                .accept_encoding = .omit,
                .authorization = if (self.request.authorization) |value|
                    .{ .override = value }
                else
                    .default,
            },
            .redirect_behavior = .unhandled,
            .response_writer = &response_writer,
        }) catch |err| switch (err) {
            error.WriteFailed => return error.OAuthResponseTooLarge,
            else => return err,
        };
        const body = response_writer.buffered();
        if (body.len > oauth_response_max_bytes) return error.OAuthResponseTooLarge;
        return .{
            .disposition = if (result.status == .ok) .accepted else .rejected,
            .body = try self.alloc.dupe(u8, body),
        };
    }
};

test "X1 builtins expose only LayerX1 endpoints" {
    try std.testing.expect(std.mem.startsWith(u8, default_chat_url, "https://api.layerx1.com/"));
    try std.testing.expect(std.mem.startsWith(u8, models_path, "https://api.layerx1.com/"));
    try std.testing.expectEqualStrings(default_chat_url, defaultChatUrl());
}
