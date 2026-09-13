const std = @import("std");
const model_catalog = @import("../core/gateway/model_catalog.zig");
const builtin_x1 = @import("../builtins/x1.zig");
const layerx1_models = @import("layerx1_models.zig");

const Allocator = std.mem.Allocator;

extern "x1" fn x1_http_request(
    method_ptr: [*]const u8,
    method_len: usize,
    url_ptr: [*]const u8,
    url_len: usize,
    headers_ptr: [*]const u8,
    headers_len: usize,
    body_ptr: [*]const u8,
    body_len: usize,
    status_out: *u16,
    response_ptr: [*]u8,
    response_cap: usize,
) i32;

pub const provider = model_catalog.Provider{ .fetch_fn = fetch };

fn fetch(
    _: ?*anyopaque,
    alloc: Allocator,
    input: model_catalog.FetchInput,
) Allocator.Error!model_catalog.ProviderResult {
    if (input.cancel_flag) |flag| {
        if (flag.load(.seq_cst)) return .{ .failure = .{ .category = .cancellation } };
    }

    const url = builtin_x1.models_path;

    const Header = struct { name: []const u8, value: []const u8 };
    var headers: std.ArrayList(Header) = .empty;
    defer headers.deinit(alloc);
    const authorization = if (input.access.authorizationCredential()) |credential|
        try std.fmt.allocPrint(alloc, "Bearer {s}", .{credential})
    else
        null;
    defer if (authorization) |value| alloc.free(value);
    if (authorization) |value| {
        try headers.append(alloc, .{ .name = "authorization", .value = value });
    }
    if (input.access.accountId()) |account_id| {
        try headers.append(alloc, .{ .name = "x-account-id", .value = account_id });
    }

    var headers_json: std.Io.Writer.Allocating = .init(alloc);
    defer headers_json.deinit();
    std.json.Stringify.value(headers.items, .{}, &headers_json.writer) catch return error.OutOfMemory;

    const response_cap = 4 * 1024 * 1024;
    const response = try alloc.alloc(u8, response_cap);
    defer alloc.free(response);
    var status: u16 = 0;
    const method = "GET";
    const response_len = x1_http_request(
        method.ptr,
        method.len,
        url.ptr,
        url.len,
        headers_json.writer.buffered().ptr,
        headers_json.writer.buffered().len,
        "".ptr,
        0,
        &status,
        response.ptr,
        response.len,
    );
    if (response_len < 0) return .{ .failure = .{ .category = .transport, .retryable = true } };
    if (response_len > response.len) return .{ .failure = .{ .category = .resource_exhausted } };
    if (status != 200) {
        return .{ .failure = model_catalog.failureForHttpStatus(@enumFromInt(status)) };
    }

    const catalog = layerx1_models.parseCatalog(
        alloc,
        response[0..@intCast(response_len)],
    ) catch |err| return .{ .failure = .{
        .category = if (err == error.OutOfMemory) .resource_exhausted else .malformed_response,
        .http_status = .ok,
    } };
    return .{ .catalog = catalog };
}
