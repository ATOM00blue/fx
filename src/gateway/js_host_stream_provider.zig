const stream_provider = @import("../core/agent/stream_provider.zig");
const host_stream_provider = @import("host_stream_provider.zig");
const builtin_x1 = @import("../builtins/x1.zig");
const layerx1 = @import("layerx1.zig");

extern "x1" fn x1_http_stream_open(
    method_ptr: [*]const u8,
    method_len: usize,
    url_ptr: [*]const u8,
    url_len: usize,
    headers_ptr: [*]const u8,
    headers_len: usize,
    body_ptr: [*]const u8,
    body_len: usize,
) i32;
extern "x1" fn x1_http_stream_status(handle: i32, status_out: *u16) i32;
extern "x1" fn x1_http_stream_next(handle: i32, out_ptr: [*]u8, out_cap: usize) i32;
extern "x1" fn x1_http_stream_close(handle: i32) void;

const provider_context = host_stream_provider.initContext(layerx1.buildRequest, .{ .fixed = builtin_x1.default_chat_url }, .{
    .context = null,
    .open_fn = open,
    .status_fn = status,
    .next_fn = next,
    .close_fn = close,
});

pub fn provider() stream_provider.Provider {
    return host_stream_provider.provider(@constCast(&provider_context));
}

fn open(_: ?*anyopaque, method: []const u8, url: []const u8, headers: []const u8, body: []const u8) !i32 {
    const handle = x1_http_stream_open(method.ptr, method.len, url.ptr, url.len, headers.ptr, headers.len, body.ptr, body.len);
    if (handle < 0) return error.HostStreamFailed;
    return handle;
}

fn status(_: ?*anyopaque, handle: i32, status_out: *u16) i32 {
    return x1_http_stream_status(handle, status_out);
}

fn next(_: ?*anyopaque, handle: i32, out: []u8) i32 {
    return x1_http_stream_next(handle, out.ptr, out.len);
}

fn close(_: ?*anyopaque, handle: i32) void {
    x1_http_stream_close(handle);
}
