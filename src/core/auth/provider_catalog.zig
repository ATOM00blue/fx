const std = @import("std");
const model_provider = @import("../config/model_provider.zig");

pub const Entry = struct {
    id: model_provider.ProviderId,
    slug: []const u8,
    aliases: []const []const u8 = &.{},
    name: []const u8,
    route_name: []const u8,
    description: []const u8,
    subscription: bool,
};

pub const entries = [_]Entry{
    .{
        .id = .layerx1,
        .slug = "x1",
        .aliases = &.{"layerx1"},
        .name = "X1",
        .route_name = "X1",
        .description = "X1 platform subscription",
        .subscription = true,
    },
};

pub fn parse(value: []const u8) ?model_provider.ProviderId {
    for (&entries) |*entry| {
        if (std.ascii.eqlIgnoreCase(value, entry.slug)) return entry.id;
        for (entry.aliases) |alias| if (std.ascii.eqlIgnoreCase(value, alias)) return entry.id;
    }
    return null;
}

pub fn find(id: model_provider.ProviderId) *const Entry {
    for (&entries) |*entry| if (entry.id == id) return entry;
    unreachable;
}

pub fn label(id: model_provider.ProviderId) []const u8 {
    return find(id).route_name;
}

test "auth provider catalog uses the model provider identity and explicit aliases" {
    try std.testing.expectEqual(model_provider.ProviderId.layerx1, parse("layerx1").?);
    try std.testing.expectEqual(model_provider.ProviderId.layerx1, parse("x1").?);
    try std.testing.expect(parse("vercel") == null);
    try std.testing.expect(parse("gateway") == null);
    try std.testing.expect(parse("codex") == null);
    try std.testing.expect(parse("grok") == null);
    try std.testing.expect(parse("openai-codex") == null);
    try std.testing.expect(parse("chatgpt") == null);
    try std.testing.expect(parse("unknown") == null);
    try std.testing.expect(find(.layerx1).subscription);
}
