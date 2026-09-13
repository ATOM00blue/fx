const std = @import("std");
const types = @import("../shared/types.zig");

pub const ProviderId = enum {
    layerx1,
};

pub const ProviderSelection = struct {
    provider: ProviderId,
    model: []const u8,
};

pub fn parse(value: []const u8) ?ProviderId {
    if (std.ascii.eqlIgnoreCase(value, "layerx1") or std.ascii.eqlIgnoreCase(value, "x1")) return .layerx1;
    return null;
}

pub fn authorizesCredential(provider: ProviderId, source: ?types.CredentialSource) bool {
    const selected = source orelse return false;
    return switch (provider) {
        .layerx1 => selected == .layerx1_subscription,
    };
}

test "x1 provider authorizes only the LayerX1 subscription credential" {
    try std.testing.expect(authorizesCredential(.layerx1, .layerx1_subscription));
    try std.testing.expect(!authorizesCredential(.layerx1, null));
}

test "provider parsing exposes only x1 aliases" {
    try std.testing.expectEqual(ProviderId.layerx1, parse("layerx1").?);
    try std.testing.expectEqual(ProviderId.layerx1, parse("x1").?);
    try std.testing.expectEqual(ProviderId.layerx1, parse("X1").?);
    try std.testing.expect(parse("gateway") == null);
    try std.testing.expect(parse("codex") == null);
    try std.testing.expect(parse("grok") == null);
    try std.testing.expect(parse("openai-codex") == null);
    try std.testing.expect(parse("") == null);
}
