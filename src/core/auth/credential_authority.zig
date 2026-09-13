const std = @import("std");
const types = @import("../shared/types.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Identity = struct {
    bytes: [Sha256.digest_length]u8,

    pub fn eql(self: Identity, other: Identity) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
};

/// Derives a persistable, non-secret identity. Gateway sources use the selected
/// credential slot; provider subscriptions require a stable account ID.
pub fn derive(
    source: types.CredentialSource,
    account_id: ?[]const u8,
) ?Identity {
    var hash = Sha256.init(.{});
    hash.update("x1-credential-authority-v1\x00");
    hash.update(@tagName(source));
    switch (source) {
        .layerx1_subscription,
        => {
            const account = account_id orelse return null;
            if (account.len == 0) return null;
            hash.update("\x00account\x00");
            hash.update(account);
        },
    }
    var bytes: [Sha256.digest_length]u8 = undefined;
    hash.final(&bytes);
    return .{ .bytes = bytes };
}

test "credential authority uses account identity for provider subscriptions" {
    const first = derive(.layerx1_subscription, "acct_1").?;
    const refreshed = derive(.layerx1_subscription, "acct_1").?;
    const other = derive(.layerx1_subscription, "acct_2").?;
    try std.testing.expect(first.eql(refreshed));
    try std.testing.expect(!first.eql(other));
    try std.testing.expect(derive(.layerx1_subscription, null) == null);
    try std.testing.expect(derive(.layerx1_subscription, "") == null);
    try std.testing.expect(@sizeOf(Identity) == 32);
    _ = types.CredentialSource;
}
