const std = @import("std");
const layerx1_oauth = @import("layerx1_oauth.zig");
const debug_trace = @import("../shared/debug_trace.zig");
const host = @import("../hosts/host.zig");
const io_mod = @import("../shared/io.zig");
const model_provider = @import("../config/model_provider.zig");
const oauth_transport = @import("oauth_transport.zig");
const secret = @import("secret.zig");
const types = @import("../shared/types.zig");

pub const Source = types.CredentialSource;

pub const CatalogPublicOnly = union(enum) {
    no_credential,
    credential_refresh_failed: Source,
    authenticated_credential_rejected: Source,
    layerx1_subscription,

    fn credentialSource(self: CatalogPublicOnly) ?Source {
        return switch (self) {
            .no_credential => null,
            .credential_refresh_failed => |source| source,
            .authenticated_credential_rejected => |source| source,
            .layerx1_subscription => .layerx1_subscription,
        };
    }
};

pub const CatalogPublicOnlyReason = std.meta.Tag(CatalogPublicOnly);

pub const CatalogAuthenticatedSource = enum {
    layerx1_subscription,

    fn credentialSource(self: CatalogAuthenticatedSource) Source {
        return switch (self) {
            .layerx1_subscription => .layerx1_subscription,
        };
    }
};

/// A borrowed authorization decision for one model-catalog request. Public-only
/// states cannot carry credential or team bytes; authenticated states carry the
/// only values the request is allowed to send.
pub const CatalogAccess = union(enum) {
    public_only: CatalogPublicOnly,
    authenticated: struct {
        source: CatalogAuthenticatedSource,
        credential: []const u8,
        team_context: ?[]const u8,
        account_id: ?[]const u8 = null,
    },

    pub fn credentialSource(self: CatalogAccess) ?Source {
        return switch (self) {
            .public_only => |access| access.credentialSource(),
            .authenticated => |access| access.source.credentialSource(),
        };
    }

    pub fn publicOnlyReason(self: CatalogAccess) ?CatalogPublicOnlyReason {
        const access = self.publicOnly() orelse return null;
        return std.meta.activeTag(access);
    }

    pub fn publicOnly(self: CatalogAccess) ?CatalogPublicOnly {
        return switch (self) {
            .public_only => |access| access,
            .authenticated => null,
        };
    }

    pub fn publicFallbackAfterRejection(self: CatalogAccess) ?CatalogAccess {
        return switch (self) {
            .public_only => null,
            .authenticated => null,
        };
    }

    pub fn authorizationCredential(self: CatalogAccess) ?[]const u8 {
        return switch (self) {
            .public_only => null,
            .authenticated => |access| access.credential,
        };
    }

    pub fn teamContext(self: CatalogAccess) ?[]const u8 {
        const team = switch (self) {
            .public_only => return null,
            .authenticated => |access| access.team_context orelse return null,
        };
        return if (team.len > 0) team else null;
    }

    pub fn accountId(self: CatalogAccess) ?[]const u8 {
        const account_id = switch (self) {
            .public_only => return null,
            .authenticated => |access| access.account_id orelse return null,
        };
        return if (account_id.len > 0) account_id else null;
    }
};

pub fn catalogAccessAt(credential: ?Credential, now_ms: i64) CatalogAccess {
    _ = now_ms;
    const selected = credential orelse return .{ .public_only = .no_credential };
    return catalogAccessForCredentialAndAccount(
        selected.source,
        selected.token,
        selected.gatewayTeam(),
        selected.accountId(),
    );
}

pub fn catalogAccessAfterRefreshFailure(source: Source) CatalogAccess {
    return .{
        .public_only = .{
            .credential_refresh_failed = source,
        },
    };
}

pub fn catalogAccessForCredential(
    source: ?Source,
    credential: []const u8,
    team_context: ?[]const u8,
) CatalogAccess {
    return catalogAccessForCredentialAndAccount(source, credential, team_context, null);
}

pub fn catalogAccessForCredentialAndAccount(
    source: ?Source,
    credential: []const u8,
    team_context: ?[]const u8,
    account_id: ?[]const u8,
) CatalogAccess {
    _ = team_context;
    const selected_source = source orelse return .{ .public_only = .no_credential };
    const authenticated_source: CatalogAuthenticatedSource = switch (selected_source) {
        .layerx1_subscription => .layerx1_subscription,
    };
    return .{
        .authenticated = .{
            .source = authenticated_source,
            .credential = credential,
            .team_context = null,
            .account_id = account_id,
        },
    };
}

/// Current native product copy. Store mechanics and availability come from the
/// injected host port; Core retains the stable user-facing source name.
/// Both modes resolve the X1 session; the mode selects whether an expired
/// session may be refreshed.
pub const LoadMode = enum { stored, refresh_if_needed };
pub const missing_layerx1_credential_message = "x1 needs a LayerX1 login. Run x1 login.";
pub const missing_layerx1_interactive_credential_message = "X1 needs a LayerX1 login. Run /login.";

pub const Credential = struct {
    token: []u8,
    source: Source,
    account_id: ?[]u8 = null,
    team_id: ?[]u8 = null,
    team_slug: ?[]u8 = null,
    refresh_after_ms: ?i64 = null,

    pub fn deinit(self: *Credential, alloc: std.mem.Allocator) void {
        secret.zeroAndFree(alloc, self.token);
        if (self.account_id) |account_id| alloc.free(account_id);
        if (self.team_id) |team| alloc.free(team);
        if (self.team_slug) |team| alloc.free(team);
        self.* = undefined;
    }

    pub fn gatewayTeam(self: Credential) ?[]const u8 {
        if (self.team_id) |team| return team;
        return self.team_slug;
    }

    pub fn accountId(self: Credential) ?[]const u8 {
        return self.account_id;
    }

    pub fn needsRefreshAt(self: Credential, now_ms: i64) bool {
        const refresh_after_ms = self.refresh_after_ms orelse return false;
        return refresh_after_ms <= now_ms;
    }
};

pub const StoredKeyReadStatus = enum {
    not_attempted,
    not_found,
    unavailable,
};

/// Why the x1 login produced no credential. Only meaningful once resolution has
/// reached the x1-login step and it stayed silent. `unavailable` means the
/// session could not be loaded or its refresh failed, which is different from
/// having no session at all: the login exists and may still be repairable.
pub const x1LoginReadStatus = enum {
    not_attempted,
    absent,
    unavailable,
};

pub const Resolution = struct {
    credential: ?Credential = null,
    stored_key_status: StoredKeyReadStatus = .not_attempted,
    x1_login_status: x1LoginReadStatus = .not_attempted,
};

/// The single credential resolution method. Walks source precedence, then falls back to
/// the stored key, reporting why that store was silent when it produced nothing.
pub fn resolve(
    alloc: std.mem.Allocator,
    transport: oauth_transport.Provider,
    secret_store: host.SecretStore,
    mode: LoadMode,
) !Resolution {
    return resolveForProvider(alloc, transport, secret_store, mode, .layerx1, null);
}

pub fn resolveForProvider(
    alloc: std.mem.Allocator,
    transport: oauth_transport.Provider,
    secret_store: host.SecretStore,
    mode: LoadMode,
    provider: model_provider.ProviderId,
    preferred: ?Source,
) !Resolution {
    _ = secret_store;
    _ = preferred;
    _ = provider;
    const credential = switch (mode) {
        .stored => try loadStoredLayerX1Credential(alloc),
        .refresh_if_needed => try loadLayerX1Credential(alloc, transport, .if_needed),
    };
    return .{ .credential = credential };
}

/// `preferred` is the source the user last chose in the hub. It wins over the
/// precedence order below, including over the environment, because it is an
/// explicit choice rather than a default. A preferred source that no longer
/// resolves falls through to precedence instead of failing.
pub fn resolvePreferring(
    alloc: std.mem.Allocator,
    transport: oauth_transport.Provider,
    secret_store: host.SecretStore,
    mode: LoadMode,
    preferred: ?Source,
) !Resolution {
    return resolveForProvider(alloc, transport, secret_store, mode, .layerx1, preferred);
}

/// `loadSource` always refreshes an expired x1 login, which `.stored` mode
/// forbids: a diagnostic must not rewrite the session file or make an OAuth
/// request. Honour the mode for the preferred source too.
fn loadPreferredSource(
    alloc: std.mem.Allocator,
    transport: oauth_transport.Provider,
    secret_store: host.SecretStore,
    mode: LoadMode,
    source: Source,
) !?Credential {
    _ = secret_store;
    return switch (source) {
        .layerx1_subscription => switch (mode) {
            .stored => loadStoredLayerX1Credential(alloc),
            .refresh_if_needed => loadLayerX1Credential(alloc, transport, .if_needed),
        },
    };
}

pub fn loadSource(
    alloc: std.mem.Allocator,
    transport: oauth_transport.Provider,
    secret_store: host.SecretStore,
    source: Source,
) !?Credential {
    _ = secret_store;
    return switch (source) {
        .layerx1_subscription => loadLayerX1Credential(alloc, transport, .if_needed),
    };
}

pub fn sourceExists(
    alloc: std.mem.Allocator,
    secret_store: host.SecretStore,
    source: Source,
) !bool {
    _ = secret_store;
    return switch (source) {
        .layerx1_subscription => layerx1_oauth.sourceExists(alloc),
    };
}

fn loadLayerX1Credential(
    alloc: std.mem.Allocator,
    transport: oauth_transport.Provider,
    mode: layerx1_oauth.RefreshMode,
) !?Credential {
    var access = (try layerx1_oauth.loadAccess(alloc, transport, mode)) orelse return null;
    defer access.deinit(alloc);
    const token = access.access_token;
    access.access_token = &.{};
    const account_id = access.account_id;
    access.account_id = &.{};
    return .{
        .token = token,
        .source = .layerx1_subscription,
        .account_id = account_id,
        .refresh_after_ms = access.refresh_after_ms,
    };
}

fn loadStoredLayerX1Credential(alloc: std.mem.Allocator) !?Credential {
    return loadLayerX1Credential(alloc, oauth_transport.unavailable_provider, .stored);
}

pub fn refreshLayerX1Credential(
    alloc: std.mem.Allocator,
    transport: oauth_transport.Provider,
) !?Credential {
    return loadLayerX1Credential(alloc, transport, .force);
}

pub fn sourceLabel(source: Source) []const u8 {
    return switch (source) {
        .layerx1_subscription => "X1 subscription",
    };
}

pub fn sourceRefreshable(source: Source) bool {
    return source == .layerx1_subscription;
}

test "X1 is the only credential source" {
    try std.testing.expectEqualStrings("X1 subscription", sourceLabel(.layerx1_subscription));
    try std.testing.expect(sourceRefreshable(.layerx1_subscription));
}

test "X1 catalog access carries only its account credential" {
    const missing = catalogAccessAt(null, 0);
    try std.testing.expectEqual(CatalogPublicOnlyReason.no_credential, missing.publicOnlyReason().?);
    try std.testing.expect(missing.credentialSource() == null);
    try std.testing.expect(missing.authorizationCredential() == null);

    var credential = Credential{
        .token = try std.testing.allocator.dupe(u8, "x1-secret"),
        .source = .layerx1_subscription,
        .account_id = try std.testing.allocator.dupe(u8, "acct_x1"),
    };
    defer credential.deinit(std.testing.allocator);

    const access = catalogAccessAt(credential, 0);
    try std.testing.expectEqual(Source.layerx1_subscription, access.credentialSource().?);
    try std.testing.expectEqualStrings("x1-secret", access.authorizationCredential().?);
    try std.testing.expectEqualStrings("acct_x1", access.accountId().?);
    try std.testing.expect(access.teamContext() == null);
    try std.testing.expect(access.publicFallbackAfterRejection() == null);
}
