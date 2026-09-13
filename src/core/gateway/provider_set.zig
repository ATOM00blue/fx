const std = @import("std");
const stream_provider = @import("../agent/stream_provider.zig");
const model_provider = @import("../config/model_provider.zig");
const model_capabilities = @import("../config/model_capabilities.zig");
const provider_catalog = @import("../auth/provider_catalog.zig");
const generation_usage_provider = @import("../session/generation_usage_provider.zig");
const gateway_provider = @import("gateway_provider.zig");
const auto_classifier = @import("../permissions/auto_classifier.zig");
const model_catalog = @import("model_catalog.zig");

const Allocator = std.mem.Allocator;

pub const Bundle = struct {
    pub const AuthStrategy = enum {
        layerx1,
    };
    pub const Capabilities = struct {
        provider_search: bool = false,
        vision_fallback: bool = false,
    };

    capabilities: Capabilities = .{},
    presentation: ?*const provider_catalog.Entry = null,
    auth_strategy: ?AuthStrategy = null,
    fallback_model_capabilities_fn: *const fn ([]const u8) model_capabilities.Capabilities = emptyModelCapabilities,
    agent_stream: ?stream_provider.Provider = null,
    cli_model_catalog: ?gateway_provider.CliModelCatalogProvider = null,
    model_catalog: ?model_catalog.Provider = null,
    permission_reviewer: ?auto_classifier.Provider = null,
    deferred_usage: ?generation_usage_provider.Provider = null,
    credits: ?gateway_provider.CreditsProvider = null,

    pub fn agent_stream_or_unavailable(self: Bundle) stream_provider.Provider {
        return self.agent_stream orelse stream_provider.unavailable_provider;
    }

    pub fn fallbackModelCapabilities(self: Bundle, model: []const u8) model_capabilities.Capabilities {
        return self.fallback_model_capabilities_fn(model);
    }
};

fn emptyModelCapabilities(_: []const u8) model_capabilities.Capabilities {
    return .{};
}

pub const Set = struct {
    layerx1: Bundle,

    pub fn select(self: Set, provider: model_provider.ProviderId) Bundle {
        return switch (provider) {
            .layerx1 => self.layerx1,
        };
    }

    pub fn deferredUsageProviders(self: Set) generation_usage_provider.Set {
        return .{
            .layerx1 = self.layerx1.deferred_usage,
        };
    }
};

pub fn x1Only(layerx1: Bundle) Set {
    return .{ .layerx1 = layerx1 };
}

test "provider set selects the complete x1 route" {
    var layerx1_tag: u8 = 0;

    const Fake = struct {
        fn cli_catalog(
            _: ?*anyopaque,
            _: Allocator,
            _: gateway_provider.CliModelCatalogInput,
        ) gateway_provider.CliModelCatalogResult {
            return .{ .failure = .{
                .access = .init(.{ .public_only = .no_credential }),
                .anonymous_fallback_used = false,
                .failure = .{ .category = .runtime },
            } };
        }

        fn model_catalog_fetch(
            _: ?*anyopaque,
            _: Allocator,
            _: model_catalog.FetchInput,
        ) Allocator.Error!model_catalog.ProviderResult {
            return .{ .catalog = .empty };
        }

        fn review(
            _: ?*anyopaque,
            _: Allocator,
            _: auto_classifier.ProviderInput,
            _: auto_classifier.ReviewRequest,
        ) anyerror!auto_classifier.ParseOutcome {
            return .invalid;
        }
    };

    const layerx1 = Bundle{
        .capabilities = .{ .vision_fallback = true },
        .presentation = provider_catalog.find(.layerx1),
        .auth_strategy = .layerx1,
        .agent_stream = stream_provider.Provider{
            .context = &layerx1_tag,
            .stream_fn = stream_provider.unavailable_provider.stream_fn,
        },
        .cli_model_catalog = .{ .context = &layerx1_tag, .fetch_fn = Fake.cli_catalog },
        .model_catalog = .{ .context = &layerx1_tag, .fetch_fn = Fake.model_catalog_fetch },
        .permission_reviewer = .{ .context = &layerx1_tag, .review_fn = Fake.review },
        .deferred_usage = generation_usage_provider.unavailable_provider,
    };
    var providers = Set{ .layerx1 = layerx1 };

    try std.testing.expect(providers.select(.layerx1).capabilities.vision_fallback);
    try std.testing.expect(providers.select(.layerx1).deferred_usage != null);
    try std.testing.expectEqualStrings("x1", providers.select(.layerx1).presentation.?.slug);
    try std.testing.expectEqual(Bundle.AuthStrategy.layerx1, providers.select(.layerx1).auth_strategy.?);
    try std.testing.expect(providers.select(.layerx1).agent_stream.?.context.? == @as(*anyopaque, @ptrCast(&layerx1_tag)));
    try std.testing.expect(providers.select(.layerx1).cli_model_catalog.?.context.? == @as(*anyopaque, @ptrCast(&layerx1_tag)));
    try std.testing.expect(providers.select(.layerx1).model_catalog.?.context.? == @as(*anyopaque, @ptrCast(&layerx1_tag)));
    try std.testing.expect(providers.select(.layerx1).permission_reviewer.?.context.? == @as(*anyopaque, @ptrCast(&layerx1_tag)));
    try std.testing.expect(providers.select(.layerx1).agent_stream_or_unavailable().context.? == @as(*anyopaque, @ptrCast(&layerx1_tag)));

    providers.layerx1.model_catalog = null;
    try std.testing.expect(providers.select(.layerx1).model_catalog == null);
}
