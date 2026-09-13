const std = @import("std");
const credentials = @import("credentials.zig");
const model_provider = @import("../config/model_provider.zig");

pub const ProviderSwitchDecision = enum {
    no_change,
    busy,
    prepare,
};

pub const ProviderSwitchIntent = enum {
    manual,
    post_oauth,
};

pub const ProviderSwitchFacts = struct {
    current: model_provider.ProviderId,
    target: model_provider.ProviderId,
    target_credential_ready: bool,
    intent: ProviderSwitchIntent,
    stream_active: bool,
    queued_prompts: usize,
};

pub fn decideProviderSwitch(facts: ProviderSwitchFacts) ProviderSwitchDecision {
    if (facts.intent == .manual and facts.current == facts.target and facts.target_credential_ready) {
        return .no_change;
    }
    if (facts.stream_active or facts.queued_prompts > 0) return .busy;
    return .prepare;
}

pub const LogoutFacts = struct {
    requested: ?model_provider.ProviderId,
    selected: model_provider.ProviderId,
    active_source: ?credentials.Source,
    available_sources: std.EnumSet(credentials.Source),
};

pub fn decideLogoutProvider(facts: LogoutFacts) model_provider.ProviderId {
    if (facts.requested) |provider| return provider;
    _ = facts.active_source;
    _ = facts.available_sources;
    return .layerx1;
}

pub const SignInCompletionAction = union(enum) {
    switch_provider: model_provider.ProviderId,
    activate_source: credentials.Source,
};

pub fn signInCompletion(
    provider: model_provider.ProviderId,
    provider_routing_supported: bool,
) SignInCompletionAction {
    return switch (provider) {
        .layerx1 => if (provider_routing_supported)
            .{ .switch_provider = .layerx1 }
        else
            .{ .activate_source = .layerx1_subscription },
    };
}

test "provider switch and logout decisions are pure and provider keyed" {
    try std.testing.expectEqual(ProviderSwitchDecision.no_change, decideProviderSwitch(.{
        .current = .layerx1,
        .target = .layerx1,
        .target_credential_ready = true,
        .intent = .manual,
        .stream_active = false,
        .queued_prompts = 0,
    }));
    try std.testing.expectEqual(ProviderSwitchDecision.busy, decideProviderSwitch(.{
        .current = .layerx1,
        .target = .layerx1,
        .target_credential_ready = false,
        .intent = .manual,
        .stream_active = true,
        .queued_prompts = 0,
    }));

    const inventory: std.EnumSet(credentials.Source) = .empty;
    try std.testing.expectEqual(model_provider.ProviderId.layerx1, decideLogoutProvider(.{
        .requested = null,
        .selected = .layerx1,
        .active_source = null,
        .available_sources = inventory,
    }));
    try std.testing.expectEqual(model_provider.ProviderId.layerx1, decideLogoutProvider(.{
        .requested = .layerx1,
        .selected = .layerx1,
        .active_source = .layerx1_subscription,
        .available_sources = inventory,
    }));
}

test "sign in completion selects routing or credential activation without effects" {
    try std.testing.expectEqual(
        SignInCompletionAction{ .switch_provider = .layerx1 },
        signInCompletion(.layerx1, true),
    );
    try std.testing.expectEqual(
        SignInCompletionAction{ .activate_source = .layerx1_subscription },
        signInCompletion(.layerx1, false),
    );
}
