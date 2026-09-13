const provider_set = @import("../core/gateway/provider_set.zig");
const layerx1 = @import("../gateway/layerx1.zig");
const layerx1_models = @import("../gateway/layerx1_models.zig");
const provider_catalog = @import("../core/auth/provider_catalog.zig");

pub const native = provider_set.Set{
    .layerx1 = .{
        .presentation = provider_catalog.find(.layerx1),
        .auth_strategy = .layerx1,
        .agent_stream = layerx1.agent_stream_provider,
        .cli_model_catalog = layerx1_models.cli_model_catalog_provider,
        .model_catalog = layerx1_models.model_catalog_provider,
        .credits = layerx1.credits_provider,
    },
};
