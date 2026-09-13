const std = @import("std");
const config_runtime = @import("../config/config_runtime.zig");
const debug_trace = @import("../shared/debug_trace.zig");
const host = @import("../hosts/host.zig");
const runtime_profile = @import("../hosts/runtime_profile.zig");
const host_target = @import("../hosts/target.zig");
const io_mod = @import("../shared/io.zig");
const credentials = @import("../auth/credentials.zig");
const auth_runtime = @import("../auth/auth_runtime.zig");
const login_flow = @import("../auth/login_flow.zig");
const layerx1_oauth = @import("../auth/layerx1_oauth.zig");
const provider_catalog = @import("../auth/provider_catalog.zig");
const auth_transition = @import("../auth/auth_transition.zig");
const model_provider = @import("../config/model_provider.zig");
const model_catalog = @import("../gateway/model_catalog.zig");
const provider_runtime = @import("provider_runtime.zig");
const types = @import("../shared/types.zig");

fn oauthAuthEnabled(comptime App: type) bool {
    return runtime_profile.allows(App, .native_auth) or
        runtime_profile.allows(App, .js_host_auth);
}

const ProviderSwitchDecision = auth_transition.ProviderSwitchDecision;
const ProviderSwitchIntent = auth_transition.ProviderSwitchIntent;
const ProviderSwitchFacts = auth_transition.ProviderSwitchFacts;
const decideProviderSwitch = auth_transition.decideProviderSwitch;

fn providerFailureMessage(
    intent: ProviderSwitchIntent,
    ordinary: []const u8,
    after_oauth: []const u8,
) []const u8 {
    return if (intent == .post_oauth) after_oauth else ordinary;
}

fn selectCatalogModel(
    entries: []const model_catalog.ModelCatalogEntry,
    primary: ?[]const u8,
    secondary: ?[]const u8,
) ?[]const u8 {
    for ([_]?[]const u8{ primary, secondary }) |maybe_candidate| {
        const candidate = maybe_candidate orelse continue;
        for (entries) |entry| {
            if (std.mem.eql(u8, candidate, entry.id)) return entry.id;
        }
    }
    return if (entries.len > 0) entries[0].id else null;
}

pub fn Runtime(comptime App: type) type {
    return struct {
        fn ensurePromptCredential(app: *App) !bool {
            if (comptime provider_runtime.supported(App) and
                @hasDecl(@TypeOf(app.auth), "selectForProvider"))
            {
                const provider = provider_runtime.provider(app);
                const required_source: credentials.Source = .layerx1_subscription;
                const route_change = app.auth.selectForProvider(app.alloc, provider) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    else => return recoverCredentialFailure(app, required_source, err),
                };
                if (route_change) |changed| {
                    applyCredentialChange(app, changed);
                } else if (!model_provider.authorizesCredential(provider, app.auth.credentialSource())) {
                    try app.writeDomainNotice(.{
                        .topic = "auth",
                        .tone = .warning,
                        .body = credentials.missing_layerx1_interactive_credential_message,
                    }, true);
                    app.shell.render_requests.request(.footer);
                    return false;
                }
            }
            if (app.auth.credentialSource() != null) return true;

            const auth_view = app.auth.view();
            if (auth_view.onboarding_skipped or comptime !runtime_profile.allows(App, .native_auth)) {
                try app.writeDomainNotice(.{
                    .topic = "auth",
                    .tone = .@"error",
                    .body = if (comptime host_target.is_wasm)
                        "Missing X1_API_KEY. Supply it through createX1Terminal()."
                    else
                        credentials.missing_layerx1_interactive_credential_message,
                }, true);
            } else if (!app.auth.pickerView().active) {
                try app.auth.refreshSourceInventory(app.alloc);
                app.auth.openOnboardingPicker(app.alloc);
            }
            app.shell.render_requests.request(.footer);
            return false;
        }

        pub fn runLoginCommand(app: *App) !void {
            if (comptime !oauthAuthEnabled(App)) {
                try app.writeDomainNotice(.{
                    .topic = "auth",
                    .tone = .warning,
                    .body = "Set X1_API_KEY through createX1Terminal() to authenticate this WASM session.",
                }, true);
                return;
            }
            if (comptime host_target.is_wasm) {
                try app.writeDomainNotice(.{
                    .topic = "auth",
                    .tone = .warning,
                    .body = "Set X1_API_KEY through createX1Terminal() to authenticate this WASM session.",
                }, true);
                return;
            }
            try beginLayerX1SignIn(app);
        }

        pub fn runLogoutCommand(app: *App, target: []const u8) !void {
            if (comptime !oauthAuthEnabled(App)) {
                try app.writeDomainNotice(.{
                    .topic = "auth",
                    .tone = .warning,
                    .body = "Authentication is owned by the embedding SDK for this WASM session.",
                }, true);
                return;
            }
            const requested_provider = if (std.mem.trim(u8, target, " \t\r\n").len == 0)
                null
            else
                provider_catalog.parse(std.mem.trim(u8, target, " \t\r\n")) orelse {
                    try writeAuthNotice(app, .{
                        .topic = "auth",
                        .tone = .warning,
                        .body = "Usage: /logout [x1]",
                    });
                    return;
                };
            try app.flushBeforeBlockingExternalWork();
            _ = requested_provider;
            const outcome = layerx1_oauth.logout(app.alloc, app.auth.oauthTransport()) catch {
                try writeAuthNotice(app, .{
                    .topic = "auth",
                    .tone = .@"error",
                    .body = "Could not durably sign out of X1. The current source is unchanged.",
                });
                return;
            };
            const changed = if (comptime @hasDecl(@TypeOf(app.auth), "reconcileAfterLayerX1Logout"))
                try app.auth.reconcileAfterLayerX1Logout(app.alloc)
            else
                false;
            applyCredentialChange(app, changed);
            try writeAuthNotice(app, switch (outcome.deletion) {
                .deleted => .{ .topic = "auth", .tone = .neutral, .body = "Signed out of X1." },
                .missing => .{ .topic = "auth", .tone = .neutral, .body = "No X1 login session found." },
                .deleted_not_durable => .{ .topic = "auth", .tone = .warning, .body = "Signed out of X1, but could not confirm the profile directory update." },
            });
            if (outcome.revocation_failed) {
                try writeAuthNotice(app, .{
                    .topic = "auth",
                    .tone = .warning,
                    .body = "The local X1 session was removed, but remote revocation could not be confirmed.",
                });
            }
        }

        pub fn openSetupHub(app: *App) !void {
            if (comptime !runtime_profile.allows(App, .native_auth)) {
                try app.writeDomainNotice(.{
                    .topic = "auth",
                    .tone = .warning,
                    .body = "Sign-in is supplied by the embedding SDK in this WASM session.",
                }, true);
                return;
            }
            try beginLayerX1SignIn(app);
        }

        pub fn applyPickerChoice(app: *App, choice: auth_runtime.Choice) !void {
            if (comptime !oauthAuthEnabled(App)) {
                try app.writeDomainNotice(.{
                    .topic = "auth",
                    .tone = .warning,
                    .body = "Browser authentication is supplied by the embedding SDK.",
                }, true);
                return;
            }
            switch (choice) {
                .provider => |provider| try switchProvider(app, provider, true, .manual),
                .source => |source| try applySourceChoice(app, source),
                .action => |action| switch (action) {
                    .connections => unreachable,
                    .login => try beginLayerX1SignIn(app),
                    .layerx1_login => try beginLayerX1SignIn(app),
                    .setup => try beginLayerX1SignIn(app),
                    .change_team => try beginLayerX1SignIn(app),
                    .switch_credential => app.auth.openSwitchCredentialPicker(app.alloc),
                    .switch_provider => app.auth.openProviderPicker(app.alloc, provider_runtime.provider(app)),
                    .automatic => try applyAutomaticCredential(app),
                },
                .team => try beginLayerX1SignIn(app),
            }
        }

        pub fn routeAuthPickerByte(app: *App, byte: u8) !bool {
            if (app.auth.signInEntryActive()) {
                if (byte == '\t') {
                    _ = app.auth.toggleSignInCodeEntry();
                } else if (app.auth.signInCodeEntryActive()) {
                    switch (byte) {
                        3, 4 => _ = app.auth.popPickerStage(app.alloc),
                        '\r', '\n' => _ = try app.auth.submitSignInCode(app.alloc),
                        8, 127 => _ = app.auth.deleteSignInCodeByte(),
                        else => _ = try app.auth.appendSignInCodeByte(app.alloc, byte),
                    }
                } else {
                    switch (byte) {
                        3, 4 => _ = app.auth.popPickerStage(app.alloc),
                        '\r', '\n' => try openSignInBrowser(app),
                        else => {},
                    }
                }
                app.shell.render_requests.request(.footer);
                return true;
            }
            if (app.auth.teamPickerActive()) {
                const consumed = switch (byte) {
                    8, 127 => app.auth.deleteTeamQueryByte(),
                    else => try app.auth.appendTeamQueryByte(app.alloc, byte),
                };
                if (consumed) {
                    app.shell.render_requests.request(.footer);
                    return true;
                }
            }
            if (!app.auth.apiKeyEntryActive()) return false;
            switch (byte) {
                3, 4 => _ = app.auth.popPickerStage(app.alloc),
                '\r', '\n' => try submitApiKeyEntry(app),
                8, 127 => _ = app.auth.deleteApiKeyByte(),
                else => _ = try app.auth.appendApiKeyByte(app.alloc, byte),
            }
            app.shell.render_requests.request(.footer);
            return true;
        }

        pub fn routeAuthPickerEscapeAction(app: *App, action: anytype) bool {
            if (!app.auth.signInEntryActive() and !app.auth.apiKeyEntryActive()) return false;
            return switch (action) {
                .escape, .remapped_byte => false,
                .paste_start => blk: {
                    if (app.auth.signInCodeEntryActive()) break :blk false;
                    if (!app.auth.toggleSignInCodeEntry()) break :blk true;
                    app.shell.render_requests.request(.footer);
                    break :blk false;
                },
                .paste_end => !app.auth.signInCodeEntryActive(),
                else => true,
            };
        }

        pub fn collectSignInFacts(app: *App) !void {
            if (comptime !oauthAuthEnabled(App)) return;
            const sign_in_source: credentials.Source = if (comptime @hasDecl(@TypeOf(app.auth), "pickerView"))
                app.auth.pickerView().sign_in_source
            else
                .layerx1_subscription;
            app.auth.pulseSignIn(app.alloc);
            switch (app.auth.pollSignInTransition(app.alloc)) {
                .none => {},
                .cancelled => app.shell.render_requests.request(.footer),
                .failed => |err| {
                    debug_trace.logf("auth", "login failed source={t} err={s}", .{ sign_in_source, @errorName(err) });
                    _ = app.auth.popPickerStage(app.alloc);
                    try writeLoginError(app, sign_in_source, err);
                },
                .succeeded => |completed| {
                    var owned = completed;
                    defer owned.deinit(app.alloc);
                    try finishSubscriptionSignIn(app, .layerx1);
                },
            }
        }

        fn finishSubscriptionSignIn(
            app: *App,
            provider: model_provider.ProviderId,
        ) !void {
            try app.auth.refreshSourceInventory(app.alloc);
            switch (auth_transition.signInCompletion(
                provider,
                comptime provider_runtime.supported(App),
            )) {
                .switch_provider => |target| {
                    app.auth.closePicker(app.alloc);
                    try switchProvider(app, target, false, .post_oauth);
                },
                .activate_source => |source| {
                    if (!try selectCredentialSource(app, source)) {
                        _ = app.auth.popPickerStage(app.alloc);
                        try writeAuthNotice(app, .{
                            .topic = "auth",
                            .tone = .@"error",
                            .body = "Signed in, but the X1 subscription credential could not be loaded.",
                        });
                        return;
                    }
                    app.auth.closePicker(app.alloc);
                    try writeAuthNotice(app, .{
                        .topic = "auth",
                        .tone = .neutral,
                        .body = "Signed in with X1.",
                    });
                },
            }
        }

        fn prepareApiKeyInputBoundary(app: *App) void {
            if (comptime @hasDecl(App, "prepareApiKeyInputBoundary")) {
                app.prepareApiKeyInputBoundary();
            }
        }

        fn submitApiKeyEntry(app: *App) !void {
            if (app.auth.pickerView().api_key_mask_count == 0) return;
            switch (app.auth.beginApiKeySave(app.alloc)) {
                .started => app.shell.render_requests.request(.footer),
                .empty => {},
                .busy => try app.writeDomainNotice(.{
                    .topic = "auth",
                    .tone = .warning,
                    .body = "Still saving the previous API key. Nothing was stored for this one; try again in a moment.",
                }, true),
            }
        }

        /// Polled from the event loop so a save that blocks on a locked key store
        /// or a slow gateway never stalls rendering.
        pub fn collectApiKeySaveFacts(app: *App) !void {
            const result = app.auth.takeApiKeySaveResult(app.alloc) orelse return;
            try applyApiKeySaveResult(app, result);
        }

        fn applyApiKeySaveResult(app: *App, result: auth_runtime.ApiKeySaveResult) !void {
            switch (result) {
                .empty => return,
                .saved => |changed| {
                    applyCredentialChange(app, changed);
                    try app.writeDomainNotice(.{
                        .topic = "auth",
                        .tone = .warning,
                        .body = "API key setup is not available in X1. Use /login.",
                    }, true);
                },
                .gateway_refused, .gateway_unavailable => try app.writeDomainNotice(.{
                    .topic = "auth",
                    .tone = .@"error",
                    .body = "API key setup is not available in X1. Use /login.",
                }, true),
                .store_failed, .reload_failed => try app.writeDomainNotice(.{
                    .topic = "auth",
                    .tone = .warning,
                    .body = "API key setup is not available in X1. Use /login.",
                }, true),
            }
        }

        /// Clearing the remembered choice must also re-resolve, otherwise the
        /// session would keep running on a source precedence no longer selects.
        fn applyAutomaticCredential(app: *App) !void {
            forgetCredentialSource(app);
            app.auth.closePicker(app.alloc);
            applyCredentialChange(app, try app.auth.reselectByPrecedence(app.alloc));
            try app.writeDomainNotice(.{
                .topic = "auth",
                .tone = .neutral,
                .body = "Using automatic credential precedence again.",
            }, true);
        }

        fn forgetCredentialSource(app: *App) void {
            var attempt = config_runtime.attemptUserPreferences(
                app.alloc,
                .{ .clear_credential_source = true },
            );
            defer attempt.deinit(app.alloc);
            switch (attempt) {
                .outcome => debug_trace.logf("auth", "credential choice cleared", .{}),
                .failure => |failure| debug_trace.logf(
                    "auth",
                    "credential choice not cleared err={s}",
                    .{@errorName(failure.err)},
                ),
            }
        }

        fn applySourceChoice(app: *App, source: credentials.Source) !void {
            const body = try std.fmt.allocPrint(
                app.alloc,
                "Switched credential to {s}.",
                .{credentials.sourceLabel(source)},
            );
            defer app.alloc.free(body);

            if (!try selectCredentialSource(app, source)) {
                try app.writeDomainNotice(.{
                    .topic = "auth",
                    .tone = .warning,
                    .body = "That credential is no longer available. The current source is unchanged.",
                }, true);
                return;
            }

            rememberCredentialSource(app, source);
            try app.writeDomainNotice(.{
                .topic = "auth",
                .tone = .neutral,
                .body = body,
            }, true);
        }

        /// An explicit source choice outlives the session. Failing to persist
        /// leaves the source active for this run rather than refusing a working
        /// credential the user already selected.
        fn rememberCredentialSource(app: *App, source: credentials.Source) void {
            _ = app;
            _ = source;
        }

        fn beginLayerX1SignIn(app: *App) !void {
            if (comptime provider_runtime.supported(App)) {
                const decision = decideProviderSwitch(.{
                    .current = provider_runtime.provider(app),
                    .target = .layerx1,
                    .target_credential_ready = false,
                    .intent = .post_oauth,
                    .stream_active = app.stream.active,
                    .queued_prompts = app.worker.queuedPromptCount(),
                });
                if (decision == .busy) {
                    try app.writeDomainNotice(.{
                        .topic = "auth",
                        .tone = .warning,
                        .body = "X1 sign-in is unavailable until active and queued work finishes.",
                    }, true);
                    return;
                }
            }
            try app.flushBeforeBlockingExternalWork();
            const started = app.auth.openLayerX1SignInPickerFromRoot(app.alloc);
            if (started catch |err| {
                debug_trace.logf("auth", "LayerX1 login failed err={s}", .{@errorName(err)});
                try writeLoginError(app, .layerx1_subscription, err);
                return;
            }) {
                app.shell.render_requests.request(.footer);
                if (io_mod.getenv("X1_NO_OPEN_BROWSER") == null) try openSignInBrowser(app);
            }
        }

        fn beginLayerX1SignInForProviderSwitch(app: *App) !void {
            try app.flushBeforeBlockingExternalWork();
            const started = app.auth.openLayerX1SignInPickerForProviderSwitch(app.alloc);
            if (started catch |err| {
                debug_trace.logf("auth", "LayerX1 login failed err={s}", .{@errorName(err)});
                try writeLoginError(app, .layerx1_subscription, err);
                return;
            }) {
                app.shell.render_requests.request(.footer);
                if (io_mod.getenv("X1_NO_OPEN_BROWSER") == null) try openSignInBrowser(app);
            }
        }

        fn switchProvider(
            app: *App,
            target: model_provider.ProviderId,
            allow_login: bool,
            intent: ProviderSwitchIntent,
        ) !void {
            if (comptime !provider_runtime.supported(App) or
                !@hasDecl(App, "fetchProviderCatalog") or
                !@hasDecl(@TypeOf(app.model_cache), "adoptOwnedCatalog"))
            {
                try app.writeDomainNotice(.{
                    .topic = "provider",
                    .tone = .warning,
                    .body = "Provider switching is unavailable in this host.",
                }, true);
                return;
            }
            if (comptime host_target.is_wasm) {
                try app.writeDomainNotice(.{
                    .topic = "provider",
                    .tone = .warning,
                    .body = "Subscription provider switching is unavailable in this WASM session.",
                }, true);
                return;
            }

            const current = provider_runtime.provider(app);
            const active_source = app.auth.credentialSource();
            const target_credential_ready = if (active_source) |source|
                model_provider.authorizesCredential(target, source)
            else
                false;
            switch (decideProviderSwitch(.{
                .current = current,
                .target = target,
                .target_credential_ready = target_credential_ready,
                .intent = intent,
                .stream_active = app.stream.active,
                .queued_prompts = app.worker.queuedPromptCount(),
            })) {
                .prepare => {},
                .no_change => {
                    const body = try std.fmt.allocPrint(
                        app.alloc,
                        "Already using {s}.",
                        .{provider_catalog.label(target)},
                    );
                    defer app.alloc.free(body);
                    try app.writeDomainNotice(.{ .topic = "provider", .tone = .neutral, .body = body }, true);
                    return;
                },
                .busy => {
                    try app.writeDomainNotice(.{
                        .topic = "provider",
                        .tone = .warning,
                        .body = providerFailureMessage(
                            intent,
                            "Provider switching is unavailable until active and queued work finishes.",
                            "Subscription sign-in completed, but provider activation is unavailable until active and queued work finishes. The current provider is unchanged.",
                        ),
                    }, true);
                    return;
                },
            }
            try app.flushBeforeBlockingExternalWork();

            const resolution = credentials.resolveForProvider(
                app.alloc,
                app.auth.oauthTransport(),
                app.auth.secretStore(),
                .refresh_if_needed,
                target,
                null,
            ) catch |err| {
                debug_trace.logf("provider", "credential preparation failed provider={t} err={s}", .{ target, @errorName(err) });
                try app.writeDomainNotice(.{
                    .topic = "provider",
                    .tone = .@"error",
                    .body = providerFailureMessage(
                        intent,
                        "Could not prepare the target provider credential. The current provider is unchanged.",
                        "Subscription sign-in completed, but its credential could not be prepared. The current provider is unchanged.",
                    ),
                }, true);
                return;
            };
            var credential = resolution.credential orelse {
                if (allow_login) {
                    try beginLayerX1SignInForProviderSwitch(app);
                    return;
                }
                try app.writeDomainNotice(.{
                    .topic = "provider",
                    .tone = .warning,
                    .body = if (intent == .post_oauth)
                        "Subscription sign-in completed, but its saved credential is unavailable. The current provider is unchanged."
                    else
                        credentials.missing_layerx1_interactive_credential_message,
                }, true);
                return;
            };
            defer credential.deinit(app.alloc);
            if (!model_provider.authorizesCredential(target, credential.source)) {
                try app.writeDomainNotice(.{
                    .topic = "provider",
                    .tone = .@"error",
                    .body = providerFailureMessage(
                        intent,
                        "The target credential cannot authorize that provider. The current provider is unchanged.",
                        "Subscription sign-in completed, but its credential cannot authorize the provider. The current provider is unchanged.",
                    ),
                }, true);
                return;
            }

            const access = credentials.catalogAccessForCredentialAndAccount(
                credential.source,
                credential.token,
                credential.gatewayTeam(),
                credential.accountId(),
            );
            const fetched = app.fetchProviderCatalog(target, access) catch |err| {
                debug_trace.logf("provider", "catalog preparation failed provider={t} err={s}", .{ target, @errorName(err) });
                try app.writeDomainNotice(.{
                    .topic = "provider",
                    .tone = .@"error",
                    .body = providerFailureMessage(
                        intent,
                        "Could not load the target provider catalog. The current provider is unchanged.",
                        "Subscription sign-in completed, but its model catalog could not be loaded. The current provider is unchanged.",
                    ),
                }, true);
                return;
            };
            var catalog = switch (fetched) {
                .catalog => |catalog| catalog,
                .failure => |failure| {
                    debug_trace.logf("provider", "catalog rejected provider={t} category={t}", .{ target, failure.category });
                    try app.writeDomainNotice(.{
                        .topic = "provider",
                        .tone = .@"error",
                        .body = providerFailureMessage(
                            intent,
                            "The target provider catalog could not be validated. The current provider is unchanged.",
                            "Subscription sign-in completed, but its model catalog could not be validated. The current provider is unchanged.",
                        ),
                    }, true);
                    return;
                },
            };
            defer model_catalog.freeModelCatalog(app.alloc, &catalog);
            if (catalog.items.len == 0) {
                try app.writeDomainNotice(.{
                    .topic = "provider",
                    .tone = .@"error",
                    .body = providerFailureMessage(
                        intent,
                        "The target provider returned no supported models. The current provider is unchanged.",
                        "Subscription sign-in completed, but its model catalog returned no supported models. The current provider is unchanged.",
                    ),
                }, true);
                return;
            }

            var settings = config_runtime.loadMergedSettings(app.alloc, app.workspace_root) catch |err| {
                debug_trace.logf("provider", "settings load failed err={s}", .{@errorName(err)});
                try app.writeDomainNotice(.{
                    .topic = "provider",
                    .tone = .@"error",
                    .body = providerFailureMessage(
                        intent,
                        "Could not load the saved provider model. The current provider is unchanged.",
                        "Subscription sign-in completed, but its saved provider model could not be loaded. The current provider is unchanged.",
                    ),
                }, true);
                return;
            };
            defer settings.deinit(app.alloc);
            const saved_model = settings.models.get(target);
            const current_model = if (intent == .post_oauth and current == target)
                provider_runtime.model(app)
            else
                null;
            const preferred_model = if (intent == .post_oauth)
                saved_model
            else
                io_mod.getenv("X1_MODEL") orelse saved_model;
            const selected_model = selectCatalogModel(catalog.items, current_model, preferred_model) orelse unreachable;
            var owned_model = try app.alloc.dupe(u8, selected_model);
            errdefer app.alloc.free(owned_model);

            if (app.stream.active or app.worker.queuedPromptCount() > 0) {
                try app.writeDomainNotice(.{
                    .topic = "provider",
                    .tone = .warning,
                    .body = providerFailureMessage(
                        intent,
                        "Provider switching is unavailable until active and queued work finishes.",
                        "Subscription sign-in completed, but provider activation is unavailable until active and queued work finishes. The current provider is unchanged.",
                    ),
                }, true);
                return;
            }

            app.model_cache.adoptOwnedCatalog(access, &catalog);
            app.provider_selection.adoptOwned(target, &owned_model);
            _ = app.auth.adoptCredential(app.alloc, &credential);
            reconcileGatewayCredential(app);

            const body = try std.fmt.allocPrint(
                app.alloc,
                "Switched to {s} with {s}.",
                .{ provider_catalog.label(target), provider_runtime.model(app) },
            );
            defer app.alloc.free(body);
            if (comptime @hasDecl(App, "persistRuntimePreferences")) {
                var persistence = app.persistRuntimePreferences(.{
                    .provider = target,
                    .model = provider_runtime.model(app),
                });
                defer persistence.deinit(app.alloc);
                if (persistence.settings_error != null or persistence.session_error != null) {
                    debug_trace.logf(
                        "provider",
                        "runtime switch persistence failed settings={s} session={s}",
                        .{
                            if (persistence.settings_error) |err| @errorName(err) else "none",
                            if (persistence.session_error) |err| @errorName(err) else "none",
                        },
                    );
                    try app.writeDomainNotice(.{
                        .topic = "provider",
                        .tone = .warning,
                        .body = "Provider switched for this run, but the selection could not be saved.",
                    }, true);
                } else {
                    try app.writeDomainNotice(.{ .topic = "provider", .tone = .neutral, .body = body }, true);
                }
            } else {
                var persistence = config_runtime.attemptUserPreferences(app.alloc, .{
                    .provider = target,
                    .model_preference = .{
                        .provider = target,
                        .model = provider_runtime.model(app),
                    },
                });
                defer persistence.deinit(app.alloc);
                switch (persistence) {
                    .outcome => try app.writeDomainNotice(.{ .topic = "provider", .tone = .neutral, .body = body }, true),
                    .failure => |failure| {
                        debug_trace.logf("provider", "runtime switch persistence failed err={s}", .{@errorName(failure.err)});
                        try app.writeDomainNotice(.{
                            .topic = "provider",
                            .tone = .warning,
                            .body = "Provider switched for this run, but the selection could not be saved.",
                        }, true);
                    },
                }
            }
            app.shell.render_requests.request(.footer);
        }

        fn beginSignIn(app: *App, from_root: bool) !void {
            try app.flushBeforeBlockingExternalWork();

            const started = if (from_root)
                app.auth.openSignInPickerFromRoot(app.alloc)
            else
                app.auth.openSignInPicker(app.alloc);
            if (started catch |err| {
                debug_trace.logf("auth", "login failed err={s}", .{@errorName(err)});
                try writeLoginError(app, .layerx1_subscription, err);
                return;
            }) {
                app.shell.render_requests.request(.footer);
                // Open the browser as soon as the device code is ready instead of
                // waiting for Enter; Enter stays as a manual re-open, and
                // X1_NO_OPEN_BROWSER opts out for headless/SSH sessions.
                if (io_mod.getenv("X1_NO_OPEN_BROWSER") == null) try openSignInBrowser(app);
            }
        }

        fn openSignInBrowser(app: *App) !void {
            const url = (try app.auth.signInBrowserUrlAlloc(app.alloc)) orelse return;
            defer app.alloc.free(url);
            if (!try app.urlOpener().open(app.alloc, url)) {
                debug_trace.logf("auth", "login browser launcher failed", .{});
            }
        }

        pub fn selectCredentialSource(app: *App, source: credentials.Source) !bool {
            const changed = (try app.auth.selectSource(app.alloc, source)) orelse return false;
            applyCredentialChange(app, changed);
            return true;
        }

        fn refreshx1LoginCredentialIfNeeded(app: *App) !void {
            if (!try app.auth.refreshx1LoginIfNeeded(app.alloc)) return;
            reconcileGatewayCredential(app);
            if (app.auth.modelCatalogAccess().authorizationCredential() == null) return;
            app.model_cache.reset();
            if (comptime @hasDecl(App, "startModelCacheWarmup")) {
                app.startModelCacheWarmup();
            }
        }

        pub fn admitPromptCredential(app: *App) !bool {
            if (comptime !oauthAuthEnabled(App)) {
                if (app.auth.apiKey() != null) return true;
                try app.writeDomainNotice(.{
                    .topic = "auth",
                    .tone = .warning,
                    .body = "Missing X1_API_KEY. Supply it through createX1Terminal().",
                }, true);
                return false;
            }
            if (!try ensurePromptCredential(app)) return false;
            return preparePromptCredential(app);
        }

        fn preparePromptCredential(app: *App) !bool {
            for (0..2) |_| {
                refreshx1LoginCredentialIfNeeded(app) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    else => return recoverPromptCredentialRefreshFailure(app, err),
                };
                if (app.auth.gatewayCredential() != null) return true;
            }
            return recoverPromptCredentialRefreshFailure(app, error.CredentialRefreshUnavailable);
        }

        fn recoverPromptCredentialRefreshFailure(app: *App, err: anyerror) !bool {
            const active_source = app.auth.credentialSource();
            const source = if (active_source) |active|
                if (credentials.sourceRefreshable(active)) active else .layerx1_subscription
            else
                .layerx1_subscription;
            return recoverCredentialFailure(app, source, err);
        }

        fn recoverCredentialFailure(app: *App, source: credentials.Source, err: anyerror) !bool {
            debug_trace.logf("auth", "prompt credential refresh failed source={t} err={s}", .{ source, @errorName(err) });
            if (app.auth.credentialSource() == source) app.auth.recordCredentialRefreshFailure(source);
            try app.auth.refreshSourceInventory(app.alloc);
            app.auth.openPickerForProvider(app.alloc, provider_runtime.provider(app));
            const failure = auth_runtime.FailureSnapshot{
                .source = source,
                .reason = .credential_refresh_failed,
            };
            const failure_text = try failure.renderText(app.alloc);
            defer app.alloc.free(failure_text);
            const recovery = try std.fmt.allocPrint(
                app.alloc,
                "{s}.\nRun /login to reconnect.",
                .{failure_text},
            );
            defer app.alloc.free(recovery);
            try app.writeDomainNotice(.{
                .topic = "auth",
                .tone = .@"error",
                .body = recovery,
            }, true);
            app.shell.render_requests.request(.footer);
            return false;
        }

        fn applyCredentialChange(app: *App, changed: bool) void {
            if (!changed) return;
            reconcileGatewayCredential(app);
            app.model_cache.reset();
            if (comptime @hasDecl(App, "startModelCacheWarmup")) {
                app.startModelCacheWarmup();
            }
        }

        fn reconcileGatewayCredential(app: *App) void {
            if (comptime !runtime_profile.allows(App, .generation_usage)) return;
            if (comptime @hasField(App, "session") and
                @hasField(@TypeOf(app.session), "usage"))
            {
                if (app.auth.gatewayCredential()) |credential| {
                    const subscription = if (comptime @hasField(@TypeOf(credential), "source"))
                        credential.source == .layerx1_subscription
                    else
                        false;
                    if (subscription) {
                        app.session.usage.clearReconciliationCredential();
                    } else {
                        if (comptime @hasDecl(
                            @TypeOf(app.session.usage),
                            "replaceProviderReconciliationCredential",
                        )) {
                            app.session.usage.replaceProviderReconciliationCredential(
                                app.alloc,
                                .layerx1,
                                credential.source,
                                null,
                                credential.api_key,
                            );
                        } else {
                            app.session.usage.replaceReconciliationCredential(
                                app.alloc,
                                credential.api_key,
                            );
                        }
                    }
                } else {
                    app.session.usage.clearReconciliationCredential();
                }
            }
        }

        fn writeLoginError(app: *App, source: credentials.Source, err: anyerror) !void {
            _ = source;
            const notice: types.SemanticNotice = switch (err) {
                error.LayerX1AuthorizationFailed => .{ .topic = "auth", .tone = .@"error", .body = "X1 sign-in was denied. The current credential is unchanged." },
                error.LayerX1LoginTimedOut, error.LoginTimedOut => .{ .topic = "auth", .tone = .warning, .body = "X1 sign-in expired. The current credential is unchanged; run /login to try again." },
                else => .{ .topic = "auth", .tone = .@"error", .body = "X1 sign-in failed. The current credential is unchanged." },
            };
            try writeAuthNotice(app, notice);
        }

        fn writeAuthNotice(app: *App, notice: types.SemanticNotice) !void {
            try app.writeDomainNotice(notice, true);
            app.shell.render_requests.request(.first_frame);
            try app.flushBeforeBlockingExternalWork();
        }
    };
}

test "X1 catalog selection keeps the saved model when available" {
    const entries = [_]model_catalog.ModelCatalogEntry{
        .{ .id = @constCast("x1/model-a"), .model_type = @constCast("language") },
        .{ .id = @constCast("x1/model-b"), .model_type = @constCast("language") },
    };
    try std.testing.expectEqualStrings(
        "x1/model-b",
        selectCatalogModel(&entries, "x1/model-b", null).?,
    );
}

test "X1 provider switch no-ops when the active credential is ready" {
    try std.testing.expectEqual(
        ProviderSwitchDecision.no_change,
        decideProviderSwitch(.{
            .current = .layerx1,
            .target = .layerx1,
            .target_credential_ready = true,
            .intent = .manual,
            .stream_active = false,
            .queued_prompts = 0,
        }),
    );
}
