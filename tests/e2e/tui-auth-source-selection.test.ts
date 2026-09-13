import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runx1, writeLayerX1Auth } from "../evals/eval-helpers";
import {
  FAKE_GATEWAY_MODEL,
  fakeGatewayFinalText,
  startFakeGateway,
  TmuxSession,
  tmuxAvailable,
} from "./tmux-helpers";

const SKIP = !tmuxAvailable();
const TIMEOUT = 30_000;

let session: TmuxSession | null = null;
const tempDirs: string[] = [];

afterEach(async () => {
  if (session) {
    await session.kill();
    session = null;
  }
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function isolatedHome(prefix: string): string {
  const home = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  tempDirs.push(home);
  return home;
}

describe.skipIf(SKIP)("tui: LayerX1 login is the only account path", () => {
  test(
    "/login opens LayerX1 sign-in and never offers ChatGPT, Grok, or API keys",
    async () => {
      const home = isolatedHome("x1-tui-layerx1-login-");
      session = await TmuxSession.create({
        env: {
          HOME: home,
          X1_AUTO_UPGRADE: "0",
          X1_DISABLE_KEYCHAIN: "1",
          X1_NO_OPEN_BROWSER: "1",
          X1_SKIP_ONBOARDING: "1",
        },
      });
      await session.waitForComposer(TIMEOUT);
      await session.sendText("/login");
      const pane = await session.waitForText("Sign in with X1", TIMEOUT);
      expect(pane).toContain("Open");
      expect(pane).not.toContain("ChatGPT");
      expect(pane).not.toContain("Grok");
      expect(pane).not.toContain("Add an API key");
      expect(pane).not.toContain("Vercel team");
      expect(existsSync(join(home, ".x1", "chatgpt-auth.json"))).toBe(false);
      expect(existsSync(join(home, ".x1", "grok-auth.json"))).toBe(false);
    },
    TIMEOUT,
  );

  test(
    "an unauthenticated prompt points the user to /login",
    async () => {
      const home = isolatedHome("x1-tui-unauthenticated-prompt-");
      session = await TmuxSession.create({
        env: {
          HOME: home,
          X1_AUTO_UPGRADE: "0",
          X1_DISABLE_KEYCHAIN: "1",
          X1_SKIP_ONBOARDING: "1",
        },
      });
      await session.waitForComposer(TIMEOUT);
      await session.sendText("hello without a LayerX1 login");
      const pane = await session.waitForPane(
        (text) => text.includes("/login") || text.includes("Sign in with X1"),
        TIMEOUT,
      );
      expect(pane).toMatch(/\/login|Sign in with X1/);
      expect(pane).not.toContain("AI_GATEWAY_API_KEY");
    },
    TIMEOUT,
  );

  test(
    "a seeded LayerX1 session can ask through the live catalog fake",
    async () => {
      const home = isolatedHome("x1-tui-seeded-layerx1-");
      writeLayerX1Auth(home);
      const gateway = startFakeGateway([fakeGatewayFinalText("LAYERX1_SEEDED_OK")]);
      try {
        session = await TmuxSession.create({
          env: {
            HOME: home,
            X1_AUTO_UPGRADE: "0",
            X1_DISABLE_KEYCHAIN: "1",
            X1_SKIP_ONBOARDING: "1",
            X1_GATEWAY_CHAT_URL: gateway.chatUrl,
            X1_GATEWAY_MODELS_URL: gateway.modelsUrl,
            X1_MODEL: FAKE_GATEWAY_MODEL,
          },
        });
        await session.waitForComposer(TIMEOUT);
        await session.sendText("Say exactly: LAYERX1_SEEDED_OK");
        const pane = await session.waitForText("LAYERX1_SEEDED_OK", TIMEOUT);
        expect(pane).toContain("LAYERX1_SEEDED_OK");
      } finally {
        gateway.stop();
      }
    },
    TIMEOUT,
  );
});

describe("cli: LayerX1 login aliases", () => {
  test(
    "login and logout reject ChatGPT and Grok aliases",
    async () => {
      const home = isolatedHome("x1-cli-unknown-login-");
      const login = await runx1(["login", "chatgpt"], {
        env: { HOME: home, X1_DISABLE_KEYCHAIN: "1" },
      });
      expect(login.code).toBe(1);
      expect(login.stderr).toContain("usage: x1 login [x1]");

      const logout = await runx1(["logout", "grok"], {
        env: { HOME: home, X1_DISABLE_KEYCHAIN: "1" },
      });
      expect(logout.code).toBe(1);
      expect(logout.stderr).toContain("usage: x1 logout [x1]");
    },
    TIMEOUT,
  );

  test(
    "legacy FX auth.json is not treated as a LayerX1 session",
    async () => {
      const home = isolatedHome("x1-cli-legacy-fx-auth-");
      const x1Dir = join(home, ".x1");
      mkdirSync(x1Dir, { recursive: true, mode: 0o700 });
      writeFileSync(
        join(x1Dir, "auth.json"),
        JSON.stringify({
          version: 1,
          issuer: "https://vercel.com",
          access_token: "legacy-fx-token",
          refresh_token: "legacy-fx-refresh",
          expires_at_ms: Date.now() + 60_000,
        }) + "\n",
        { mode: 0o600 },
      );
      const status = await runx1(["status", "--json"], {
        env: { HOME: home, X1_DISABLE_KEYCHAIN: "1" },
      });
      expect(status.code).toBe(0);
      const json = JSON.parse(status.stdout);
      expect(json.auth).toBe("missing");
      expect(json.auth_help).toContain("x1 login");
      expect(existsSync(join(home, ".x1", "layerx1-auth.json"))).toBe(false);
      expect(readFileSync(join(x1Dir, "auth.json"), "utf8")).toContain("legacy-fx-token");
    },
    TIMEOUT,
  );
});
