import { expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runx1 } from "../evals/eval-helpers";

const TIMEOUT = 30_000;
const OAUTH_SERVICE = "X1_OAUTH_SESSION_V1";

test(
  "legacy FX auth.json and OAuth keychain names are never migrated into LayerX1 auth",
  async () => {
    const home = mkdtempSync(join(tmpdir(), "x1-oauth-keychain-not-migrated-"));
    try {
      const x1Dir = join(home, ".x1");
      mkdirSync(x1Dir, { recursive: true, mode: 0o700 });
      chmodSync(x1Dir, 0o700);
      const authPath = join(x1Dir, "auth.json");
      writeFileSync(
        authPath,
        JSON.stringify({
          version: 1,
          issuer: "https://vercel.com",
          client_id: "test-client",
          access_token: "legacy-fx-access",
          refresh_token: "legacy-fx-refresh",
          expires_at_ms: Date.now() + 60 * 60 * 1000,
          scope: "openid offline_access use:ai-gateway",
          token_type: "Bearer",
        }) + "\n",
        { mode: 0o600 },
      );
      chmodSync(authPath, 0o600);

      const status = await runx1(["status", "--json"], {
        env: {
          HOME: home,
          X1_DISABLE_KEYCHAIN: "0",
          X1_SKIP_ONBOARDING: "1",
        },
      });
      expect(status.code).toBe(0);
      const json = JSON.parse(status.stdout);
      expect(json.auth).toBe("missing");
      expect(json.auth_help).toContain("x1 login");
      expect(existsSync(join(x1Dir, "layerx1-auth.json"))).toBe(false);
      expect(readFileSync(authPath, "utf8")).toContain("legacy-fx-access");
      expect(status.stdout).not.toContain("legacy-fx-access");
      expect(status.stdout).not.toContain(OAUTH_SERVICE);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  },
  TIMEOUT,
);
