import { expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runx1, writeLayerX1Auth } from "../evals/eval-helpers";
import {
  FAKE_GATEWAY_MODEL,
  fakeGatewayFinalText,
  startFakeGateway,
} from "./tmux-helpers";

const TIMEOUT = 30_000;
const ACCOUNT_ID = "acct_e2e";

function startLayerX1Refresh(options: {
  accessTokens: string[];
  userinfoSub?: string;
  revokeStatus?: number;
}) {
  const requests: Array<{ method: string; path: string; body: string }> = [];
  let tokenIndex = 0;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      const body = await request.text();
      requests.push({ method: request.method, path: url.pathname, body });
      if (url.pathname === "/oauth2/token") {
        const form = new URLSearchParams(body);
        if (form.get("grant_type") !== "refresh_token") {
          return new Response("unexpected grant", { status: 400 });
        }
        if (form.get("client_id") !== "layerx1-cli-oauth") {
          return new Response("unexpected client", { status: 400 });
        }
        const accessToken = options.accessTokens[tokenIndex++];
        if (!accessToken) return new Response("unexpected refresh", { status: 500 });
        return Response.json({
          access_token: accessToken,
          refresh_token: `rotated-${accessToken}`,
          expires_in: 3600,
          token_type: "Bearer",
        });
      }
      if (url.pathname === "/oauth2/userinfo") {
        return Response.json({
          sub: options.userinfoSub ?? ACCOUNT_ID,
          customer_id: options.userinfoSub ?? ACCOUNT_ID,
          plan: "pro",
        });
      }
      if (url.pathname === "/oauth2/revoke") {
        return new Response(null, { status: options.revokeStatus ?? 200 });
      }
      return new Response("not found", { status: 404 });
    },
  });
  const baseUrl = `http://127.0.0.1:${server.port}`;
  return {
    requests,
    tokenUrl: `${baseUrl}/oauth2/token`,
    userinfoUrl: `${baseUrl}/oauth2/userinfo`,
    revokeUrl: `${baseUrl}/oauth2/revoke`,
    stop() {
      server.stop(true);
    },
  };
}

test(
  "x1 ask refreshes an expired LayerX1 session then retries inference",
  async () => {
    const home = mkdtempSync(join(tmpdir(), "x1-layerx1-refresh-"));
    const oauth = startLayerX1Refresh({ accessTokens: ["refreshed-access-token"] });
    writeLayerX1Auth(home, {
      accessToken: "expired-access-token",
      refreshToken: "seeded-refresh-token",
      accountId: ACCOUNT_ID,
      expiresAtMs: Date.now() - 60_000,
    });
    const gateway = startFakeGateway([
      fakeGatewayFinalText("REFRESHED_LAYERX1_RESPONSE"),
    ]);
    try {
      const result = await runx1(
        ["ask", "--json", "--no-save", "exercise the refreshed login"],
        {
          env: {
            HOME: home,
            X1_DISABLE_KEYCHAIN: "1",
            X1_SKIP_ONBOARDING: "1",
            X1_AUTO_UPGRADE: "0",
            X1_E2E_LAYERX1_TOKEN_URL: oauth.tokenUrl,
            X1_E2E_LAYERX1_USERINFO_URL: oauth.userinfoUrl,
            X1_GATEWAY_CHAT_URL: gateway.chatUrl,
            X1_MODEL: FAKE_GATEWAY_MODEL,
          },
          timeoutMs: TIMEOUT,
        },
      );
      expect(result.code, `stdout: ${result.stdout}\nstderr: ${result.stderr}`).toBe(0);
      expect(JSON.parse(result.stdout).output).toContain("REFRESHED_LAYERX1_RESPONSE");
      const token = oauth.requests.find((request) => request.path === "/oauth2/token");
      expect(token?.body).toContain("grant_type=refresh_token");
      expect(token?.body).toContain("client_id=layerx1-cli-oauth");
      expect(token?.body).toContain("refresh_token=seeded-refresh-token");
      expect(gateway.requests[0]!.headers.get("authorization")).toBe(
        "Bearer refreshed-access-token",
      );
      const saved = JSON.parse(readFileSync(join(home, ".x1", "layerx1-auth.json"), "utf8")) as {
        access_token: string;
        refresh_token: string;
        account_id: string;
      };
      expect(saved.access_token).toBe("refreshed-access-token");
      expect(saved.refresh_token).toBe("rotated-refreshed-access-token");
      expect(saved.account_id).toBe(ACCOUNT_ID);
    } finally {
      gateway.stop();
      oauth.stop();
      rmSync(home, { recursive: true, force: true });
    }
  },
  TIMEOUT,
);

test(
  "LayerX1 refresh keeps the stored session when userinfo sub does not match",
  async () => {
    const home = mkdtempSync(join(tmpdir(), "x1-layerx1-refresh-mismatch-"));
    const oauth = startLayerX1Refresh({
      accessTokens: ["mismatched-access-token"],
      userinfoSub: "acct_other",
    });
    writeLayerX1Auth(home, {
      accessToken: "expired-access-token",
      refreshToken: "seeded-refresh-token",
      accountId: ACCOUNT_ID,
      expiresAtMs: Date.now() - 60_000,
    });
    const gateway = startFakeGateway([fakeGatewayFinalText("should-not-run")]);
    try {
      const result = await runx1(
        ["ask", "--json", "--no-save", "do not switch accounts"],
        {
          env: {
            HOME: home,
            X1_DISABLE_KEYCHAIN: "1",
            X1_SKIP_ONBOARDING: "1",
            X1_AUTO_UPGRADE: "0",
            X1_E2E_LAYERX1_TOKEN_URL: oauth.tokenUrl,
            X1_E2E_LAYERX1_USERINFO_URL: oauth.userinfoUrl,
            X1_GATEWAY_CHAT_URL: gateway.chatUrl,
            X1_MODEL: FAKE_GATEWAY_MODEL,
          },
          timeoutMs: TIMEOUT,
        },
      );
      expect(result.code).not.toBe(0);
      expect(gateway.requests).toHaveLength(0);
      const saved = JSON.parse(readFileSync(join(home, ".x1", "layerx1-auth.json"), "utf8")) as {
        access_token: string;
        account_id: string;
      };
      expect(saved.access_token).toBe("expired-access-token");
      expect(saved.account_id).toBe(ACCOUNT_ID);
    } finally {
      gateway.stop();
      oauth.stop();
      rmSync(home, { recursive: true, force: true });
    }
  },
  TIMEOUT,
);

test(
  "logout after a successful refresh revokes the rotated token",
  async () => {
    const home = mkdtempSync(join(tmpdir(), "x1-layerx1-refresh-logout-"));
    const oauth = startLayerX1Refresh({ accessTokens: ["refreshed-access-token"] });
    writeLayerX1Auth(home, {
      accessToken: "expired-access-token",
      refreshToken: "seeded-refresh-token",
      accountId: ACCOUNT_ID,
      expiresAtMs: Date.now() - 60_000,
    });
    const gateway = startFakeGateway([fakeGatewayFinalText("before logout")]);
    try {
      const ask = await runx1(["ask", "--json", "--no-save", "refresh then logout"], {
        env: {
          HOME: home,
          X1_DISABLE_KEYCHAIN: "1",
          X1_SKIP_ONBOARDING: "1",
          X1_AUTO_UPGRADE: "0",
          X1_E2E_LAYERX1_TOKEN_URL: oauth.tokenUrl,
          X1_E2E_LAYERX1_USERINFO_URL: oauth.userinfoUrl,
          X1_GATEWAY_CHAT_URL: gateway.chatUrl,
          X1_MODEL: FAKE_GATEWAY_MODEL,
        },
        timeoutMs: TIMEOUT,
      });
      expect(ask.code).toBe(0);
      const logout = await runx1(["logout"], {
        env: {
          HOME: home,
          X1_DISABLE_KEYCHAIN: "1",
          X1_E2E_LAYERX1_REVOKE_URL: oauth.revokeUrl,
        },
      });
      expect(logout.code).toBe(0);
      expect(logout.stdout).toContain("Signed out of X1.");
      expect(existsSync(join(home, ".x1", "layerx1-auth.json"))).toBe(false);
      expect(oauth.requests.some((request) => request.path === "/oauth2/revoke")).toBe(true);
    } finally {
      gateway.stop();
      oauth.stop();
      rmSync(home, { recursive: true, force: true });
    }
  },
  TIMEOUT,
);
