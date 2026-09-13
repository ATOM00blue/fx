import { describe, expect, test } from "bun:test";
import { buildEvalProcessEnv, shouldLoadDotEnv } from "./eval-helpers";

describe("eval helpers", () => {
  test("passes the selected eval model to x1 through X1_MODEL", () => {
    const previous = process.env.X1_MODEL;
    process.env.X1_MODEL = "ambient/model";

    try {
      const env = buildEvalProcessEnv("/tmp/x1-eval-home-test", "selected/model");

      expect(env.X1_MODEL).toBe("selected/model");
      expect(env.HOME).toBe("/tmp/x1-eval-home-test");
      expect(env.NO_COLOR).toBe("1");
    } finally {
      if (previous === undefined) {
        delete process.env.X1_MODEL;
      } else {
        process.env.X1_MODEL = previous;
      }
    }
  });

  test("does not load repository dotenv files in a hermetic run", () => {
    expect(shouldLoadDotEnv({ X1_E2E_DISABLE_DOTENV: "1" })).toBe(false);
    expect(shouldLoadDotEnv({})).toBe(true);
  });
});
