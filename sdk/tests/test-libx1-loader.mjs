#!/usr/bin/env node
import { strict as assert } from "node:assert";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  createX1Agent,
  createX1Terminal,
  x1SdkApiVersion,
  libx1ApiVersion,
} from "../node.js";
import * as browser from "../browser.js";

assert.equal(libx1ApiVersion, 2);
assert.equal(x1SdkApiVersion, 1);
assert.equal(browser.libx1ApiVersion, 2);
assert.equal(typeof browser.createX1Agent, "function");
assert.equal(typeof browser.createX1Terminal, "function");

const dir = await mkdtemp(resolve(tmpdir(), "libx1-loader-"));
const nativePath = resolve(dir, "native.mjs");
await writeFile(nativePath, `
  export async function createX1Agent(options) { return { backend: "native-agent", options }; }
  export async function createX1Terminal(options) { return { backend: "native-terminal", options }; }
`);
const nativeUrl = pathToFileURL(nativePath);

for (const gatewayChatUrl of [
  "http://attacker.example/chat",
  "https://[redacted]@example.com/chat",
  "https://example.com/chat",
  "file:///tmp/socket",
]) {
  await assert.rejects(
    createX1Agent({ nativeAddon: nativeUrl, env: { X1_GATEWAY_CHAT_URL: gatewayChatUrl } }),
    TypeError,
  );
}

const agent = await createX1Agent({ nativeAddon: nativeUrl, marker: 1 });
assert.equal(agent.backend, "native-agent");
assert.equal(agent.options.marker, 1);
assert.equal("nativeAddon" in agent.options, false);
assert.equal("backend" in agent.options, false);

const terminal = await createX1Terminal({ nativeAddon: nativeUrl, marker: 2 });
assert.equal(terminal.backend, "native-terminal");
assert.equal(terminal.options.marker, 2);

await assert.rejects(
  createX1Agent({ nativeAddon: nativeUrl, backend: "wasm" }),
  (error) => error?.code === "LIBX1_JSPI_REQUIRED" &&
    error.message.includes("--experimental-wasm-jspi"),
);

const coreOnlyPath = resolve(dir, "core-only.mjs");
await writeFile(coreOnlyPath, `
  export const libx1ApiVersion = 2;
  export async function createX1Agent() { return { backend: "core-only" }; }
`);
await assert.rejects(
  createX1Terminal({ nativeAddon: pathToFileURL(coreOnlyPath), backend: "native" }),
  (error) => error?.code === "LIBX1_NATIVE_UNAVAILABLE" &&
    error.message.includes("createX1Terminal"),
);

const incompatiblePath = resolve(dir, "incompatible.mjs");
await writeFile(incompatiblePath, `
  export const libx1ApiVersion = 3;
  export async function createX1Agent() {}
`);
await assert.rejects(
  createX1Agent({ nativeAddon: pathToFileURL(incompatiblePath), backend: "native" }),
  (error) => error?.code === "LIBX1_NATIVE_UNAVAILABLE" &&
    error.message.includes("incompatible"),
);

for (const [name, source] of [
  ["missing-version", `
    export function createCore() { throw new Error("missing-version createCore invoked"); }
  `],
  ["unequal-version", `
    export const libx1ApiVersion = 3;
    export function createCore() { throw new Error("unequal-version createCore invoked"); }
  `],
]) {
  const modulePath = resolve(dir, `${name}.mjs`);
  await writeFile(modulePath, source);
  await assert.rejects(
    createX1Agent({ nativeAddon: pathToFileURL(modulePath), backend: "native" }),
    (error) => error?.code === "LIBX1_NATIVE_UNAVAILABLE" &&
      error.message.includes("incompatible") &&
      !String(error.cause).includes("createCore invoked"),
    `${name} low-level addon must fail before createCore invocation`,
  );
}

const matchingVersionPath = resolve(dir, "matching-version.mjs");
await writeFile(matchingVersionPath, `
  export const libx1ApiVersion = 2;
  export function createCore() {
    const error = new Error("matching-version createCore invoked");
    error.code = "MATCHING_VERSION_INVOKED";
    throw error;
  }
`);
await assert.rejects(
  createX1Agent({ nativeAddon: pathToFileURL(matchingVersionPath), backend: "native" }),
  (error) => error?.code === "MATCHING_VERSION_INVOKED",
  "matching v2 low-level addon must reach createCore",
);

console.log("libx1 loader passed: browser exports, native preference, fallback diagnostics, and strict low-level API validation");
