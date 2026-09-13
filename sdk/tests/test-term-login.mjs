#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createX1Terminal, supportsJspi } from "../node.js";
import { responsesTextSse } from "./responses-sse.mjs";

const scriptDir = fileURLToPath(new URL(".", import.meta.url));
const defaultWasm = resolve(scriptDir, "../../zig-out/bin/x1-term.wasm");
const wasmPath = resolve(process.argv[2] || defaultWasm);

if (!supportsJspi()) {
  console.error("Node JSPI is disabled. Run with: node --experimental-wasm-jspi sdk/scripts/test-term-login.mjs");
  process.exit(2);
}

const wasm = await readFile(wasmPath);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const accessToken = "term-login-access-token-sentinel";
const gatewayRequests = [];
const openedUrls = [];

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function sseResponse(label) {
  return new Response(responsesTextSse([label]), {
    status: 200,
    headers: { "content-type": "text/event-stream" },
  });
}

const stubFetch = async (input, init = {}) => {
  const url = new URL(String(input));
  const method = init.method || "GET";
  const headers = new Headers(init.headers);
  if (url.pathname.endsWith("/v1/models")) {
    return json({
      object: "list",
      data: [{
        id: "stub/login-model",
        tier: "language",
        capabilities: { tools: true },
      }],
    });
  }
  if (method === "POST" && url.pathname.endsWith("/v1/responses")) {
    gatewayRequests.push({ authorization: headers.get("authorization") });
    return sseResponse(`LOGIN_GATEWAY_OK_${gatewayRequests.length}`);
  }
  throw new Error(`unexpected stub request: ${method} ${url.origin}${url.pathname}`);
};

function createTerminalCapture() {
  let transcript = "";
  let trace = "";
  const events = [];
  return {
    terminal: {
      cols: 90,
      rows: 28,
      write(value) {
        const chunk = value instanceof Uint8Array ? value : encoder.encode(value);
        transcript += decoder.decode(chunk, { stream: true });
      },
      async drain() {},
      onData() { return () => {}; },
      onResize() { return () => {}; },
    },
    stderr(value) {
      const chunk = value instanceof Uint8Array ? value : encoder.encode(value);
      trace += decoder.decode(chunk, { stream: true });
    },
    event(event) { events.push(event); },
    transcript() { return transcript; },
    trace() { return trace; },
    events,
  };
}

async function waitFor(predicate, label, diagnostics = () => "") {
  const deadline = performance.now() + 15000;
  while (!predicate()) {
    if (performance.now() >= deadline) throw new Error(`timed out waiting for ${label}: ${diagnostics()}`);
    await new Promise((resolveWait) => setTimeout(resolveWait, 10));
  }
}

async function start(env = {}) {
  const capture = createTerminalCapture();
  const runtime = await createX1Terminal({
    backend: "wasm",
    wasm,
    terminal: capture.terminal,
    env: { X1_THEME: "dark", X1_TRACE_STDERR: "1", X1_TRACE_SCOPES: "auth", ...env },
    fetch: stubFetch,
    openUrl(url) { openedUrls.push(url); return true; },
    onEvent: capture.event,
    stderr: capture.stderr,
  });
  await waitFor(
    () => capture.transcript().includes("layerx1.com"),
    "x1-term startup",
    () => JSON.stringify(capture.transcript().slice(-1000)),
  );
  return { capture, runtime };
}

async function exit(runtime, label) {
  runtime.write("\x15/exit\r");
  const code = await Promise.race([
    runtime.exited,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`timed out waiting for ${label} exit`)), 5000)),
  ]);
  if (code !== 0) throw new Error(`${label} exited with code ${code}`);
}

const first = await start({ X1_API_KEY: accessToken });
first.runtime.write("/login\r");
await waitFor(
  () => first.capture.transcript().includes("X1_API_KEY"),
  "WASM login tells the host to set X1_API_KEY",
  () => JSON.stringify(first.capture.transcript().slice(-1500)),
);
if (openedUrls.length !== 0) throw new Error("WASM /login must not open a browser OAuth loopback");

first.runtime.write("first authenticated prompt\r");
await waitFor(
  () => gatewayRequests.length === 1,
  "first authenticated LayerX1 response",
  () => JSON.stringify(first.capture.transcript().slice(-1500)),
);
if (gatewayRequests[0]?.authorization !== `Bearer ${accessToken}`) {
  throw new Error("gateway did not receive the X1_API_KEY bearer credential");
}
await exit(first.runtime, "first terminal");

const second = await start();
second.runtime.write("unauthenticated prompt\r");
await waitFor(
  () => second.capture.transcript().includes("/login") || second.capture.transcript().includes("X1_API_KEY"),
  "unauthenticated prompt leads to login help",
  () => JSON.stringify(second.capture.transcript().slice(-1500)),
);
if (gatewayRequests.length !== 1) throw new Error("unauthenticated WASM prompt must not call LayerX1 inference");
await exit(second.runtime, "second terminal");

console.log("term login passed: wasm_login_help=true, no_oauth_loopback=true, x1_api_key_bearer=true, unauthenticated_prompt_asks_login=true");
