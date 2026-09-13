import {
  createX1Agent as createWasmAgent,
  createX1Terminal as createWasmTerminal,
  encodeXtermKeyEvent,
  x1SdkApiVersion,
  supportsJspi,
  xtermAdapter,
} from "./x1-sdk.js";

export { encodeXtermKeyEvent, x1SdkApiVersion, supportsJspi, xtermAdapter };
export const libx1ApiVersion = 2;

const defaultCoreWasm = new URL("./x1-core.wasm", import.meta.url).href;
const defaultTermWasm = new URL("./x1-term.wasm", import.meta.url).href;

export function createX1Agent(options = {}) {
  return createWasmAgent({ ...options, wasm: options.wasm ?? defaultCoreWasm });
}

export function createX1Terminal(options = {}) {
  return createWasmTerminal({ ...options, wasm: options.wasm ?? defaultTermWasm });
}
