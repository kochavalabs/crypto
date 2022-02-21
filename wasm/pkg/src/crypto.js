import * as wasmBase64Bytes from "../crypto.wasm"
require('../wasm_exec.js')

const go = new Go(); // Defined in wasm_exec.js

var bytes = Buffer.from(wasmBase64Bytes, 'base64');
export async function NewCrypto() {
    const wasmInstanceSource = await WebAssembly.instantiate(bytes , go.importObject);
    const wasmInstance = wasmInstanceSource.instance;
    // wasm = wasmInstance.exports;
	go.run(wasmInstance);
	return New()
}