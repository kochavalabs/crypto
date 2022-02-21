import * as wasmBase64Bytes from "../crypto.wasm"
require('../wasm_exec.js')

// CUSTOM INITIALIZATION START
const go = new Go(); // Defined in wasm_exec.js

function _base64ToArrayBuffer(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

const bytes = _base64ToArrayBuffer(wasmBase64Bytes);
export async function NewCrypto() {
    const wasmInstanceSource = await WebAssembly.instantiate(bytes , go.importObject);
    const wasmInstance = wasmInstanceSource.instance;
    // wasm = wasmInstance.exports;
	go.run(wasmInstance);
	return New()
}
// CUSTOM INITIALIZATION END
