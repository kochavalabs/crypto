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
async function init() {
    const wasmInstanceSource = await WebAssembly.instantiate(bytes , go.importObject);
    const wasmInstance = wasmInstanceSource.instance;
    // wasm = wasmInstance.exports;
	go.run(wasmInstance);
	return 'done'
}
// CUSTOM INITIALIZATION END

// Return a function that calls the given WebAssembly Module function
// and throws an error if the result of the WebAssembly function contains
// an error field
function wrapError(func) {
	return function (args) {
		const result = func(args)
		if ((result != null) && ('error' in result)) {
			throw result.error
		}
		return result
	}
}

export class Crypto {
	constructor (async_param) {
        if (typeof async_param === 'undefined') {
            throw new Error('Cannot be called directly');
        }
    }

    static async build () {
        var async_result = await init();
        return new Crypto(async_result);
    }

	GenerateEd25519KeyPair() {
		let wrapped = wrapError(GenerateEd25519KeyPair)
		return wrapped()
	}

	NewEd25519Signer() {
		let wrapped = wrapError(NewEd25519Signer)
		return wrapped()
	}

	NewEd25519Verifier() {
		let wrapped = wrapError(NewEd25519Verifier)
		return wrapped()
	}

	Ed25519PublicKeyFromPrivate() {
		let wrapped = wrapError(Ed25519PublicKeyFromPrivate)
		return wrapped()
	}

	Ed25519KeyPairFromSeed() {
		let wrapped = wrapError(Ed25519KeyPairFromSeed)
		return wrapped()
	}
}
