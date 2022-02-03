require('./wasm_exec.js');

const go = new Go(); // Defined in wasm_exec.js

// Read in wasm bytes
const path = require('path').join(__dirname, 'crypto.wasm');
const bytes = require('fs').readFileSync(path);

// Instantiate
const wasmModule = new WebAssembly.Module(bytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, go.importObject);
go.run(wasmInstance);

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


// Export Functions
module.exports.GenerateEd25519KeyPair = wrapError(GenerateEd25519KeyPair)
module.exports.NewEd25519Signer = wrapError(NewEd25519Signer)
module.exports.NewEd25519Verifier = wrapError(NewEd25519Verifier)
