require('./wasm_exec.js');
const fetch = require('node-fetch');

const go = new Go(); // Defined in wasm_exec.js
const WASM_URL = require('path').join(__dirname, 'crypto.wasm');

let wasm;

if ('instantiateStreaming' in WebAssembly) {
	WebAssembly.instantiateStreaming(fetch(WASM_URL), go.importObject).then(function (obj) {
		wasm = obj.instance;
		go.run(wasm);
	})
} else {
	fetch(WASM_URL).then(resp =>
		resp.arrayBuffer()
	).then(bytes =>
		WebAssembly.instantiate(bytes, go.importObject).then(function (obj) {
			wasm = obj.instance;
			go.run(wasm);
		})
	)
}

module.exports.__wasm = wasm;
module.exports = GenerateEd25519KeyPair()