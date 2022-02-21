require('./wasm_exec.js');

const go = new Go(); // Defined in wasm_exec.js

// Read in wasm bytes
const path = require('path').join(__dirname, 'crypto.wasm');
const bytes = require('fs').readFileSync(path);

// Instantiate
const wasmModule = new WebAssembly.Module(bytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, go.importObject);
go.run(wasmInstance);

// Export Functions
module.exports.NewCrypto = New
