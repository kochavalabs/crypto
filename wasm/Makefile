.PHONY: $(MAKECMDGOALS)

build-tiny-wasm:
	tinygo build -o ./pkg/crypto.wasm -target wasm .
	cp -p pkg/wasm_exec_tiny.js pkg/wasm_exec.js

build-wasm:
	GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o ./pkg/crypto.wasm .
	cp -p ${GOROOT}/misc/wasm/wasm_exec.js pkg
	sed -i '' -e 's/require(/__non_webpack_require__(/g' pkg/wasm_exec.js
