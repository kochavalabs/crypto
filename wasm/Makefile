.PHONY: $(MAKECMDGOALS)

build-tiny-wasm:
	tinygo build -o ./pkg/crypto.wasm -target wasm *.go

build-wasm:
	GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o ./pkg/crypto.wasm *.go
