package main

import (
	"syscall/js"
)

func main() {
	c := make(chan struct{})
	js.Global().Set("GenerateEd25519KeyPair", GenerateEd25519KeyPair())
	js.Global().Set("NewEd25519Signer", js.FuncOf(NewEd25519Signer))
	js.Global().Set("NewEd25519Verifier", js.FuncOf(NewEd25519Verifier))
	<-c
}

// Return an JS Value object map with the error key set based on the error string
func convertError(err error) interface{} {
	if err == nil {
		return js.ValueOf(map[string]interface{}{
			"error": "",
		})
	}
	return js.ValueOf(map[string]interface{}{
		"error": err.Error(),
	})
}
