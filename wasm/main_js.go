package main

import (
	"syscall/js"
)

func main() {
	c := make(chan struct{})
	// Return a single function "New" that returns an object with
	// a set of functions available from the Crypto library
	js.Global().Set("New", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return js.ValueOf(map[string]interface{}{
			"GenerateEd25519KeyPair":      GenerateEd25519KeyPair(),
			"NewEd25519Signer":            js.FuncOf(NewEd25519Signer),
			"NewEd25519Verifier":          js.FuncOf(NewEd25519Verifier),
			"Ed25519PublicKeyFromPrivate": Ed25519PublicKeyFromPrivate(),
			"Ed25519KeyPairFromSeed":      Ed25519KeyPairFromSeed(),
		})
	}))
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
