package main

import (
	"syscall/js"

	"github.com/kochavalabs/crypto"
)

func GenerateEd25519KeyPair() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		pub, priv, err := crypto.GenerateEd25519KeyPair()
		if err != nil {
			return convertError(err)
		}

		return js.ValueOf(map[string]interface{}{
			"pub":  crypto.ToHex(pub),
			"priv": crypto.ToHex(priv),
		})
	})
}

func main() {
	c := make(chan struct{})
	js.Global().Set("GenerateEd25519KeyPair", GenerateEd25519KeyPair())
	js.Global().Set("NewEd25519Signer", js.FuncOf(NewEd25519Signer))
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
