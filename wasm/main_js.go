package main

import (
	"syscall/js"

	"github.com/kochavalabs/crypto"
)

func GenerateEd25519KeyPair() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		pub, priv, err := crypto.GenerateEd25519KeyPair()
		return js.ValueOf(map[string]interface{}{
			"pub":   pub,
			"priv":  priv,
			"error": convertError(err),
		})
	})
}

func main() {
	c := make(chan struct{})
	js.Global().Set("GenerateEd25519KeyPair", GenerateEd25519KeyPair())
	<-c
}

// Return empty string if error is nil, otherwise return error string
func convertError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
