package main

import (
	"errors"
	"syscall/js"

	"github.com/kochavalabs/crypto"
)

type ed25519SignerWrapper struct {
	signer crypto.Signer
}

// NewEd25519Signer constructor for ed25519 Signer
// First argument is a string Hex Private Key
func NewEd25519Signer(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return errors.New("NewEd25519Signer must receive hex private key as argument").Error()
	}

	key, err := crypto.FromHex(args[0].String())
	if err != nil {
		return err.Error()
	}

	signer, err := crypto.NewEd25519Signer(key)
	if err != nil {
		return err.Error()
	}

	wrapper := &ed25519SignerWrapper{
		signer: signer,
	}

	return js.ValueOf(map[string]interface{}{
		"Sign": wrapper.sign(),
	})
}

// Sign takes a data
func (s *ed25519SignerWrapper) sign() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return errors.New("NewEd25519Signer must receive hex data to sign").Error()
		}

		toSign, err := crypto.FromHex(args[0].String())
		if err != nil {
			return err.Error()
		}

		signature, err := s.signer.Sign(toSign)
		if err != nil {
			return err.Error()
		}

		return js.ValueOf(crypto.ToHex(signature))
	})
}
