package main

import (
	"errors"
	"fmt"
	"syscall/js"

	"github.com/kochavalabs/crypto"
)

// NewEd25519Signer constructor for ed25519 Signer
// First argument is a string Hex Public Key
func NewEd25519Verifier(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return convertError(errors.New("NewEd25519Verifier must receive hex public key as argument"))
	}

	key, err := crypto.FromHex(args[0].String())
	if err != nil {
		return convertError(err)
	}

	verifier, err := crypto.NewEd25519Verifier(key)
	if err != nil {
		return convertError(err)
	}

	wrapper := &ed25519VerifierWrapper{
		verifier: verifier,
	}

	return js.ValueOf(map[string]interface{}{
		"Verify": wrapper.verify(),
	})
}

// NewEd25519Signer constructor for ed25519 Signer
// First argument is a string Hex Private Key
func NewEd25519Signer(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return convertError(errors.New("NewEd25519Signer must receive hex private key as argument"))
	}

	key, err := crypto.FromHex(args[0].String())
	if err != nil {
		return convertError(err)
	}

	signer, err := crypto.NewEd25519Signer(key)
	if err != nil {
		return convertError(err)
	}

	wrapper := &ed25519SignerWrapper{
		signer: signer,
	}

	return js.ValueOf(map[string]interface{}{
		"Sign": wrapper.sign(),
	})
}

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

func Ed25519PublicKeyFromPrivate() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return convertError(errors.New("Ed25519PublicKeyFromPrivate must receive hex private key as argument"))
		}

		key, err := crypto.FromHex(args[0].String())
		if err != nil {
			return convertError(err)
		}

		pub, err := crypto.Ed25519PublicKeyFromPrivate(key)
		if err != nil {
			return convertError(err)
		}

		return js.ValueOf(crypto.ToHex(pub))
	})
}

func Ed25519KeyPairFromSeed() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return convertError(errors.New("Ed25519KeyPairFromSeed must receive hex seed as argument"))
		}

		seed, err := crypto.FromHex(args[0].String())
		if err != nil {
			return convertError(err)
		}

		pub, priv, err := crypto.Ed25519KeyPairFromSeed(seed)
		if err != nil {
			return convertError(err)
		}

		return js.ValueOf(map[string]interface{}{
			"pub":  crypto.ToHex(pub),
			"priv": crypto.ToHex(priv),
		})
	})
}

type ed25519VerifierWrapper struct {
	verifier crypto.Verifier
}

func (s *ed25519VerifierWrapper) verify() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			return convertError(errors.New("verify must receive hex data to verify and hex signature as aruments"))
		}

		toVerify, err := crypto.FromHex(args[0].String())
		if err != nil {
			return convertError(fmt.Errorf("error trying to parse first argument: %v", err))
		}

		signature, err := crypto.FromHex(args[1].String())
		if err != nil {
			return convertError(fmt.Errorf("error trying to parse second argument: %v", err))
		}

		verified := s.verifier.Verify(toVerify, signature)

		return js.ValueOf(verified)
	})
}

type ed25519SignerWrapper struct {
	signer crypto.Signer
}

// Sign takes a data
func (s *ed25519SignerWrapper) sign() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return convertError(errors.New("sign must receive hex data to sign"))
		}

		toSign, err := crypto.FromHex(args[0].String())
		if err != nil {
			return convertError(err)
		}

		signature, err := s.signer.Sign(toSign)
		if err != nil {
			return convertError(err)
		}

		return js.ValueOf(crypto.ToHex(signature))
	})
}
