package crypto

import (
	"testing"
)

// TestSignatureVerification generates a private/public key pair using
// the P256 elliptic curve then loops over random strings, hasing and signing them.
// The public key assoicated with the private key is then used to verify the signature
func TestSignatureVerification(t *testing.T) {
	testCases := []struct {
		in string
	}{
		// Random strings to hash then sign
		{
			in: "ZE1vrINNJ*nsFYCyXDND",
		},
		{
			in: "7Njjy0ETe&TQwkyG6NRl",
		},
		{
			in: "URtsNRnpRZL4C0wtRss3",
		},
		{
			in: "9w242!S0S9yvHKQy22nb",
		},
		{
			in: "7Acme4RZgwBrgQ1sKYkn",
		},
		{
			in: "0wGTXx7vKNDIx8DvgVxz",
		},
		{
			in: "0DKEpSlN1bveMUQmWA2Z",
		},
		{
			in: "JB3TkKL8K2QQHV@dupMh",
		},
		{
			in: "4u2IsH6d7HUg#TgjgPik",
		},
		{
			in: "FAeHxOF5zg$KnenETgjH",
		},
	}
	prv, public, err := GenerateKeyPairP256()
	if err != nil {
		t.Error("Failed to generate keys using P256 ellipitic curve", err)
	}

	for _, tt := range testCases {
		t.Run(tt.in, func(t *testing.T) {
			hash := Sha3_256([]byte(tt.in))
			sig, err := prv.Sign(hash)
			if err != nil {
				t.Error("Failed to sign hash with private key", err)
			}
			if verified := public.Verify(hash, sig); !verified {
				t.Error("Expected : Valid signature, Got : Invalid signature")
			}
		})
	}
}

func TestIncorrectPublicKey(t *testing.T) {
	prv, _, err := GenerateKeyPairP256()
	if err != nil {
		t.Error("Failed to generate keys using P256 ellipitic curve", err)
	}
	_, public, err := GenerateKeyPairP256()
	if err != nil {
		t.Error("Failed to generate keys using P256 ellipitic curve", err)
	}

	hash := Sha3_256([]byte("test"))
	sig, err := prv.Sign(hash)
	if err != nil {
		t.Error("Failed to sign hash with private key", err)
	}

	// Try to verify signature with incorrect public key
	if verified := public.Verify(hash, sig); verified {
		t.Error("Expected : Invalid signature, Got : Valid signature")
	}
}

func TestNonDeterministic(t *testing.T) {
	prv, _, err := GenerateKeyPairP256()
	if err != nil {
		t.Error("Failed to generate keys using P256 ellipitic curve", err)
	}

	hash := Sha3_256([]byte("test"))
	sig1, err := prv.Sign(hash)
	if err != nil {
		t.Error("Failed to sign hash with private key", err)
	}
	sig2, err := prv.Sign(hash)
	if err != nil {
		t.Error("Failed to sign hash with private key", err)
	}

	if sig1.R == sig2.R && sig1.S == sig2.S {
		t.Error("Expected : mismatch signatures, Got: matching signatures")
	}
}
