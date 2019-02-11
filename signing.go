package crypto

// A signer/verifyer should return some information about what type of signature
// it is generating. An example may be ecdsa_p256_keccak256 indicating an
// eliptic curve signing algorithm using curve p256 and hashing with
// keccak256.
type CryptoSuite interface {
	SuiteType() string
}

// Abstraction around verifying signatures. This can be a useful abstraction
// if you don't particularly care about the key/signature format but simply want
// to create a cryptographic verifyer of a certin type.
type Verifyer interface {
	CryptoSuite
	Verify(toVerify Hashable, signature []byte) bool
}

// Abstraction around signing. This can be a useful abstraction if you don't
// particularly care about the key/signature format but simply want to create a
// cryptographic signer of a certin type. We assume that if you can sign that
// you can also verify (especially in the case of ecdsa.)
type Signer interface {
	Verifyer
	Sign(toSign Hashable) ([]byte, error)
}
