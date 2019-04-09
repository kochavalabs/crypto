package crypto

// Suite signer/verifier should return some information about what type of signature
// it is generating. An example may be ecdsa_p256_keccak256 indicating an
// eliptic curve signing algorithm using curve p256 and hashing with
// keccak256.
type Suite interface {
	SuiteType() string
}

// Verifier abstraction around verifying signatures. This can be a useful abstraction
// if you don't particularly care about the key/signature format but simply want
// to create a cryptographic verifier of a certin type.
type Verifier interface {
	Suite
	Verify(toVerify []byte, signature []byte) bool
}

// Signer abstraction around signing. This can be a useful abstraction if you don't
// particularly care about the key/signature format but simply want to create a
// cryptographic signer of a certin type. We assume that if you can sign that
// you can also verify (especially in the case of ecdsa.)
type Signer interface {
	Verifier
	Sign(toSign []byte) ([]byte, error)
}

// MockSigner mock of the signier interface.
type MockSigner struct {
	Suite string

	ToVerify  []byte
	Signature []byte
	VerifyRet bool

	ToSign     []byte
	SignSigRet []byte
	SignErrRet error
}

// Sign mock.
func (s *MockSigner) Sign(toSign []byte) ([]byte, error) {
	s.ToSign = toSign
	return s.SignSigRet, s.SignErrRet
}

// Verify mock.
func (s *MockSigner) Verify(toVerify []byte, signature []byte) bool {
	s.ToVerify = toVerify
	s.Signature = signature
	return s.VerifyRet
}

// SuiteType mock.
func (s *MockSigner) SuiteType() string {
	return s.Suite
}
