package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

const (
	P256PrivateKeyLength = 32
	P256PublicKeyLength  = 64
	P256SignatureLength  = 64
)

// GenerateKeyPairP256 create a private/public key pair using the P256 elliptic
// curve
func GenerateKeyPairP256() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	prvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return prvKey, &prvKey.PublicKey, nil
}

func splitByteSlice(toSplit []byte) (*big.Int, *big.Int) {
	l := len(toSplit)
	left := new(big.Int).SetBytes(toSplit[:l/2])
	right := new(big.Int).SetBytes(toSplit[l/2:])
	return left, right
}

type EcdsaVerifyer struct {
	publicKey *ecdsa.PublicKey
	hasher    Hasher
	suiteType string
}

func (s *EcdsaVerifyer) Verify(toVerify Hashable, signature []byte) bool {
	messageHash := toVerify.Hash(s.hasher)
	R, S := splitByteSlice(signature)
	return ecdsa.Verify(s.publicKey, messageHash, R, S)
}

func (s *EcdsaVerifyer) SuiteType() string {
	return s.suiteType
}

type EcdsaSigner struct {
	hasher     Hasher
	verifyer   *EcdsaVerifyer
	reader     newReader
	privateKey ecdsa.PrivateKey
}

func (s *EcdsaSigner) Sign(toSign Hashable) ([]byte, error) {
	messageHash := toSign.Hash(s.hasher)
	reader := s.reader(s.hasher, messageHash, s.privateKey.D.Bytes())
	R, S, err := ecdsa.Sign(reader, &s.privateKey, messageHash)
	if err != nil {
		return nil, err
	}
	return append(R.Bytes(), S.Bytes()...), nil
}

func (s *EcdsaSigner) Verify(toVerify Hashable, signature []byte) bool {
	return s.verifyer.Verify(toVerify, signature)
}

func (s *EcdsaSigner) SuiteType() string {
	return s.verifyer.SuiteType()
}

// Convenience function for creating verifyers. Used in functions such as
// NewP256Sha3_256DetSigner
func getVerifyer(
	curve elliptic.Curve,
	pubData []byte,
	hasher Hasher,
	suiteType string,
) *EcdsaVerifyer {
	X, Y := splitByteSlice(pubData)
	pubKey := ecdsa.PublicKey{
		X:     X,
		Y:     Y,
		Curve: curve,
	}
	return &EcdsaVerifyer{
		hasher:    hasher,
		publicKey: &pubKey,
		suiteType: suiteType,
	}
}

// Convenience function for creating signers. Used in functions such as
// NewP256Sha3_256DetSigner
func getSigner(
	curve elliptic.Curve,
	privData []byte,
	hasher Hasher,
	reader newReader,
	suiteType string,
) *EcdsaSigner {
	k := new(big.Int).SetBytes(privData)
	privKey := new(ecdsa.PrivateKey)
	privKey.PublicKey.Curve = curve
	privKey.D = k
	privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(k.Bytes())
	pubData := append(privKey.PublicKey.X.Bytes(), privKey.PublicKey.Y.Bytes()...)
	return &EcdsaSigner{
		hasher:     hasher,
		reader:     reader,
		privateKey: *privKey,
		verifyer:   getVerifyer(curve, pubData, hasher, suiteType),
	}
}

func NewP256Sha3_256Verifyer(pubData []byte) (Verifyer, error) {
	if len(pubData) != 64 {
		errorMsg := fmt.Sprintf(
			"Bad keydata passed to verifyer, expected 64 bytes, got %d bytes",
			len(pubData))
		return nil, errors.New(errorMsg)
	}
	return getVerifyer(
		elliptic.P256(), pubData, &Sha3_256Hasher{}, "ecdsa_P256_sha3-256",
	), nil
}

func NewP256Sha3_256DetSigner(privData []byte) (Signer, error) {
	if len(privData) != 32 {
		errorMsg := fmt.Sprintf(
			"Bad keydata passed to verifyer, expected 32 bytes, got %d bytes",
			len(privData))
		return nil, errors.New(errorMsg)
	}
	hasher := &Sha3_256Hasher{}
	return getSigner(
		elliptic.P256(),
		privData,
		hasher,
		newDeterministicReader,
		"ecdsa_P256_sha3-256_det",
	), nil
}

func NewP256Sha3_256InDetSigner(privData []byte) (Signer, error) {
	if len(privData) != 32 {
		errorMsg := fmt.Sprintf(
			"Bad keydata passed to verifyer, expected 32 bytes, got %d bytes",
			len(privData))
		return nil, errors.New(errorMsg)
	}
	hasher := &Sha3_256Hasher{}
	return getSigner(
		elliptic.P256(),
		privData,
		hasher,
		newRandomReader,
		"ecdsa_P256_sha3-256_indet",
	), nil
}

func NewP256Shake256Verifyer(pubData []byte) (Verifyer, error) {
	if len(pubData) != 64 {
		errorMsg := fmt.Sprintf(
			"Bad keydata passed to verifyer, expected 64 bytes, got %d bytes",
			len(pubData))
		return nil, errors.New(errorMsg)
	}
	return getVerifyer(
		elliptic.P256(), pubData, &Shake256Hasher{}, "ecdsa_P256_shake256",
	), nil
}

func NewP256Shake256DetSigner(privData []byte) (Signer, error) {
	if len(privData) != 32 {
		errorMsg := fmt.Sprintf(
			"Bad keydata passed to verifyer, expected 32 bytes, got %d bytes",
			len(privData))
		return nil, errors.New(errorMsg)
	}
	hasher := &Shake256Hasher{}
	return getSigner(
		elliptic.P256(),
		privData,
		hasher,
		newDeterministicReader,
		"ecdsa_P256_shake256_det",
	), nil
}

func NewP256Shake256InDetSigner(privData []byte) (Signer, error) {
	if len(privData) != 32 {
		errorMsg := fmt.Sprintf(
			"Bad keydata passed to verifyer, expected 32 bytes, got %d bytes",
			len(privData))
		return nil, errors.New(errorMsg)
	}
	hasher := &Shake256Hasher{}
	return getSigner(
		elliptic.P256(),
		privData,
		hasher,
		newRandomReader,
		"ecdsa_P256_shake256_indet",
	), nil
}
