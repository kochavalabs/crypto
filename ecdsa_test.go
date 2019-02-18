package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

const P256PubHex = "0x0e609d4eea6ecac33fd083bf108e90db5a31fbf9239bc5cc19a8a6dd10b61050c746f61b03ab399bcc5d18bd33953b4e73a4fdf7529f58747304a32c4814d24e"
const P256PrivHex = "0x25590b07bb236b0cdc4052550093684efe4e8123291c11095e1360203c0b1a63"

type fixedReader struct {
	value byte
}

func (r *fixedReader) Read(p []byte) (n int, err error) {
	for i, _ := range p {
		p[i] = r.value
	}
	return len(p), nil
}

func newAllBytesEight(hasher Hasher, messageHash []byte, privKey *ecdsa.PrivateKey) io.Reader {
	return &fixedReader{
		value: 8,
	}
}

var signingTestCases = []struct {
	message []byte
}{
	{nil},
	{[]byte{}},
	{[]byte{1, 2, 3}},
}

func TestEcdsSignerSuiteType(t *testing.T) {
	signer := EcdsaSigner{
		verifyer: &EcdsaVerifyer{suiteType: "Test"},
	}
	expected := "Test"
	result := signer.SuiteType()
	if expected != result {
		t.Errorf("Got %s, expected %s", result, expected)
	}
}

func TestEcdsaSignerSign(t *testing.T) {
	for _, tt := range signingTestCases {
		t.Run(ToHex(tt.message), func(t *testing.T) {
			allBytesEight := &fixedReader{value: 8}
			hasher := &Sha3_256Hasher{}
			testKey, _ := ecdsa.GenerateKey(elliptic.P256(), allBytesEight)
			signer := EcdsaSigner{
				hasher:     hasher,
				reader:     newAllBytesEight,
				privateKey: *testKey,
			}

			result, err := signer.Sign(&ByteHashable{toHash: tt.message})
			r, s, _ := ecdsa.Sign(allBytesEight, testKey, hasher.Hash(tt.message))
			expected := append(r.Bytes(), s.Bytes()...)

			if err != nil {
				t.Errorf("Signer.Sign returned unexpected error: %s", err)
			}

			if !reflect.DeepEqual(expected, result) {
				t.Errorf("Expected %s, result was %s.", expected, result)
			}

		})
	}
}

func TestEcdsaSignerVerifyPass(t *testing.T) {
	for _, tt := range signingTestCases {
		t.Run(ToHex(tt.message), func(t *testing.T) {
			allBytesEight := &fixedReader{value: 8}
			hasher := &Sha3_256Hasher{}
			testKey, _ := ecdsa.GenerateKey(elliptic.P256(), allBytesEight)
			signer := EcdsaSigner{
				hasher:     hasher,
				reader:     newAllBytesEight,
				privateKey: *testKey,
				verifyer: &EcdsaVerifyer{
					publicKey: &testKey.PublicKey,
					hasher:    hasher,
				},
			}

			r, s, _ := ecdsa.Sign(allBytesEight, testKey, hasher.Hash(tt.message))
			signature := append(r.Bytes(), s.Bytes()...)

			if !signer.Verify(&ByteHashable{toHash: tt.message}, signature) {
				t.Errorf("Expected signature to verify, it did not.")
			}

		})
	}
}

func TestEcdsaSignerVerifyFailBadSignature(t *testing.T) {
	for _, tt := range signingTestCases {
		t.Run(ToHex(tt.message), func(t *testing.T) {
			allBytesEight := &fixedReader{value: 8}
			hasher := &Sha3_256Hasher{}
			testKey, _ := ecdsa.GenerateKey(elliptic.P256(), allBytesEight)
			signer := EcdsaSigner{
				hasher:     hasher,
				reader:     newAllBytesEight,
				privateKey: *testKey,
				verifyer: &EcdsaVerifyer{
					publicKey: &testKey.PublicKey,
					hasher:    hasher,
				},
			}

			r, s, _ := ecdsa.Sign(allBytesEight, testKey, hasher.Hash(tt.message))
			r = r.Add(r, s)
			signature := append(r.Bytes(), s.Bytes()...)

			if signer.Verify(&ByteHashable{toHash: tt.message}, signature) {
				t.Errorf("Expected signature to not verify, it did.")
			}

		})
	}
}

func TestEcdsaSignerVerifyFailMismatchHasher(t *testing.T) {
	for _, tt := range signingTestCases {
		t.Run(ToHex(tt.message), func(t *testing.T) {
			allBytesEight := &fixedReader{value: 8}
			hasher := &Sha3_256Hasher{}
			testKey, _ := ecdsa.GenerateKey(elliptic.P256(), allBytesEight)
			signer := EcdsaSigner{
				hasher:     hasher,
				reader:     newAllBytesEight,
				privateKey: *testKey,
				verifyer: &EcdsaVerifyer{
					publicKey: &testKey.PublicKey,
					hasher:    &Sha_256Hasher{},
				},
			}

			r, s, _ := ecdsa.Sign(allBytesEight, testKey, hasher.Hash(tt.message))
			r = r.Add(r, s)
			signature := append(r.Bytes(), s.Bytes()...)

			if signer.Verify(&ByteHashable{toHash: tt.message}, signature) {
				t.Errorf("Expected signature to not verify, it did.")
			}

		})
	}
}

func TestEcdsaSignerVerifyFailBadKey(t *testing.T) {
	for _, tt := range signingTestCases {
		t.Run(ToHex(tt.message), func(t *testing.T) {
			allBytesEight := &fixedReader{value: 8}
			hasher := &Sha3_256Hasher{}
			testKey, _ := ecdsa.GenerateKey(elliptic.P256(), allBytesEight)
			badKey, _ := ecdsa.GenerateKey(elliptic.P224(), allBytesEight)
			signer := EcdsaSigner{
				hasher:     hasher,
				reader:     newAllBytesEight,
				privateKey: *testKey,
				verifyer: &EcdsaVerifyer{
					publicKey: &badKey.PublicKey,
					hasher:    hasher,
				},
			}

			r, s, _ := ecdsa.Sign(allBytesEight, testKey, hasher.Hash(tt.message))
			r = r.Add(r, s)
			signature := append(r.Bytes(), s.Bytes()...)

			if signer.Verify(&ByteHashable{toHash: tt.message}, signature) {
				t.Errorf("Expected signature to not verify, it did.")
			}

		})
	}
}

func TestEcdsaSignerVerifyFailBadMessage(t *testing.T) {
	for _, tt := range signingTestCases {
		t.Run(ToHex(tt.message), func(t *testing.T) {
			allBytesEight := &fixedReader{value: 8}
			hasher := &Sha3_256Hasher{}
			testKey, _ := ecdsa.GenerateKey(elliptic.P256(), allBytesEight)
			signer := EcdsaSigner{
				hasher:     hasher,
				reader:     newAllBytesEight,
				privateKey: *testKey,
				verifyer: &EcdsaVerifyer{
					publicKey: &testKey.PublicKey,
					hasher:    hasher,
				},
			}
			badMessage := append(tt.message, 8)

			r, s, _ := ecdsa.Sign(allBytesEight, testKey, hasher.Hash(badMessage))
			r = r.Add(r, s)
			signature := append(r.Bytes(), s.Bytes()...)

			if signer.Verify(&ByteHashable{toHash: tt.message}, signature) {
				t.Errorf("Expected signature to not verify, it did.")
			}

		})
	}
}

var constructorTestCases = []struct {
	signerNew     func([]byte) (Signer, error)
	verifyerNew   func([]byte) (Verifyer, error)
	pubKeyHex     string
	privKeyHex    string
	message       []byte
	deterministic bool
}{
	{NewP256Sha3_256DetSigner, NewP256Sha3_256Verifyer, P256PubHex, P256PrivHex, nil, true},
	{NewP256Sha3_256DetSigner, NewP256Sha3_256Verifyer, P256PubHex, P256PrivHex, []byte{1, 2}, true},
	{NewP256Sha3_256InDetSigner, NewP256Sha3_256Verifyer, P256PubHex, P256PrivHex, nil, false},
	{NewP256Sha3_256InDetSigner, NewP256Sha3_256Verifyer, P256PubHex, P256PrivHex, []byte{1, 2}, false},
	{NewP256Shake256DetSigner, NewP256Shake256Verifyer, P256PubHex, P256PrivHex, nil, true},
	{NewP256Shake256DetSigner, NewP256Shake256Verifyer, P256PubHex, P256PrivHex, []byte{1, 2}, true},
	{NewP256Shake256InDetSigner, NewP256Shake256Verifyer, P256PubHex, P256PrivHex, nil, false},
	{NewP256Shake256InDetSigner, NewP256SShake256Verifyer, P256PubHex, P256PrivHex, []byte{1, 2}, false},
}

func TestEcdsaConstructorPairSuccess(t *testing.T) {
	for _, tt := range constructorTestCases {
		testName := fmt.Sprintf("%s_%t", ToHex(tt.message), tt.deterministic)
		t.Run(testName, func(t *testing.T) {
			privKey, _ := FromHex(tt.privKeyHex)
			pubKey, _ := FromHex(tt.pubKeyHex)
			signer, errConSign := tt.signerNew(privKey)
			verifyer, errConVer := tt.verifyerNew(pubKey)
			message := &ByteHashable{toHash: tt.message}

			if !strings.HasPrefix(signer.SuiteType(), verifyer.SuiteType()) {
				t.Errorf(
					"Different suite type: Verifyer=%s Signer=%s",
					verifyer.SuiteType(),
					signer.SuiteType())
			}

			if errConSign != nil {
				t.Errorf("Error creating the signer.")
			}

			if errConVer != nil {
				t.Errorf("Error creating the signer.")
			}

			signature1, errSign1 := signer.Sign(message)
			signature2, errSign2 := signer.Sign(message)

			if errSign1 != nil {
				t.Errorf("Error while signing first time.")
			}

			if errSign2 != nil {
				t.Errorf("Error while signing second time.")
			}

			if !signer.Verify(message, signature1) {
				t.Errorf("Signer didn't verify signature1 for its own message.")
			}

			if !signer.Verify(message, signature2) {
				t.Errorf("Signer didn't verify signature2 for its own message.")
			}

			if !verifyer.Verify(message, signature1) {
				t.Errorf("Verifyer didn't verify signature1 for for signer.")
			}

			if !verifyer.Verify(message, signature2) {
				t.Errorf("Verifyer didn't verify signature2 for for signer.")
			}

			if reflect.DeepEqual(signature1, signature2) != tt.deterministic {
				t.Errorf("Signature determinisim was not what was expected.")
			}

		})
	}
}
