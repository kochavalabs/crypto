package crypto

import (
	"reflect"
	"testing"

	"golang.org/x/crypto/sha3"
)

var sha3_256Hashes = []struct {
	input    [][]byte
	expected string
}{
	{nil, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
	{[][]byte{{}}, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
	{[][]byte{[]byte("asdf")}, "dd2781f4c51bccdbe23e4d398b8a82261f585c278dbb4b84989fea70e76723a9"},
	{[][]byte{[]byte("asdf"), []byte("qwer")}, "06b7857261bcda1d351383b80bc2fb08d5957b61495ac73d7bd788f8f77e7c18"},
}

func TestGenericHasherHex(t *testing.T) {
	for _, tt := range sha3_256Hashes {
		t.Run(tt.expected, func(t *testing.T) {
			hasher := GenericHasher{hashFunc: sha3.New256()}
			result := hasher.HashHex(tt.input...)
			if result != tt.expected {
				t.Errorf("Got %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestGenericHasherHash(t *testing.T) {
	for _, tt := range sha3_256Hashes {
		t.Run(tt.expected, func(t *testing.T) {
			hasher := GenericHasher{hashFunc: sha3.New256()}
			result := hasher.Hash(tt.input...)
			expected, _ := FromHex(tt.expected)
			if !reflect.DeepEqual(expected, result) {
				t.Errorf("Got %s, want %s", result, expected)
			}
		})
	}
}
