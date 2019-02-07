package crypto

import (
	"reflect"
	"testing"
)

var keccakTestCases = []struct {
	hasher   Hasher
	input    [][]byte
	expected string
}{
	{&Keccak256Hasher{}, nil, "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
	{&Keccak256Hasher{}, [][]byte{{}}, "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
	{&Keccak256Hasher{}, [][]byte{[]byte("asdf")}, "0x4c8f18581c0167eb90a761b4a304e009b924f03b619a0c0e8ea3adfce20aee64"},
	{&Keccak256Hasher{}, [][]byte{[]byte("asdf"), []byte("qwer")}, "0x68432ece0d2ea60cf463a6a9fae1b6deef509cb1e3b422df729ea6cc418ee8b5"},
}

func TestKeccakHasherHex(t *testing.T) {
	for _, tt := range keccakTestCases {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.hasher.HashHex(tt.input...)
			if result != tt.expected {
				t.Errorf("Got %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestKeccakHasherHash(t *testing.T) {
	for _, tt := range keccakTestCases {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.hasher.Hash(tt.input...)
			expected, _ := FromHex(tt.expected)
			if !reflect.DeepEqual(expected, result) {
				t.Errorf("Got %s, want %s", result, expected)
			}
		})
	}
}
