package crypto

import (
	"reflect"
	"testing"
)

var shakeTestCases = []struct {
	hasher   Hasher
	input    [][]byte
	expected string
}{
	{&Shake256Hasher{}, nil, "0x46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"},
	{&Shake256Hasher{}, [][]byte{{}}, "0x46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"},
	{&Shake256Hasher{}, [][]byte{[]byte("asdf")}, "0xf00c15643396616a89a0cb79039f740575defe9dbe307cccdaf8ae210e1c9cc6"},
	{&Shake256Hasher{}, [][]byte{[]byte("asdf"), []byte("qwer")}, "0xc37f508e9af6afc86f9a768c15553036b7df09ba6d6fb3a836c1aa9a3bfc2b27"},
}

func TestShakeHasherHex(t *testing.T) {
	for _, tt := range shakeTestCases {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.hasher.HashHex(tt.input...)
			if result != tt.expected {
				t.Errorf("Got %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestShakeHasherHash(t *testing.T) {
	for _, tt := range shakeTestCases {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.hasher.Hash(tt.input...)
			expected, _ := FromHex(tt.expected)
			if !reflect.DeepEqual(expected, result) {
				t.Errorf("Got %s, want %s", result, expected)
			}
		})
	}
}
