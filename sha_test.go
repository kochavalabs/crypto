package crypto

import (
	"reflect"
	"testing"
)

var shaTestCases = []struct {
	hasher   Hasher
	input    [][]byte
	expected string
}{
	{&Sha3_256Hasher{}, [][]byte{{}}, "0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
	{&Sha3_256Hasher{}, [][]byte{[]byte("asdf")}, "0xdd2781f4c51bccdbe23e4d398b8a82261f585c278dbb4b84989fea70e76723a9"},
	{&Sha3_256Hasher{}, [][]byte{[]byte("asdf"), []byte("qwer")}, "0x06b7857261bcda1d351383b80bc2fb08d5957b61495ac73d7bd788f8f77e7c18"},
	{&Sha3_512Hasher{}, [][]byte{{}}, "0xa69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"},
	{&Sha3_512Hasher{}, [][]byte{[]byte("asdf")}, "0x8d88cf5b20f53acd7ae1479b5b36dc2021753b049902c77247bb27b131b300bd3ca8beef28756dce27b8990867c4577a2535e7e3b75141399ca1a94cc84b0eb9"},
	{&Sha3_512Hasher{}, [][]byte{[]byte("asdf"), []byte("qwer")}, "0x5bf3ca908fcf1ad5f52f09a5ea48567c69905cfd315d98717e93708713042e6bd8c63d9465d572132ccb79a50d76ec851afd495931a1a33a07063803ee919a46"},
	{&Sha_256Hasher{}, [][]byte{{}}, "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{&Sha_256Hasher{}, [][]byte{[]byte("asdf")}, "0xf0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b"},
	{&Sha_256Hasher{}, [][]byte{[]byte("asdf"), []byte("qwer")}, "0x2cbe13972c4067ebee6437e9bf8b0efa1d869357b4289c3b1b830bd2f602afcd"},
	{&Sha_512Hasher{}, [][]byte{{}}, "0xcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
	{&Sha_512Hasher{}, [][]byte{[]byte("asdf")}, "0x401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429080fb337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1"},
	{&Sha_512Hasher{}, [][]byte{[]byte("asdf"), []byte("qwer")}, "0x4f56742c6948f264fa2109286fb4d48166263a6441477509cc5651c7e7533986e715901d67ef53e1a9c09e3cd72e910386f16eebc61b2a62d3059b17c860d81f"},
}

func TestShaHasherHex(t *testing.T) {
	for _, tt := range shaTestCases {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.hasher.HashHex(tt.input...)
			if result != tt.expected {
				t.Errorf("Got %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestShaHasherHash(t *testing.T) {
	for _, tt := range shaTestCases {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.hasher.Hash(tt.input...)
			expected, _ := FromHex(tt.expected)
			if !reflect.DeepEqual(expected, result) {
				t.Errorf("Got %s, want %s", result, expected)
			}
		})
	}
}
