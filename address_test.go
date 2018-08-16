package crypto

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAddress(t *testing.T) {
	_, pubk, err := GenerateKeyPairP256()
	if err != nil {
		t.Error("Failed to generate keys")
	}
	address, err := AddressFromPublicKey(pubk)
	if err != nil {
		t.Error(err)
	}

	address2, err := AddressFromHex(address.Hex())
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(*address, address2) {
		t.Errorf("addresses do not match, eppected: [%v] got: [%v]", address, address2)
	}
}

func TestAddressUnmarshalJSON(t *testing.T) {
	var tests = []struct {
		Input     string
		ShouldErr bool
		Output    string
	}{
		{"", true, ""},
		{`""`, true, ""},
		{`"0x"`, true, ""},
		{`"0x00"`, true, ""},
		{`"0xG000000000000000000000000000000000000000"`, true, ""},
		{`"0x0000000000000000000000000000000000000000"`, false, "0x0000000000000000000000000000000000000000"},
		{`"0x0000000000000000000000000000000000000010"`, false, "0x0000000000000000000000000000000000000010"},
	}
	for i, test := range tests {
		var v Address
		err := json.Unmarshal([]byte(test.Input), &v)
		if err != nil && !test.ShouldErr {
			t.Errorf("test #%d: unexpected error: %v", i, err)
		}
		if err == nil {
			if test.ShouldErr {
				t.Errorf("test #%d: expected error, got none", i)
			}
			if v.String() != test.Output {
				t.Errorf("test #%d: address mismatch: have %v, want %v", i, v.String(), test.Output)
			}
		}
	}
}
