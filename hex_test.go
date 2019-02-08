package crypto

import (
	"errors"
	"reflect"
	"testing"
)

var validHexTests = []struct {
	str   string
	bytes []byte
	err   error
}{
	{"0x00", []byte{0}, nil},
	{"0x01", []byte{1}, nil},
	{"0x0f", []byte{15}, nil},
	{"0xff", []byte{255}, nil},
	{"0xffff", []byte{255, 255}, nil},
	{"0x0123456789abcdef", []byte{1, 35, 69, 103, 137, 171, 205, 239}, nil},
}

var invalidHexTests = []struct {
	str   string
	bytes []byte
	err   error
}{
	{"0", []byte{0}, nil},
	{"F", []byte{15}, nil},
	{"0x0F", []byte{15}, nil},
	{"ffff", []byte{255, 255}, nil},
	{"g", []byte{}, errors.New("")},
}

func TestFromHex(t *testing.T) {
	for _, tt := range append(validHexTests, invalidHexTests...) {
		t.Run(tt.str, func(t *testing.T) {
			result, err := FromHex(tt.str)
			if (tt.err != nil) != (err != nil) {
				t.Errorf("Error: got %s, want %s", err, tt.err)
			}
			if tt.err == nil && !reflect.DeepEqual(tt.bytes, result) {
				t.Errorf("Got %d, want %d", result, tt.bytes)
			}
		})
	}
}

func TestToHex(t *testing.T) {
	for _, tt := range validHexTests {
		t.Run(tt.str, func(t *testing.T) {
			result := ToHex(tt.bytes)
			if tt.str != result {
				t.Errorf("Got %s, want %s", result, tt.str)
			}
		})
	}
}
