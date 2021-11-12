package crypto

import (
	"encoding/hex"
)

// ToHex encodes b as a hex string
func ToHex(b []byte) string {
	// consider checks for string size in the future
	return hex.EncodeToString(b)
}

// FromHex returns the bytes represented by the hexadecimal string s.
func FromHex(hexEncoded string) ([]byte, error) {
	// consider checks for string size in the future
	return hex.DecodeString(hexEncoded)
}
