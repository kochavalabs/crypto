package crypto

import (
	"encoding/hex"
)

// Leading characters of a hex formatted string.
const (
	HexPrefix = "0x"
)

// encodes b as a hex string with 0x prefix.
func ToHex(b []byte) string {
	enc := make([]byte, len(b)*2+2)
	copy(enc, HexPrefix)
	hex.Encode(enc[2:], b)
	return string(enc)
}

// FromHex returns the bytes represented by the hexadecimal string s.
// s may be prefixed with "0x".
func FromHex(hexEncoded string) ([]byte, error) {
	if hasHexPrefix(hexEncoded) {
		hexEncoded = hexEncoded[2:] // remove prefix
	}

	// If there is an odd number of characters prefix with 0 to correct
	if len(hexEncoded)%2 == 1 {
		hexEncoded = "0" + hexEncoded
	}

	hashAddress, err := hex.DecodeString(hexEncoded)
	if err != nil {
		return nil, err
	}

	return hashAddress, nil
}

func hasHexPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}
