package crypto

import (
	"encoding/hex"
	"math/big"
)

// AddressLength of address in bytes
const (
	HashLength = 32
	HexPrefix  = "0x"
)

// Hash represents the 32 byte hash of arbitrary data.
type Hash struct {
	value []byte
}

// Bytes gets the byte representation of the underlying hash.
func (h Hash) Bytes() []byte { return h.value }

// Big converts a hash to a big integer.
func (h Hash) Big() *big.Int { return new(big.Int).SetBytes(h.value) }

// Hex converts a hash to a hex string.
func (h Hash) Hex() string {
	return encode(h.value)
}

// encodes b as a hex string with 0x prefix.
func encode(b []byte) string {
	enc := make([]byte, len(b)*2+2)
	copy(enc, HexPrefix)
	hex.Encode(enc[2:], b)
	return string(enc)
}

// String implements fmt.Stringer
func (h Hash) String() string {
	return h.Hex()
}

// HexToHash sets byte representation of s to hash.
// If b is larger than len(h), b will be cropped from the left.
func HexToHash(s string) (Hash, error) {
	bytes, err := FromHex(s)
	if err != nil {
		return Hash{}, err
	}

	hash := BytesToHash(bytes)

	return hash, nil
}

// BytesToHash sets b to hash.
// If b is larger than len(h), b will be cropped from the left.
func BytesToHash(b []byte) Hash {
	h := Hash{
		value: make([]byte, HashLength),
	}
	h.SetBytes(b)
	return h
}

// BigToHash sets byte representation of b to hash.
// If b is larger than len(h), b will be cropped from the left.
func BigToHash(b *big.Int) Hash { return BytesToHash(b.Bytes()) }

// SetBytes sets the hash to the value of b.
// If b is larger than len(h), b will be cropped from the left.
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h.value) {
		b = b[len(b)-HashLength:]
	}

	copy(h.value[HashLength-len(b):], b)
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

// Hex2Bytes returns the bytes represented by the hexadecimal string str.
func Hex2Bytes(str string) []byte {
	h, _ := hex.DecodeString(str)
	return h
}

func hasHexPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

// isHexCharacter returns bool of c being a valid hexadecimal.
func isHexCharacter(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// isHex validates whether each byte is valid hexadecimal string.
func isHex(str string) bool {
	if len(str)%2 != 0 {
		return false
	}
	for _, c := range []byte(str) {
		if !isHexCharacter(c) {
			return false
		}
	}
	return true
}
