package crypto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
)

// AddressLength of address in bytes
const (
	AddressLength = 20
)

var (
	addressT = reflect.TypeOf(Address{})
)

// Address represents a 32 byte address
type Address [AddressLength]byte

// Bytes returns the raw bytes of the address
func (a Address) Bytes() []byte {
	return a[:]
}

// Hex returns the hex encoded representation of the address bytes
// TODO: Include a checksum rule for capitalization?
func (a Address) Hex() string {
	return encode(a[:])
}

// String implements fmt.Stringer
func (a Address) String() string {
	return a.Hex()
}

// Format implements fmt.Formatter, forcing the byte slice to be formatted as is,
// without going through the stringer interface used for logging.
func (a Address) Format(s fmt.State, c rune) {
	fmt.Fprintf(s, "%"+string(c), a[:])
}

// SetBytes sets the hash to the value of b.
// If b is larger than len(h), b will be cropped from the left.
func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}

	copy(a[AddressLength-len(b):], b)
}

// AddressFromPublicKey returns the address of a EC public key
func AddressFromPublicKey(pubk *PublicKey) (*Address, error) {
	x509encoded, err := MarshaPublicKeyX509(pubk)
	if err != nil {
		return nil, err
	}
	hashAddress := Sha3_256(x509encoded)
	address := &Address{}
	address.SetBytes(hashAddress)
	return address, nil
}

// AddressFromHex returns the Address from a hex encoded string or error
func AddressFromHex(hexEncoded string) (Address, error) {
	bytes, err := FromHex(hexEncoded)
	if err != nil {
		return Address{}, err
	}

	address := AddressFromBytes(bytes)

	return address, nil
}

// AddressFromBytes returns the Address from the bytes
func AddressFromBytes(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

// IsHexAddress verifies whether a string can represent a valid hex-encoded
// address or not.
func IsHexAddress(s string) bool {
	if hasHexPrefix(s) {
		s = s[2:]
	}
	return len(s) == 2*AddressLength && isHex(s)
}

// MarshalText returns the hex representation of an Address.
func (a Address) MarshalText() ([]byte, error) {
	b := a.Bytes()
	result := make([]byte, len(b)*2+2)
	copy(result, `0x`)
	hex.Encode(result[2:], b)
	return result, nil
}

// UnmarshalText parses an address in hex syntax.
func (a *Address) UnmarshalText(input []byte) error {
	out := a[:]

	if len(input) == 0 {
		// Skip removing prefix
	} else if len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X') {
		input = input[2:] // Remove prefix if found
	}

	if len(input)/2 != len(out) {
		return fmt.Errorf("hex string has length %d, want %d for %s", len(input), len(out)*2, "Address")
	}
	// Pre-verify syntax before modifying out.
	for _, b := range input {
		if decodeNibble(b) == badNibble {
			return ErrSyntax
		}
	}
	hex.Decode(out, input)
	return nil
}

// UnmarshalJSON parses an address in hex syntax.
func (a *Address) UnmarshalJSON(input []byte) error {
	// Check if string
	if !(len(input) >= 2 && input[0] == '"' && input[len(input)-1] == '"') {
		return &json.UnmarshalTypeError{Value: "non-string", Type: addressT}
	}

	return a.UnmarshalText(input[1 : len(input)-1])
}

const badNibble = ^uint64(0)

func decodeNibble(in byte) uint64 {
	switch {
	case in >= '0' && in <= '9':
		return uint64(in - '0')
	case in >= 'A' && in <= 'F':
		return uint64(in - 'A' + 10)
	case in >= 'a' && in <= 'f':
		return uint64(in - 'a' + 10)
	default:
		return badNibble
	}
}
