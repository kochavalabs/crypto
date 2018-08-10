package crypto

import "fmt"

// AddressLength of address in bytes
const (
	AddressLength = 20
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
