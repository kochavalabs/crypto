package crypto

import (
	"encoding/hex"
	"errors"
)

// AddressLength of address in bytes
const (
	AddressLength    = 32
	AddressHexPrefix = "0x"
)

// Address represents the 32 byte address from a sha3_356 hashed X509 encoded EC public key
type Address [AddressLength]byte

// Bytes returns the raw bytes of the address
func (addr Address) Bytes() []byte { return addr[:] }

// Hex - todo
func (addr Address) Hex() string {
	return AddressHexPrefix + hex.EncodeToString(addr[:])
}

// Strings implements fmt.Stringer
func (addr Address) String() string {
	return addr.Hex()
}

// HexToAddress returns the Address with byte values of hexEncoded.
func HexToAddress(hexEncodedAddress string) (Address, error) {
	var addr Address
	if hasHexPrefix(hexEncodedAddress) {
		hexEncodedAddress = hexEncodedAddress[2:] // remove prefix
	}
	h, err := hex.DecodeString(hexEncodedAddress)
	if err != nil {
		return addr, err
	}
	if len(h) != AddressLength {
		return addr, errors.New("Invalid decoding of hex string")
	}
	copy(addr[:], h[:])
	return addr, nil
}

func hasHexPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')

}
