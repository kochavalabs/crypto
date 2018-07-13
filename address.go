package crypto

import (
	"encoding/hex"
)

// AddressLength of address in bytes
const (
	AddressLength    = 32
	AddressHexPrefix = "0x"
)

// Address represents the 32 byte address from a sha3_256 hashed x509 encoded EC public key
type Address struct {
	// hashed value of X509 Marshalled Public Key
	value [AddressLength]byte
}

// Bytes returns the raw bytes of the address
func (addr *Address) Bytes() []byte {
	return addr.value[:]
}

// Hex returns the hex encoded representation of the address bytes
func (addr *Address) Hex() string {
	return AddressHexPrefix + hex.EncodeToString(addr.value[:])
}

// String implements fmt.Stringer
func (addr Address) String() string {
	return addr.Hex()
}

// AddressFromPublicKey returns the address of a EC public key
func AddressFromPublicKey(pubk *PublicKey) (*Address, error) {
	x509encoded, err := MarshaPublicKeyX509(pubk)
	if err != nil {
		return nil, err
	}
	hashAddress := Sha3_256(x509encoded)
	address := &Address{}
	copy(address.value[AddressLength-len(hashAddress):], hashAddress)
	return address, nil
}

// AddressFromHex returns the a Address from a hex encoded string or error
func AddressFromHex(hexEncoded string) (*Address, error) {
	if hasHexPrefix(hexEncoded) {
		hexEncoded = hexEncoded[2:] // remove prefix
	}
	hashAddress, err := hex.DecodeString(hexEncoded)
	if err != nil {
		return nil, err
	}
	address := &Address{}
	if len(hashAddress) > AddressLength {
		return nil, ErrInvalidAddressLength
	}
	copy(address.value[AddressLength-len(hashAddress):], hashAddress)
	return address, nil
}

func hasHexPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}
