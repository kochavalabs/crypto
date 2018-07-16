package crypto

// AddressLength of address in bytes
const (
	AddressLength = 32
)

// Address represents a 32 byte address
type Address struct {
	hash Hash
}

// Bytes returns the raw bytes of the address
func (addr Address) Bytes() []byte {
	return addr.hash.Bytes()
}

// Hex returns the hex encoded representation of the address bytes
func (addr Address) Hex() string {
	return addr.hash.Hex()
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
	copy(address.hash.value[AddressLength-len(hashAddress):], hashAddress)
	return address, nil
}

// AddressFromHex returns the Address from a hex encoded string or error
func AddressFromHex(hexEncoded string) (*Address, error) {

	// Hex To Hash is guaranteed to return 32 byte hash cropped from left if needed.
	hashAddress, err := HexToHash(hexEncoded)
	if err != nil {
		return nil, err
	}

	return &Address{hash: hashAddress}, nil
}

// AddressFromBytes returns the Address from the bytes
func AddressFromBytes(b []byte) *Address {
	address := &Address{}
	address.hash = BytesToHash(b)
	return address
}

// IsHexAddress verifies whether a string can represent a valid hex-encoded
// address or not.
func IsHexAddress(s string) bool {
	if hasHexPrefix(s) {
		s = s[2:]
	}
	return len(s) == 2*AddressLength && isHex(s)
}
