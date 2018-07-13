package crypto

import "errors"

var (
	// ErrInvalidAddressLength defines a generic key for address lengths
	ErrInvalidAddressLength = errors.New("Invaild Address Length")

	// ErrPEMContentEmpty defines a generic key for Pem block empty
	ErrPEMContentEmpty = errors.New("PEM Block is empty")

	// ErrDecodeX509PEM defines a generic key for failing to decode a PEM block
	ErrDecodeX509PEM = errors.New("Unable to decode PEM Block data")
)
