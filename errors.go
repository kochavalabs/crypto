package crypto

import "errors"

var (
	// ErrPEMContentEmpty defines a generic key for Pem block empty
	ErrPEMContentEmpty = errors.New("PEM Block is empty")

	// ErrDecodeX509PEM defines a generic key for failing to decode a PEM block
	ErrDecodeX509PEM = errors.New("Unable to decode PEM Block data")

	// ErrSyntax occurs when decoding an invalid string
	ErrSyntax = errors.New("invalid hex string")
)
