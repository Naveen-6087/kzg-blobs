package kzg

import "errors"

var (
	ErrNonCanonicalFieldElement = errors.New("kzg: field element is not canonical")
	ErrInvalidG1                = errors.New("kzg: invalid G1 point encoding")
	ErrLengthMismatch           = errors.New("kzg: input lengths do not match")
	ErrInvalidSetup             = errors.New("kzg: invalid trusted setup")
)
