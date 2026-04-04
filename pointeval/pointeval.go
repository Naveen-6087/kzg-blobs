package pointeval

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Naveen-6087/kzg-blobs/kzg"
)

const (
	Address                 = 0x0a
	Gas                     = 50000
	InputLength             = 192
	VersionedHashVersionKZG = 0x01
)

var (
	ErrInputLength           = errors.New("pointeval: invalid input length")
	ErrVersionedHashMismatch = errors.New("pointeval: versioned hash does not match commitment")
	ErrProofFailed           = errors.New("pointeval: proof verification failed")
)

// VersionedHash returns 0x01 || sha256(commitment)[1:].
func VersionedHash(c kzg.Commitment) [32]byte {
	h := sha256.Sum256(c[:])
	h[0] = VersionedHashVersionKZG
	return h
}

// Input is versioned_hash (32) || z (32) || y (32) || commitment (48) || proof (48).
type Input struct {
	VersionedHash [32]byte
	Z, Y          kzg.Bytes32
	Commitment    kzg.Commitment
	Proof         kzg.Proof
}

func ParseInput(data []byte) (Input, error) {
	var in Input
	if len(data) != InputLength {
		return in, fmt.Errorf("%w: got %d bytes, want %d", ErrInputLength, len(data), InputLength)
	}
	copy(in.VersionedHash[:], data[0:32])
	copy(in.Z[:], data[32:64])
	copy(in.Y[:], data[64:96])
	copy(in.Commitment[:], data[96:144])
	copy(in.Proof[:], data[144:192])
	return in, nil
}

func (in Input) Encode() []byte {
	out := make([]byte, 0, InputLength)
	out = append(out, in.VersionedHash[:]...)
	out = append(out, in.Z[:]...)
	out = append(out, in.Y[:]...)
	out = append(out, in.Commitment[:]...)
	out = append(out, in.Proof[:]...)
	return out
}

// ReturnValue is uint256(FIELD_ELEMENTS_PER_BLOB) || uint256(BLS_MODULUS).
func ReturnValue() []byte {
	out := make([]byte, 64)
	binary.BigEndian.PutUint64(out[24:32], kzg.FieldElementsPerBlob)
	mod := kzg.Modulus()
	copy(out[32:], mod[:])
	return out
}

// Run executes the precompile; any error means the call fails.
func Run(ctx *kzg.Context, data []byte) ([]byte, error) {
	in, err := ParseInput(data)
	if err != nil {
		return nil, err
	}
	if VersionedHash(in.Commitment) != in.VersionedHash {
		return nil, ErrVersionedHashMismatch
	}
	ok, err := ctx.VerifyKZGProof(in.Commitment, in.Z, in.Y, in.Proof)
	if err != nil {
		return nil, fmt.Errorf("pointeval: %w", err)
	}
	if !ok {
		return nil, ErrProofFailed
	}
	return ReturnValue(), nil
}
