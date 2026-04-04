package kzg

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

const (
	FieldElementsPerBlob = 4096
	BytesPerFieldElement = 32
	BytesPerBlob         = FieldElementsPerBlob * BytesPerFieldElement
	BytesPerCommitment   = 48
	BytesPerProof        = 48
	BytesPerG2           = 96

	numG2Points          = 65
	primitiveRootOfUnity = 7
)

const (
	fiatShamirProtocolDomain   = "FSBLOBVERIFY_V1_"
	randomChallengeBatchDomain = "RCKZGBATCH___V1_"
)

type (
	Blob       [BytesPerBlob]byte
	Commitment [BytesPerCommitment]byte
	Proof      [BytesPerProof]byte
	Bytes32    [32]byte
)

// Modulus returns the BLS12-381 scalar field modulus, big-endian.
func Modulus() Bytes32 {
	var out Bytes32
	fr.Modulus().FillBytes(out[:])
	return out
}
