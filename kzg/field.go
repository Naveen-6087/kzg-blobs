package kzg

import (
	"fmt"
	"math/big"
	"math/bits"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var bigFieldElementsPerBlob = big.NewInt(FieldElementsPerBlob)

func bytesToField(b []byte) (fr.Element, error) {
	var e fr.Element
	if err := e.SetBytesCanonical(b); err != nil {
		return fr.Element{}, ErrNonCanonicalFieldElement
	}
	return e, nil
}

func hashToField(h [32]byte) fr.Element {
	var e fr.Element
	e.SetBytes(h[:])
	return e
}

func fieldToBytes(e *fr.Element) Bytes32 {
	return Bytes32(e.Bytes())
}

// bytesToG1 accepts the point at infinity; any other point must be a
// canonical compressed encoding in the prime-order subgroup.
func bytesToG1(b []byte) (bls12381.G1Affine, error) {
	var p bls12381.G1Affine
	if len(b) != BytesPerCommitment {
		return p, fmt.Errorf("%w: want %d bytes, got %d", ErrInvalidG1, BytesPerCommitment, len(b))
	}
	if _, err := p.SetBytes(b); err != nil {
		return bls12381.G1Affine{}, fmt.Errorf("%w: %v", ErrInvalidG1, err)
	}
	return p, nil
}

func blobToPolynomial(blob *Blob) ([]fr.Element, error) {
	poly := make([]fr.Element, FieldElementsPerBlob)
	for i := range poly {
		chunk := blob[i*BytesPerFieldElement : (i+1)*BytesPerFieldElement]
		if err := poly[i].SetBytesCanonical(chunk); err != nil {
			return nil, fmt.Errorf("%w: blob element %d", ErrNonCanonicalFieldElement, i)
		}
	}
	return poly, nil
}

func toBig(e *fr.Element) *big.Int {
	return e.BigInt(new(big.Int))
}

// computeRootsOfUnity returns [w^0, ..., w^(n-1)] for w = 7^((r-1)/n).
func computeRootsOfUnity(n uint64) []fr.Element {
	exp := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	exp.Div(exp, new(big.Int).SetUint64(n))

	var generator, root fr.Element
	generator.SetUint64(primitiveRootOfUnity)
	root.Exp(generator, exp)

	roots := make([]fr.Element, n)
	roots[0].SetOne()
	for i := uint64(1); i < n; i++ {
		roots[i].Mul(&roots[i-1], &root)
	}
	return roots
}

func isPowerOfTwo(n int) bool {
	return n > 0 && n&(n-1) == 0
}

func reverseBits(n uint64, order int) uint64 {
	return bits.Reverse64(n) >> (64 - order)
}

func bitReversalPermutation[T any](s []T) {
	if !isPowerOfTwo(len(s)) {
		panic("kzg: bit reversal permutation requires a power-of-two length")
	}
	if len(s) == 1 {
		return
	}
	order := bits.TrailingZeros(uint(len(s)))
	for i := range s {
		j := int(reverseBits(uint64(i), order))
		if i < j {
			s[i], s[j] = s[j], s[i]
		}
	}
}

func computePowers(x *fr.Element, n int) []fr.Element {
	powers := make([]fr.Element, n)
	if n == 0 {
		return powers
	}
	powers[0].SetOne()
	for i := 1; i < n; i++ {
		powers[i].Mul(&powers[i-1], x)
	}
	return powers
}

// pairingsEqual checks e(a1, a2) == e(b1, b2) as e(-a1, a2) * e(b1, b2) == 1.
func pairingsEqual(a1 *bls12381.G1Affine, a2 *bls12381.G2Affine, b1 *bls12381.G1Affine, b2 *bls12381.G2Affine) (bool, error) {
	var negA1 bls12381.G1Affine
	negA1.Neg(a1)
	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{negA1, *b1},
		[]bls12381.G2Affine{*a2, *b2},
	)
	if err != nil {
		return false, fmt.Errorf("kzg: pairing check: %w", err)
	}
	return ok, nil
}
