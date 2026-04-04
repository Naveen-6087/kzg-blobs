package kzg

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func (c *Context) BlobToCommitment(blob *Blob) (Commitment, error) {
	poly, err := blobToPolynomial(blob)
	if err != nil {
		return Commitment{}, err
	}
	p, err := c.commit(poly)
	if err != nil {
		return Commitment{}, err
	}
	return Commitment(p.Bytes()), nil
}

// ComputeKZGProof returns a proof that the blob polynomial evaluates to y at z.
func (c *Context) ComputeKZGProof(blob *Blob, z Bytes32) (Proof, Bytes32, error) {
	poly, err := blobToPolynomial(blob)
	if err != nil {
		return Proof{}, Bytes32{}, err
	}
	zf, err := bytesToField(z[:])
	if err != nil {
		return Proof{}, Bytes32{}, fmt.Errorf("z: %w", err)
	}
	proof, y, err := c.computeProof(poly, &zf)
	if err != nil {
		return Proof{}, Bytes32{}, err
	}
	return Proof(proof.Bytes()), fieldToBytes(&y), nil
}

// ComputeBlobKZGProof opens the blob at its Fiat-Shamir challenge. The
// commitment is not checked against the blob.
func (c *Context) ComputeBlobKZGProof(blob *Blob, commitment Commitment) (Proof, error) {
	cp, err := bytesToG1(commitment[:])
	if err != nil {
		return Proof{}, fmt.Errorf("commitment: %w", err)
	}
	poly, err := blobToPolynomial(blob)
	if err != nil {
		return Proof{}, err
	}
	z := computeChallenge(blob, &cp)
	proof, _, err := c.computeProof(poly, &z)
	if err != nil {
		return Proof{}, err
	}
	return Proof(proof.Bytes()), nil
}

// VerifyKZGProof returns an error only for malformed input; a well-formed
// but wrong proof returns false.
func (c *Context) VerifyKZGProof(commitment Commitment, z, y Bytes32, proof Proof) (bool, error) {
	cp, err := bytesToG1(commitment[:])
	if err != nil {
		return false, fmt.Errorf("commitment: %w", err)
	}
	zf, err := bytesToField(z[:])
	if err != nil {
		return false, fmt.Errorf("z: %w", err)
	}
	yf, err := bytesToField(y[:])
	if err != nil {
		return false, fmt.Errorf("y: %w", err)
	}
	pp, err := bytesToG1(proof[:])
	if err != nil {
		return false, fmt.Errorf("proof: %w", err)
	}
	return c.verifyProof(&cp, &zf, &yf, &pp)
}

func (c *Context) VerifyBlobKZGProof(blob *Blob, commitment Commitment, proof Proof) (bool, error) {
	cp, err := bytesToG1(commitment[:])
	if err != nil {
		return false, fmt.Errorf("commitment: %w", err)
	}
	poly, err := blobToPolynomial(blob)
	if err != nil {
		return false, err
	}
	pp, err := bytesToG1(proof[:])
	if err != nil {
		return false, fmt.Errorf("proof: %w", err)
	}
	z := computeChallenge(blob, &cp)
	y, err := c.evaluate(poly, &z)
	if err != nil {
		return false, err
	}
	return c.verifyProof(&cp, &z, &y, &pp)
}

func ComputeChallenge(blob *Blob, commitment Commitment) (Bytes32, error) {
	cp, err := bytesToG1(commitment[:])
	if err != nil {
		return Bytes32{}, fmt.Errorf("commitment: %w", err)
	}
	z := computeChallenge(blob, &cp)
	return fieldToBytes(&z), nil
}

func computeChallenge(blob *Blob, commitment *bls12381.G1Affine) fr.Element {
	h := sha256.New()
	h.Write([]byte(fiatShamirProtocolDomain))
	var degree [16]byte
	binary.BigEndian.PutUint64(degree[8:], FieldElementsPerBlob)
	h.Write(degree[:])
	h.Write(blob[:])
	cb := commitment.Bytes()
	h.Write(cb[:])
	var digest [32]byte
	h.Sum(digest[:0])
	return hashToField(digest)
}

func (c *Context) commit(poly []fr.Element) (bls12381.G1Affine, error) {
	var p bls12381.G1Affine
	if _, err := p.MultiExp(c.g1Lagrange, poly, ecc.MultiExpConfig{}); err != nil {
		return bls12381.G1Affine{}, fmt.Errorf("kzg: multi-exponentiation: %w", err)
	}
	return p, nil
}

// evaluate uses the barycentric formula
// p(z) = (z^N - 1)/N * sum_i p_i * w_i / (z - w_i).
func (c *Context) evaluate(poly []fr.Element, z *fr.Element) (fr.Element, error) {
	if len(poly) != FieldElementsPerBlob {
		return fr.Element{}, fmt.Errorf("kzg: polynomial has %d evaluations, want %d", len(poly), FieldElementsPerBlob)
	}
	if i, ok := c.rootIndex[*z]; ok {
		return poly[i], nil
	}

	denominators := make([]fr.Element, FieldElementsPerBlob)
	for i := range denominators {
		denominators[i].Sub(z, &c.rootsBRP[i])
	}
	inverses := fr.BatchInvert(denominators)

	var sum, term fr.Element
	for i := range poly {
		term.Mul(&inverses[i], &c.rootsBRP[i])
		term.Mul(&term, &poly[i])
		sum.Add(&sum, &term)
	}

	var width, zN, one fr.Element
	width.SetUint64(FieldElementsPerBlob)
	width.Inverse(&width)
	sum.Mul(&sum, &width)
	zN.Exp(*z, bigFieldElementsPerBlob)
	one.SetOne()
	zN.Sub(&zN, &one)
	sum.Mul(&sum, &zN)
	return sum, nil
}

// computeProof commits to q(X) = (p(X) - y) / (X - z) in evaluation form.
func (c *Context) computeProof(poly []fr.Element, z *fr.Element) (bls12381.G1Affine, fr.Element, error) {
	y, err := c.evaluate(poly, z)
	if err != nil {
		return bls12381.G1Affine{}, fr.Element{}, err
	}

	m, inDomain := c.rootIndex[*z]
	quotient := make([]fr.Element, FieldElementsPerBlob)
	denominators := make([]fr.Element, FieldElementsPerBlob)
	for i := range quotient {
		if inDomain && i == m {
			denominators[i].SetOne()
			continue
		}
		quotient[i].Sub(&poly[i], &y)
		denominators[i].Sub(&c.rootsBRP[i], z)
	}
	inverses := fr.BatchInvert(denominators)
	for i := range quotient {
		quotient[i].Mul(&quotient[i], &inverses[i])
	}

	if inDomain {
		// z = w_m makes q(w_m) a 0/0; the spec computes it as
		// sum_{i != m} (p_i - y) * w_i / (z * (z - w_i)).
		quotient[m].SetZero()
		for i := range denominators {
			if i == m {
				denominators[i].SetOne()
				continue
			}
			denominators[i].Sub(z, &c.rootsBRP[i])
			denominators[i].Mul(&denominators[i], z)
		}
		inverses = fr.BatchInvert(denominators)
		var term fr.Element
		for i := range poly {
			if i == m {
				continue
			}
			term.Sub(&poly[i], &y)
			term.Mul(&term, &c.rootsBRP[i])
			term.Mul(&term, &inverses[i])
			quotient[m].Add(&quotient[m], &term)
		}
	}

	proof, err := c.commit(quotient)
	if err != nil {
		return bls12381.G1Affine{}, fr.Element{}, err
	}
	return proof, y, nil
}

// verifyProof checks e(C - [y]_1, [1]_2) == e(proof, [tau]_2 - [z]_2).
func (c *Context) verifyProof(commitment *bls12381.G1Affine, z, y *fr.Element, proof *bls12381.G1Affine) (bool, error) {
	var zG2, xMinusZ bls12381.G2Affine
	zG2.ScalarMultiplicationBase(toBig(z))
	xMinusZ.Sub(&c.g2Tau, &zG2)

	var yG1, pMinusY bls12381.G1Affine
	yG1.ScalarMultiplicationBase(toBig(y))
	pMinusY.Sub(commitment, &yG1)

	return pairingsEqual(&pMinusY, &c.g2Gen, proof, &xMinusZ)
}
