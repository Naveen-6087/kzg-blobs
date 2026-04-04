package kzg

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// VerifyBlobKZGProofBatch verifies all proofs with a single two-pairing
// check over a random linear combination. An empty batch is valid.
func (c *Context) VerifyBlobKZGProofBatch(blobs []Blob, commitments []Commitment, proofs []Proof) (bool, error) {
	n := len(blobs)
	if len(commitments) != n || len(proofs) != n {
		return false, fmt.Errorf("%w: %d blobs, %d commitments, %d proofs",
			ErrLengthMismatch, n, len(commitments), len(proofs))
	}
	switch n {
	case 0:
		return true, nil
	case 1:
		return c.VerifyBlobKZGProof(&blobs[0], commitments[0], proofs[0])
	}

	cps := make([]bls12381.G1Affine, n)
	pps := make([]bls12381.G1Affine, n)
	zs := make([]fr.Element, n)
	ys := make([]fr.Element, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			errs[i] = c.prepareBatchItem(&blobs[i], commitments[i], proofs[i], &cps[i], &pps[i], &zs[i], &ys[i], i)
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return false, err
		}
	}
	return c.verifyProofBatch(cps, zs, ys, pps)
}

func (c *Context) prepareBatchItem(blob *Blob, commitment Commitment, proof Proof,
	cp, pp *bls12381.G1Affine, z, y *fr.Element, i int) error {
	var err error
	if *cp, err = bytesToG1(commitment[:]); err != nil {
		return fmt.Errorf("commitment %d: %w", i, err)
	}
	poly, err := blobToPolynomial(blob)
	if err != nil {
		return fmt.Errorf("blob %d: %w", i, err)
	}
	if *pp, err = bytesToG1(proof[:]); err != nil {
		return fmt.Errorf("proof %d: %w", i, err)
	}
	*z = computeChallenge(blob, cp)
	*y, err = c.evaluate(poly, z)
	return err
}

// verifyProofBatch checks
// e(sum r^i proof_i, [tau]_2) == e(sum r^i (C_i - [y_i]_1 + z_i proof_i), [1]_2).
func (c *Context) verifyProofBatch(commitments []bls12381.G1Affine, zs, ys []fr.Element, proofs []bls12381.G1Affine) (bool, error) {
	n := len(commitments)
	r := batchChallenge(commitments, zs, ys, proofs)
	rPowers := computePowers(&r, n)

	cMinusY := make([]bls12381.G1Affine, n)
	rTimesZ := make([]fr.Element, n)
	for i := range n {
		var yG1 bls12381.G1Affine
		yG1.ScalarMultiplicationBase(toBig(&ys[i]))
		cMinusY[i].Sub(&commitments[i], &yG1)
		rTimesZ[i].Mul(&rPowers[i], &zs[i])
	}

	var proofLincomb, proofZLincomb, cMinusYLincomb, rhs bls12381.G1Affine
	cfg := ecc.MultiExpConfig{}
	if _, err := proofLincomb.MultiExp(proofs, rPowers, cfg); err != nil {
		return false, fmt.Errorf("kzg: multi-exponentiation: %w", err)
	}
	if _, err := proofZLincomb.MultiExp(proofs, rTimesZ, cfg); err != nil {
		return false, fmt.Errorf("kzg: multi-exponentiation: %w", err)
	}
	if _, err := cMinusYLincomb.MultiExp(cMinusY, rPowers, cfg); err != nil {
		return false, fmt.Errorf("kzg: multi-exponentiation: %w", err)
	}
	rhs.Add(&cMinusYLincomb, &proofZLincomb)
	return pairingsEqual(&proofLincomb, &c.g2Tau, &rhs, &c.g2Gen)
}

func batchChallenge(commitments []bls12381.G1Affine, zs, ys []fr.Element, proofs []bls12381.G1Affine) fr.Element {
	h := sha256.New()
	h.Write([]byte(randomChallengeBatchDomain))
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], FieldElementsPerBlob)
	h.Write(u64[:])
	binary.BigEndian.PutUint64(u64[:], uint64(len(commitments)))
	h.Write(u64[:])
	for i := range commitments {
		cb := commitments[i].Bytes()
		h.Write(cb[:])
		zb := zs[i].Bytes()
		h.Write(zb[:])
		yb := ys[i].Bytes()
		h.Write(yb[:])
		pb := proofs[i].Bytes()
		h.Write(pb[:])
	}
	var digest [32]byte
	h.Sum(digest[:0])
	return hashToField(digest)
}
