package kzg

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"
)

func benchFixtures(b *testing.B, n int) (*Context, []Blob, []Commitment, []Proof) {
	b.Helper()
	ctx := mustContext(b)
	r := rand.New(rand.NewPCG(42, uint64(n)))
	blobs := make([]Blob, n)
	commitments := make([]Commitment, n)
	proofs := make([]Proof, n)
	for i := range n {
		blobs[i] = *randomBlob(r)
		var err error
		if commitments[i], err = ctx.BlobToCommitment(&blobs[i]); err != nil {
			b.Fatal(err)
		}
		if proofs[i], err = ctx.ComputeBlobKZGProof(&blobs[i], commitments[i]); err != nil {
			b.Fatal(err)
		}
	}
	return ctx, blobs, commitments, proofs
}

func BenchmarkLoadTrustedSetup(b *testing.B) {
	for b.Loop() {
		if _, err := NewContext(bytes.NewReader(mainnetSetup)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBlobToCommitment(b *testing.B) {
	ctx, blobs, _, _ := benchFixtures(b, 1)
	for b.Loop() {
		if _, err := ctx.BlobToCommitment(&blobs[0]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkComputeKZGProof(b *testing.B) {
	ctx, blobs, _, _ := benchFixtures(b, 1)
	z := randomField(rand.New(rand.NewPCG(1, 1)))
	for b.Loop() {
		if _, _, err := ctx.ComputeKZGProof(&blobs[0], z); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkComputeBlobKZGProof(b *testing.B) {
	ctx, blobs, commitments, _ := benchFixtures(b, 1)
	for b.Loop() {
		if _, err := ctx.ComputeBlobKZGProof(&blobs[0], commitments[0]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyKZGProof(b *testing.B) {
	ctx, blobs, commitments, _ := benchFixtures(b, 1)
	z := randomField(rand.New(rand.NewPCG(2, 2)))
	proof, y, err := ctx.ComputeKZGProof(&blobs[0], z)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if ok, err := ctx.VerifyKZGProof(commitments[0], z, y, proof); err != nil || !ok {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkVerifyBlobKZGProof(b *testing.B) {
	ctx, blobs, commitments, proofs := benchFixtures(b, 1)
	for b.Loop() {
		if ok, err := ctx.VerifyBlobKZGProof(&blobs[0], commitments[0], proofs[0]); err != nil || !ok {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkVerifyBlobKZGProofBatch(b *testing.B) {
	for _, n := range []int{1, 2, 4, 6, 9, 16} {
		ctx, blobs, commitments, proofs := benchFixtures(b, n)
		b.Run(fmt.Sprintf("batch/n=%d", n), func(b *testing.B) {
			for b.Loop() {
				if ok, err := ctx.VerifyBlobKZGProofBatch(blobs, commitments, proofs); err != nil || !ok {
					b.Fatal("verification failed")
				}
			}
		})
		b.Run(fmt.Sprintf("individual/n=%d", n), func(b *testing.B) {
			for b.Loop() {
				for i := range n {
					if ok, err := ctx.VerifyBlobKZGProof(&blobs[i], commitments[i], proofs[i]); err != nil || !ok {
						b.Fatal("verification failed")
					}
				}
			}
		})
	}
}

func BenchmarkComputeChallenge(b *testing.B) {
	_, blobs, commitments, _ := benchFixtures(b, 1)
	for b.Loop() {
		if _, err := ComputeChallenge(&blobs[0], commitments[0]); err != nil {
			b.Fatal(err)
		}
	}
}
