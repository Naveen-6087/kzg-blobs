package kzg

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
	"testing/quick"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func randomBlob(r *rand.Rand) *Blob {
	var blob Blob
	for i := range FieldElementsPerBlob {
		var e fr.Element
		e.SetUint64(r.Uint64())
		var hi fr.Element
		hi.SetUint64(r.Uint64())
		e.Mul(&e, &hi) // spread over the whole field
		b := e.Bytes()
		copy(blob[i*32:], b[:])
	}
	return &blob
}

func randomField(r *rand.Rand) Bytes32 {
	var raw [32]byte
	for i := range 4 {
		v := r.Uint64()
		for j := range 8 {
			raw[i*8+j] = byte(v >> (8 * j))
		}
	}
	var e fr.Element
	e.SetBytes(raw[:]) // reduce mod r
	return fieldToBytes(&e)
}

func TestRootsOfUnity(t *testing.T) {
	roots := computeRootsOfUnity(FieldElementsPerBlob)
	var one fr.Element
	one.SetOne()
	if !roots[0].Equal(&one) {
		t.Fatal("roots[0] != 1")
	}
	var w4096, w2048, minusOne fr.Element
	w4096.Exp(roots[1], bigFieldElementsPerBlob)
	if !w4096.Equal(&one) {
		t.Fatal("w^4096 != 1")
	}
	w2048 = roots[2048]
	minusOne.Neg(&one)
	if !w2048.Equal(&minusOne) {
		t.Fatal("w^2048 != -1")
	}
	seen := make(map[fr.Element]bool)
	for _, r := range roots {
		if seen[r] {
			t.Fatal("duplicate root")
		}
		seen[r] = true
	}
}

func TestBitReversalPermutation(t *testing.T) {
	s := []int{0, 1, 2, 3, 4, 5, 6, 7}
	bitReversalPermutation(s)
	want := []int{0, 4, 2, 6, 1, 5, 3, 7}
	for i := range s {
		if s[i] != want[i] {
			t.Fatalf("got %v, want %v", s, want)
		}
	}
	bitReversalPermutation(s)
	for i := range s {
		if s[i] != i {
			t.Fatalf("not an involution: %v", s)
		}
	}
	single := []int{42}
	bitReversalPermutation(single)
	if single[0] != 42 {
		t.Fatal("length-1 permutation changed the slice")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for non power of two")
		}
	}()
	bitReversalPermutation(make([]int, 6))
}

func TestBytesToField(t *testing.T) {
	mod := Modulus()
	if _, err := bytesToField(mod[:]); !errors.Is(err, ErrNonCanonicalFieldElement) {
		t.Fatalf("modulus accepted: %v", err)
	}
	modMinusOne := mod
	modMinusOne[31]--
	if _, err := bytesToField(modMinusOne[:]); err != nil {
		t.Fatalf("modulus-1 rejected: %v", err)
	}
	all := bytes.Repeat([]byte{0xff}, 32)
	if _, err := bytesToField(all); err == nil {
		t.Fatal("2^256-1 accepted")
	}
}

func TestBytesToG1(t *testing.T) {
	var inf Commitment
	inf[0] = 0xc0
	p, err := bytesToG1(inf[:])
	if err != nil || !p.IsInfinity() {
		t.Fatalf("infinity rejected: %v", err)
	}
	_, _, g1, _ := bls12381.Generators()
	gen := g1.Bytes()
	if _, err := bytesToG1(gen[:]); err != nil {
		t.Fatalf("generator rejected: %v", err)
	}
	cases := map[string][]byte{
		"short":                  gen[:47],
		"long":                   append(gen[:], 0),
		"uncompressed flag":      append([]byte{gen[0] &^ 0x80}, gen[1:]...),
		"infinity with data":     append([]byte{0xc0}, bytes.Repeat([]byte{1}, 47)...),
		"infinity with sign bit": append([]byte{0xe0}, make([]byte, 47)...),
		"x not on curve":         append([]byte{0x80}, bytes.Repeat([]byte{0}, 46)...),
	}
	cases["x not on curve"] = append(cases["x not on curve"], 0x03)
	for name, b := range cases {
		if _, err := bytesToG1(b); !errors.Is(err, ErrInvalidG1) {
			t.Errorf("%s: got %v, want ErrInvalidG1", name, err)
		}
	}
}

func TestSetupInvariants(t *testing.T) {
	ctx := mustContext(t)
	if len(ctx.g1Lagrange) != FieldElementsPerBlob || len(ctx.rootsBRP) != FieldElementsPerBlob {
		t.Fatal("wrong setup size")
	}
	var sum bls12381.G1Jac
	for i := range ctx.g1Lagrange {
		sum.AddMixed(&ctx.g1Lagrange[i])
	}
	var sumAff bls12381.G1Affine
	sumAff.FromJacobian(&sum)
	if !sumAff.Equal(&ctx.g1Gen) {
		t.Fatal("Lagrange points do not sum to the generator")
	}
	again, err := DefaultContext()
	if err != nil || again != ctx {
		t.Fatal("DefaultContext is not cached")
	}
}

func TestNewContextRejectsMalformed(t *testing.T) {
	good := string(mainnetSetup)
	lines := strings.Fields(good)
	cases := map[string]string{
		"empty":            "",
		"wrong g1 count":   "4095\n65\n",
		"wrong g2 count":   "4096\n64\n",
		"not a number":     "abc\n65\n",
		"truncated g1":     strings.Join(lines[:100], "\n"),
		"truncated g2":     strings.Join(lines[:2+4096+10], "\n"),
		"bad hex":          strings.Join(append(append([]string{}, lines[:2]...), append([]string{strings.Repeat("zz", 48)}, lines[3:]...)...), "\n"),
		"partial monomial": strings.Join(lines[:2+4096+65+10], "\n"),
	}
	for name, input := range cases {
		if _, err := NewContext(strings.NewReader(input)); !errors.Is(err, ErrInvalidSetup) {
			t.Errorf("%s: got %v, want ErrInvalidSetup", name, err)
		}
	}
	legacy := strings.Join(lines[:2+4096+65], "\n")
	if _, err := NewContext(strings.NewReader(legacy)); err != nil {
		t.Fatalf("legacy setup rejected: %v", err)
	}
	monomial := append(append([]string{}, lines[:2]...), lines[2+4096+65:]...)
	monomial = append(monomial, lines[2+4096:2+4096+65]...)
	if _, err := NewContext(strings.NewReader(strings.Join(monomial, "\n"))); !errors.Is(err, ErrInvalidSetup) {
		t.Fatalf("monomial-form setup accepted: %v", err)
	}
}

func TestPropertyBlobProofRoundTrip(t *testing.T) {
	ctx := mustContext(t)
	r := rand.New(rand.NewPCG(1, 2))
	for range 4 {
		blob := randomBlob(r)
		c, err := ctx.BlobToCommitment(blob)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := ctx.ComputeBlobKZGProof(blob, c)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := ctx.VerifyBlobKZGProof(blob, c, proof)
		if err != nil || !ok {
			t.Fatalf("valid proof rejected: %v", err)
		}
	}
}

func TestPropertyOpeningProof(t *testing.T) {
	ctx := mustContext(t)
	r := rand.New(rand.NewPCG(3, 4))
	blob := randomBlob(r)
	commitment, err := ctx.BlobToCommitment(blob)
	if err != nil {
		t.Fatal(err)
	}
	poly, _ := blobToPolynomial(blob)

	points := []Bytes32{randomField(r), randomField(r)}
	for _, i := range []int{0, 1, 4095, r.IntN(FieldElementsPerBlob)} {
		points = append(points, fieldToBytes(&ctx.rootsBRP[i]))
	}
	for _, z := range points {
		proof, y, err := ctx.ComputeKZGProof(blob, z)
		if err != nil {
			t.Fatal(err)
		}
		zf, _ := bytesToField(z[:])
		direct := naiveEvaluate(ctx, poly, &zf)
		if fieldToBytes(&direct) != y {
			t.Fatalf("barycentric evaluation disagrees with Lagrange interpolation at %x", z)
		}
		ok, err := ctx.VerifyKZGProof(commitment, z, y, proof)
		if err != nil || !ok {
			t.Fatalf("proof at %x rejected: %v", z, err)
		}
		var yf fr.Element
		yf.SetBytes(y[:])
		var one fr.Element
		one.SetOne()
		yf.Add(&yf, &one)
		ok, err = ctx.VerifyKZGProof(commitment, z, fieldToBytes(&yf), proof)
		if err != nil || ok {
			t.Fatalf("proof for y+1 accepted at %x", z)
		}
	}
}

var lagrangeDenominators []fr.Element

// naiveEvaluate is a textbook O(n^2) Lagrange evaluation used to cross-check
// the barycentric formula independently.
func naiveEvaluate(ctx *Context, poly []fr.Element, z *fr.Element) fr.Element {
	if i, ok := ctx.rootIndex[*z]; ok {
		return poly[i]
	}
	w := ctx.rootsBRP
	if lagrangeDenominators == nil {
		dens := make([]fr.Element, len(w))
		for i := range w {
			dens[i].SetOne()
			var d fr.Element
			for j := range w {
				if i != j {
					d.Sub(&w[i], &w[j])
					dens[i].Mul(&dens[i], &d)
				}
			}
		}
		lagrangeDenominators = fr.BatchInvert(dens)
	}
	var full fr.Element
	full.SetOne()
	diffs := make([]fr.Element, len(w))
	for j := range w {
		diffs[j].Sub(z, &w[j])
		full.Mul(&full, &diffs[j])
	}
	invDiffs := fr.BatchInvert(diffs)
	var sum fr.Element
	for i := range poly {
		var li fr.Element
		li.Mul(&full, &invDiffs[i]) // prod_{j!=i} (z - w_j)
		li.Mul(&li, &lagrangeDenominators[i])
		li.Mul(&li, &poly[i])
		sum.Add(&sum, &li)
	}
	return sum
}

func TestPropertyCommitmentHomomorphism(t *testing.T) {
	ctx := mustContext(t)
	r := rand.New(rand.NewPCG(5, 6))
	a, b := randomBlob(r), randomBlob(r)
	pa, _ := blobToPolynomial(a)
	pb, _ := blobToPolynomial(b)
	var sum Blob
	for i := range pa {
		var s fr.Element
		s.Add(&pa[i], &pb[i])
		e := s.Bytes()
		copy(sum[i*32:], e[:])
	}
	ca, _ := ctx.BlobToCommitment(a)
	cb, _ := ctx.BlobToCommitment(b)
	cs, _ := ctx.BlobToCommitment(&sum)
	pca, _ := bytesToG1(ca[:])
	pcb, _ := bytesToG1(cb[:])
	var added bls12381.G1Affine
	added.Add(&pca, &pcb)
	if Commitment(added.Bytes()) != cs {
		t.Fatal("commitment is not homomorphic")
	}
}

func TestPropertyBatch(t *testing.T) {
	ctx := mustContext(t)
	r := rand.New(rand.NewPCG(7, 8))
	const n = 4
	blobs := make([]Blob, n)
	commitments := make([]Commitment, n)
	proofs := make([]Proof, n)
	for i := range n {
		blobs[i] = *randomBlob(r)
		commitments[i], _ = ctx.BlobToCommitment(&blobs[i])
		proofs[i], _ = ctx.ComputeBlobKZGProof(&blobs[i], commitments[i])
	}
	ok, err := ctx.VerifyBlobKZGProofBatch(blobs, commitments, proofs)
	if err != nil || !ok {
		t.Fatalf("valid batch rejected: %v", err)
	}
	for i := range n {
		bad := append([]Proof(nil), proofs...)
		bad[i] = proofs[(i+1)%n]
		if ok, err := ctx.VerifyBlobKZGProofBatch(blobs, commitments, bad); err != nil || ok {
			t.Fatalf("batch with swapped proof %d accepted (err %v)", i, err)
		}
		badBlobs := append([]Blob(nil), blobs...)
		badBlobs[i][31] ^= 1
		if ok, err := ctx.VerifyBlobKZGProofBatch(badBlobs, commitments, proofs); err != nil || ok {
			t.Fatalf("batch with modified blob %d accepted (err %v)", i, err)
		}
	}
	if _, err := ctx.VerifyBlobKZGProofBatch(blobs, commitments[:n-1], proofs); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("length mismatch not reported: %v", err)
	}
}

func TestQuickChallengeBindsBlob(t *testing.T) {
	var inf Commitment
	inf[0] = 0xc0
	f := func(index uint16, value byte) bool {
		var blob Blob
		before, err := ComputeChallenge(&blob, inf)
		if err != nil {
			return false
		}
		again, _ := ComputeChallenge(&blob, inf)
		blob[int(index)%BytesPerBlob] ^= value | 1
		after, _ := ComputeChallenge(&blob, inf)
		return before == again && before != after
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Fatal(err)
	}
}

func TestZeroBlobCommitsToInfinity(t *testing.T) {
	ctx := mustContext(t)
	var blob Blob
	c, err := ctx.BlobToCommitment(&blob)
	if err != nil {
		t.Fatal(err)
	}
	if c[0] != 0xc0 || !bytes.Equal(c[1:], make([]byte, 47)) {
		t.Fatalf("zero blob committed to %x", c)
	}
}

func TestNonCanonicalBlobRejected(t *testing.T) {
	ctx := mustContext(t)
	var blob Blob
	mod := Modulus()
	copy(blob[100*32:], mod[:])
	if _, err := ctx.BlobToCommitment(&blob); !errors.Is(err, ErrNonCanonicalFieldElement) {
		t.Fatalf("got %v", err)
	}
	if _, _, err := ctx.ComputeKZGProof(&blob, Bytes32{}); !errors.Is(err, ErrNonCanonicalFieldElement) {
		t.Fatalf("got %v", err)
	}
}

func TestConcurrentUse(t *testing.T) {
	ctx := mustContext(t)
	r := rand.New(rand.NewPCG(9, 10))
	blob := randomBlob(r)
	c, _ := ctx.BlobToCommitment(blob)
	proof, _ := ctx.ComputeBlobKZGProof(blob, c)
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			ok, err := ctx.VerifyBlobKZGProof(blob, c, proof)
			if err == nil && !ok {
				err = errors.New("verification failed")
			}
			errs <- err
		}()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func FuzzVerifyKZGProof(f *testing.F) {
	var inf [48]byte
	inf[0] = 0xc0
	f.Add(inf[:], make([]byte, 32), make([]byte, 32), inf[:])
	ctx := mustContext(f)
	f.Fuzz(func(t *testing.T, c, z, y, p []byte) {
		if len(c) != 48 || len(z) != 32 || len(y) != 32 || len(p) != 48 {
			return
		}
		ok, err := ctx.VerifyKZGProof(Commitment(c), Bytes32(z), Bytes32(y), Proof(p))
		if err != nil && ok {
			t.Fatal("returned true together with an error")
		}
	})
}

func FuzzBytesToG1(f *testing.F) {
	_, _, g1, _ := bls12381.Generators()
	gen := g1.Bytes()
	f.Add(gen[:])
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := bytesToG1(b)
		if err != nil {
			return
		}
		if enc := p.Bytes(); !bytes.Equal(enc[:], b) {
			t.Fatalf("non-canonical encoding accepted: %x re-encodes to %x", b, enc)
		}
		if !p.IsInfinity() && !p.IsInSubGroup() {
			t.Fatal("point outside the subgroup accepted")
		}
	})
}
