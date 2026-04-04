package kzg

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

//go:embed trusted_setup.txt
var mainnetSetup []byte

// Context holds a validated trusted setup. It is immutable and safe for
// concurrent use.
type Context struct {
	g1Lagrange []bls12381.G1Affine // bit-reversed, like blob elements
	g2Gen      bls12381.G2Affine
	g2Tau      bls12381.G2Affine
	g1Gen      bls12381.G1Affine
	rootsBRP   []fr.Element
	rootIndex  map[fr.Element]int
}

var (
	defaultOnce sync.Once
	defaultCtx  *Context
	defaultErr  error
)

// DefaultContext returns a shared Context for the embedded mainnet setup.
func DefaultContext() (*Context, error) {
	defaultOnce.Do(func() {
		defaultCtx, defaultErr = NewContext(bytes.NewReader(mainnetSetup))
	})
	return defaultCtx, defaultErr
}

func LoadContextFile(path string) (*Context, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return NewContext(f)
}

// NewContext parses a setup in c-kzg-4844 text format: the G1 and G2 counts,
// 4096 G1 Lagrange points, 65 G2 monomial points, and an optional trailing
// section of 4096 G1 monomial points (EIP-7594 data, ignored here).
func NewContext(r io.Reader) (*Context, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256), 1<<20)
	sc.Split(bufio.ScanWords)

	next := func(what string) (string, error) {
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return "", fmt.Errorf("%w: reading %s: %v", ErrInvalidSetup, what, err)
			}
			return "", fmt.Errorf("%w: unexpected end of input reading %s", ErrInvalidSetup, what)
		}
		return sc.Text(), nil
	}
	readCount := func(what string, want int) error {
		tok, err := next(what)
		if err != nil {
			return err
		}
		n, err := strconv.Atoi(tok)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalidSetup, what, err)
		}
		if n != want {
			return fmt.Errorf("%w: %s is %d, want %d", ErrInvalidSetup, what, n, want)
		}
		return nil
	}

	if err := readCount("G1 point count", FieldElementsPerBlob); err != nil {
		return nil, err
	}
	if err := readCount("G2 point count", numG2Points); err != nil {
		return nil, err
	}

	g1Raw := make([][]byte, FieldElementsPerBlob)
	for i := range g1Raw {
		tok, err := next("G1 Lagrange point")
		if err != nil {
			return nil, err
		}
		if g1Raw[i], err = decodeHexPoint(tok, BytesPerCommitment); err != nil {
			return nil, fmt.Errorf("%w: G1 Lagrange point %d: %v", ErrInvalidSetup, i, err)
		}
	}
	g2 := make([]bls12381.G2Affine, numG2Points)
	for i := range g2 {
		tok, err := next("G2 monomial point")
		if err != nil {
			return nil, err
		}
		raw, err := decodeHexPoint(tok, BytesPerG2)
		if err != nil {
			return nil, fmt.Errorf("%w: G2 point %d: %v", ErrInvalidSetup, i, err)
		}
		if _, err := g2[i].SetBytes(raw); err != nil {
			return nil, fmt.Errorf("%w: G2 point %d: %v", ErrInvalidSetup, i, err)
		}
	}

	extra := 0
	for sc.Scan() {
		if len(sc.Text()) != 2*BytesPerCommitment {
			return nil, fmt.Errorf("%w: malformed trailing G1 monomial point %d", ErrInvalidSetup, extra)
		}
		extra++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSetup, err)
	}
	if extra != 0 && extra != FieldElementsPerBlob {
		return nil, fmt.Errorf("%w: found %d trailing G1 monomial points, want 0 or %d",
			ErrInvalidSetup, extra, FieldElementsPerBlob)
	}

	g1, err := decodeG1Parallel(g1Raw)
	if err != nil {
		return nil, err
	}
	return newContext(g1, g2[0], g2[1])
}

func newContext(g1Natural []bls12381.G1Affine, g2Gen, g2Tau bls12381.G2Affine) (*Context, error) {
	_, _, g1Gen, expectedG2Gen := bls12381.Generators()
	if !g2Gen.Equal(&expectedG2Gen) {
		return nil, fmt.Errorf("%w: first G2 point is not the generator", ErrInvalidSetup)
	}

	// Same sanity check as c-kzg-4844: for monomial points
	// e([tau]_1, [1]_2) == e([1]_1, [tau]_2), for Lagrange points it fails.
	isMonomial, err := pairingsEqual(&g1Natural[1], &g2Gen, &g1Natural[0], &g2Tau)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSetup, err)
	}
	if isMonomial {
		return nil, fmt.Errorf("%w: G1 points are in monomial form, want Lagrange form", ErrInvalidSetup)
	}

	g1 := make([]bls12381.G1Affine, len(g1Natural))
	copy(g1, g1Natural)
	bitReversalPermutation(g1)

	roots := computeRootsOfUnity(FieldElementsPerBlob)
	bitReversalPermutation(roots)
	index := make(map[fr.Element]int, len(roots))
	for i, root := range roots {
		index[root] = i
	}

	return &Context{
		g1Lagrange: g1,
		g2Gen:      g2Gen,
		g2Tau:      g2Tau,
		g1Gen:      g1Gen,
		rootsBRP:   roots,
		rootIndex:  index,
	}, nil
}

func decodeHexPoint(tok string, size int) ([]byte, error) {
	if len(tok) >= 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X') {
		tok = tok[2:]
	}
	if len(tok) != 2*size {
		return nil, fmt.Errorf("want %d hex characters, got %d", 2*size, len(tok))
	}
	return hex.DecodeString(tok)
}

func decodeG1Parallel(raw [][]byte) ([]bls12381.G1Affine, error) {
	out := make([]bls12381.G1Affine, len(raw))
	workers := min(runtime.GOMAXPROCS(0), len(raw))
	errs := make([]error, workers)
	var wg sync.WaitGroup
	chunk := (len(raw) + workers - 1) / workers
	for w := range workers {
		lo, hi := w*chunk, min((w+1)*chunk, len(raw))
		wg.Go(func() {
			for i := lo; i < hi; i++ {
				if _, err := out[i].SetBytes(raw[i]); err != nil {
					errs[w] = fmt.Errorf("%w: G1 Lagrange point %d: %v", ErrInvalidSetup, i, err)
					return
				}
			}
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
