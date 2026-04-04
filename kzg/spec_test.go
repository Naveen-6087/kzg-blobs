package kzg

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func specTestDir() string {
	if dir := os.Getenv("KZG_SPEC_TESTS_DIR"); dir != "" {
		return dir
	}
	return filepath.Join("..", "testdata", "spec-tests")
}

func specCases(t *testing.T, suite string) []string {
	t.Helper()
	pattern := filepath.Join(specTestDir(), suite, "kzg-mainnet", "*", "data.yaml")
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		msg := "no reference tests found for " + suite + " (run scripts/fetch-spec-tests.sh)"
		if os.Getenv("KZG_REQUIRE_SPEC_TESTS") == "1" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	return files
}

func loadCase(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func caseName(path string) string {
	return filepath.Base(filepath.Dir(path))
}

func decodeFixed(t *testing.T, s string, n int) ([]byte, bool) {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("bad hex in test vector: %v", err)
	}
	return b, len(b) == n
}

type inputs struct {
	blob, commitment, proof []byte
	z, y                    []byte
}

func parse(t *testing.T, blob, commitment, z, y, proof *string) (inputs, bool) {
	t.Helper()
	var in inputs
	ok := true
	check := func(s *string, n int) []byte {
		if s == nil {
			return nil
		}
		b, good := decodeFixed(t, *s, n)
		ok = ok && good
		return b
	}
	in.blob = check(blob, BytesPerBlob)
	in.commitment = check(commitment, BytesPerCommitment)
	in.z = check(z, 32)
	in.y = check(y, 32)
	in.proof = check(proof, BytesPerProof)
	return in, ok
}

func mustContext(t testing.TB) *Context {
	t.Helper()
	ctx, err := DefaultContext()
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestSpecBlobToKZGCommitment(t *testing.T) {
	ctx := mustContext(t)
	for _, path := range specCases(t, "blob_to_kzg_commitment") {
		var tc struct {
			Input  struct{ Blob string }
			Output *string
		}
		loadCase(t, path, &tc)
		t.Run(caseName(path), func(t *testing.T) {
			in, ok := parse(t, &tc.Input.Blob, nil, nil, nil, nil)
			var got Commitment
			var err error
			if ok {
				got, err = ctx.BlobToCommitment((*Blob)(in.blob))
			}
			if tc.Output == nil {
				if ok && err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if !ok || err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if want := *tc.Output; "0x"+hex.EncodeToString(got[:]) != want {
				t.Fatalf("got %x, want %s", got, want)
			}
		})
	}
}

func TestSpecComputeChallenge(t *testing.T) {
	for _, path := range specCases(t, "compute_challenge") {
		var tc struct {
			Input  struct{ Blob, Commitment string }
			Output *string
		}
		loadCase(t, path, &tc)
		t.Run(caseName(path), func(t *testing.T) {
			in, ok := parse(t, &tc.Input.Blob, &tc.Input.Commitment, nil, nil, nil)
			var got Bytes32
			var err error
			if ok {
				got, err = ComputeChallenge((*Blob)(in.blob), Commitment(in.commitment))
			}
			if tc.Output == nil {
				if ok && err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if !ok || err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if "0x"+hex.EncodeToString(got[:]) != *tc.Output {
				t.Fatalf("got %x, want %s", got, *tc.Output)
			}
		})
	}
}

func TestSpecComputeKZGProof(t *testing.T) {
	ctx := mustContext(t)
	for _, path := range specCases(t, "compute_kzg_proof") {
		var tc struct {
			Input  struct{ Blob, Z string }
			Output *[2]string
		}
		loadCase(t, path, &tc)
		t.Run(caseName(path), func(t *testing.T) {
			in, ok := parse(t, &tc.Input.Blob, nil, &tc.Input.Z, nil, nil)
			var proof Proof
			var y Bytes32
			var err error
			if ok {
				proof, y, err = ctx.ComputeKZGProof((*Blob)(in.blob), Bytes32(in.z))
			}
			if tc.Output == nil {
				if ok && err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if !ok || err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if "0x"+hex.EncodeToString(proof[:]) != tc.Output[0] {
				t.Fatalf("proof: got %x, want %s", proof, tc.Output[0])
			}
			if "0x"+hex.EncodeToString(y[:]) != tc.Output[1] {
				t.Fatalf("y: got %x, want %s", y, tc.Output[1])
			}
		})
	}
}

func TestSpecComputeBlobKZGProof(t *testing.T) {
	ctx := mustContext(t)
	for _, path := range specCases(t, "compute_blob_kzg_proof") {
		var tc struct {
			Input  struct{ Blob, Commitment string }
			Output *string
		}
		loadCase(t, path, &tc)
		t.Run(caseName(path), func(t *testing.T) {
			in, ok := parse(t, &tc.Input.Blob, &tc.Input.Commitment, nil, nil, nil)
			var proof Proof
			var err error
			if ok {
				proof, err = ctx.ComputeBlobKZGProof((*Blob)(in.blob), Commitment(in.commitment))
			}
			if tc.Output == nil {
				if ok && err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if !ok || err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if "0x"+hex.EncodeToString(proof[:]) != *tc.Output {
				t.Fatalf("got %x, want %s", proof, *tc.Output)
			}
		})
	}
}

func checkVerify(t *testing.T, want *bool, inputsOK bool, got bool, err error) {
	t.Helper()
	if want == nil {
		if inputsOK && err == nil {
			t.Fatalf("expected an error, got result %v", got)
		}
		return
	}
	if !inputsOK || err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != *want {
		t.Fatalf("got %v, want %v", got, *want)
	}
}

func TestSpecVerifyKZGProof(t *testing.T) {
	ctx := mustContext(t)
	for _, path := range specCases(t, "verify_kzg_proof") {
		var tc struct {
			Input  struct{ Commitment, Z, Y, Proof string }
			Output *bool
		}
		loadCase(t, path, &tc)
		t.Run(caseName(path), func(t *testing.T) {
			in, ok := parse(t, nil, &tc.Input.Commitment, &tc.Input.Z, &tc.Input.Y, &tc.Input.Proof)
			var got bool
			var err error
			if ok {
				got, err = ctx.VerifyKZGProof(Commitment(in.commitment), Bytes32(in.z), Bytes32(in.y), Proof(in.proof))
			}
			checkVerify(t, tc.Output, ok, got, err)
		})
	}
}

func TestSpecVerifyBlobKZGProof(t *testing.T) {
	ctx := mustContext(t)
	for _, path := range specCases(t, "verify_blob_kzg_proof") {
		var tc struct {
			Input  struct{ Blob, Commitment, Proof string }
			Output *bool
		}
		loadCase(t, path, &tc)
		t.Run(caseName(path), func(t *testing.T) {
			in, ok := parse(t, &tc.Input.Blob, &tc.Input.Commitment, nil, nil, &tc.Input.Proof)
			var got bool
			var err error
			if ok {
				got, err = ctx.VerifyBlobKZGProof((*Blob)(in.blob), Commitment(in.commitment), Proof(in.proof))
			}
			checkVerify(t, tc.Output, ok, got, err)
		})
	}
}

func TestSpecVerifyBlobKZGProofBatch(t *testing.T) {
	ctx := mustContext(t)
	for _, path := range specCases(t, "verify_blob_kzg_proof_batch") {
		var tc struct {
			Input struct {
				Blobs, Commitments, Proofs []string
			}
			Output *bool
		}
		loadCase(t, path, &tc)
		t.Run(caseName(path), func(t *testing.T) {
			ok := true
			blobs := make([]Blob, len(tc.Input.Blobs))
			for i, s := range tc.Input.Blobs {
				b, good := decodeFixed(t, s, BytesPerBlob)
				ok = ok && good
				copy(blobs[i][:], b)
			}
			commitments := make([]Commitment, len(tc.Input.Commitments))
			for i, s := range tc.Input.Commitments {
				b, good := decodeFixed(t, s, BytesPerCommitment)
				ok = ok && good
				copy(commitments[i][:], b)
			}
			proofs := make([]Proof, len(tc.Input.Proofs))
			for i, s := range tc.Input.Proofs {
				b, good := decodeFixed(t, s, BytesPerProof)
				ok = ok && good
				copy(proofs[i][:], b)
			}
			var got bool
			var err error
			if ok {
				got, err = ctx.VerifyBlobKZGProofBatch(blobs, commitments, proofs)
			}
			checkVerify(t, tc.Output, ok, got, err)
		})
	}
}
