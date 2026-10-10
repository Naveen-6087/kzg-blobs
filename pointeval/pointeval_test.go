package pointeval

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Naveen-6087/kzg-blobs/kzg"
)

func ctx(t testing.TB) *kzg.Context {
	t.Helper()
	c, err := kzg.DefaultContext()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGethVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/pointEvaluation.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Input, Expected, Name string
		Gas                   uint64
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no vectors")
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			input, _ := hex.DecodeString(tc.Input)
			want, _ := hex.DecodeString(tc.Expected)
			if tc.Gas != Gas {
				t.Fatalf("gas: vector says %d, constant is %d", tc.Gas, Gas)
			}
			got, err := Run(ctx(t), input)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("got %x, want %x", got, want)
			}
		})
	}
}

func validInput(t *testing.T) Input {
	t.Helper()
	c := ctx(t)
	var blob kzg.Blob
	for i := 0; i < kzg.FieldElementsPerBlob; i++ {
		blob[i*32+31] = byte(i)
		blob[i*32+30] = byte(i >> 8)
	}
	commitment, err := c.BlobToCommitment(&blob)
	if err != nil {
		t.Fatal(err)
	}
	z := kzg.Bytes32{31: 0x2a}
	proof, y, err := c.ComputeKZGProof(&blob, z)
	if err != nil {
		t.Fatal(err)
	}
	return Input{VersionedHash: VersionedHash(commitment), Z: z, Y: y, Commitment: commitment, Proof: proof}
}

func TestRunRoundTrip(t *testing.T) {
	in := validInput(t)
	got, err := Run(ctx(t), in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, ReturnValue()) {
		t.Fatalf("unexpected output %x", got)
	}
	parsed, err := ParseInput(in.Encode())
	if err != nil || parsed != in {
		t.Fatalf("parse round trip failed: %v", err)
	}
}

func TestRunFailures(t *testing.T) {
	c := ctx(t)
	in := validInput(t)

	tests := []struct {
		name   string
		mutate func(*Input) []byte
		want   error
	}{
		{"short input", func(in *Input) []byte { return in.Encode()[:191] }, ErrInputLength},
		{"long input", func(in *Input) []byte { return append(in.Encode(), 0) }, ErrInputLength},
		{"empty input", func(in *Input) []byte { return nil }, ErrInputLength},
		{"wrong version byte", func(in *Input) []byte { in.VersionedHash[0] = 0x02; return in.Encode() }, ErrVersionedHashMismatch},
		{"wrong hash", func(in *Input) []byte { in.VersionedHash[31] ^= 1; return in.Encode() }, ErrVersionedHashMismatch},
		{"wrong y", func(in *Input) []byte { in.Y[31] ^= 1; return in.Encode() }, ErrProofFailed},
		{"wrong z", func(in *Input) []byte { in.Z[31] ^= 1; return in.Encode() }, ErrProofFailed},
		{"non-canonical z", func(in *Input) []byte { in.Z = kzg.Modulus(); return in.Encode() }, kzg.ErrNonCanonicalFieldElement},
		// Setting the infinity flag on a non-zero encoding is malformed.
		{"invalid proof encoding", func(in *Input) []byte { in.Proof[0] |= 0x40; return in.Encode() }, kzg.ErrInvalidG1},
		// Flipping the sign bit yields -proof: a valid point, a wrong proof.
		{"negated proof", func(in *Input) []byte { in.Proof[0] ^= 0x20; return in.Encode() }, ErrProofFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := in
			_, err := Run(c, tt.mutate(&cp))
			if !errors.Is(err, tt.want) {
				t.Fatalf("got error %v, want %v", err, tt.want)
			}
		})
	}
}

func TestReturnValue(t *testing.T) {
	want := "000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
	if got := hex.EncodeToString(ReturnValue()); got != want {
		t.Fatalf("got %s", got)
	}
}

func TestVersionedHashKnown(t *testing.T) {
	var inf kzg.Commitment
	inf[0] = 0xc0
	h := VersionedHash(inf)
	if h[0] != VersionedHashVersionKZG {
		t.Fatalf("version byte %x", h[0])
	}
	want := "010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014"
	if got := hex.EncodeToString(h[:]); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if !MatchesVersionedHash(inf, h) {
		t.Fatal("MatchesVersionedHash returned false for matching hash")
	}
	var diff [32]byte
	if MatchesVersionedHash(inf, diff) {
		t.Fatal("MatchesVersionedHash returned true for zero hash")
	}
}

func FuzzRun(f *testing.F) {
	raw, _ := hex.DecodeString("01e798154708fe7789429634053cbf9f99b619f9f084048927333fce637f549b564c0a11a0f704f4fc3e8acfe0f8245f0ad1347b378fbf96e206da11a5d3630624d25032e67a7e6a4910df5834b8fe70e6bcfeeac0352434196bdf4b2485d5a18f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7873033e038326e87ed3e1276fd140253fa08e9fc25fb2d9a98527fc22a2c9612fbeafdad446cbc7bcdbdcd780af2c16a")
	f.Add(raw)
	f.Add([]byte{})
	c := ctx(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := Run(c, data)
		if err == nil && !bytes.Equal(out, ReturnValue()) {
			t.Fatalf("success with unexpected output %x", out)
		}
		if err != nil && out != nil {
			t.Fatal("failure returned output")
		}
	})
}
