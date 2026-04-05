package blobpack

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Naveen-6087/kzg-blobs/kzg"
)

func TestRoundTripSizes(t *testing.T) {
	for _, n := range []int{
		0, 1, 30, 31, 32,
		UsableBytesPerBlob - lengthPrefix - 1,
		UsableBytesPerBlob - lengthPrefix,
		UsableBytesPerBlob - lengthPrefix + 1,
		3*UsableBytesPerBlob + 17,
	} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*7 + 3)
		}
		blobs, err := Pack(data, 0)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if len(blobs) != BlobsNeeded(n) {
			t.Fatalf("n=%d: %d blobs, want %d", n, len(blobs), BlobsNeeded(n))
		}
		got, err := Unpack(blobs)
		if err != nil {
			t.Fatalf("n=%d: unpack: %v", n, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
	}
}

func TestBlobsAreCanonical(t *testing.T) {
	data := bytes.Repeat([]byte{0xff}, 2*UsableBytesPerBlob)
	blobs, err := Pack(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := kzg.DefaultContext()
	if err != nil {
		t.Fatal(err)
	}
	for i := range blobs {
		if _, err := ctx.BlobToCommitment(&blobs[i]); err != nil {
			t.Fatalf("blob %d is not a valid blob: %v", i, err)
		}
	}
}

func TestPackLimit(t *testing.T) {
	data := make([]byte, UsableBytesPerBlob)
	if _, err := Pack(data, 1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	if _, err := Pack(data, 2); err != nil {
		t.Fatal(err)
	}
}

func TestUnpackRejectsMalformed(t *testing.T) {
	valid, _ := Pack([]byte("hello blobs"), 0)
	tests := map[string]func() []kzg.Blob{
		"no blobs":     func() []kzg.Blob { return nil },
		"high byte":    func() []kzg.Blob { b := clone(valid); b[0][32*5] = 1; return b },
		"padding":      func() []kzg.Blob { b := clone(valid); b[0][kzg.BytesPerBlob-1] = 1; return b },
		"huge length":  func() []kzg.Blob { b := clone(valid); b[0][1] = 0xff; return b },
		"surplus blob": func() []kzg.Blob { return append(clone(valid), kzg.Blob{}) },
	}
	for name, mk := range tests {
		if _, err := Unpack(mk()); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", name, err)
		}
	}
}

func clone(b []kzg.Blob) []kzg.Blob { return append([]kzg.Blob(nil), b...) }

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("ethereum blobs"))
	f.Fuzz(func(t *testing.T, data []byte) {
		blobs, err := Pack(data, 0)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Unpack(blobs)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("mismatch")
		}
	})
}

func FuzzUnpack(f *testing.F) {
	f.Add(make([]byte, 64), uint16(0))
	f.Fuzz(func(t *testing.T, patch []byte, offset uint16) {
		blobs, _ := Pack([]byte("seed"), 0)
		copy(blobs[0][int(offset)%kzg.BytesPerBlob:], patch)
		data, err := Unpack(blobs)
		if err != nil {
			return
		}
		again, err := Pack(data, 0)
		if err != nil || len(again) != 1 || again[0] != blobs[0] {
			t.Fatal("accepted a non-canonical encoding")
		}
	})
}
