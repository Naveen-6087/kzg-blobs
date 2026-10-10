package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	payload := []byte(strings.Repeat("blob data for EIP-4844\n", 10000)) // ~230 KB, 2 blobs
	if err := os.WriteFile(input, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := runCLI(t, "pack", "-out-dir", dir, input)
	if code != exitOK {
		t.Fatalf("pack exit %d: %s", code, errOut)
	}
	var enc struct {
		InputBytes int `json:"input_bytes"`
		Blobs      []struct {
			File, Commitment, Proof string
			VersionedHash           string `json:"versioned_hash"`
		}
	}
	if err := json.Unmarshal([]byte(out), &enc); err != nil {
		t.Fatal(err)
	}
	if enc.InputBytes != len(payload) || len(enc.Blobs) != 2 {
		t.Fatalf("unexpected pack output: %s", out)
	}
	first := enc.Blobs[0]
	if !strings.HasPrefix(first.VersionedHash, "0x01") {
		t.Fatalf("versioned hash %s", first.VersionedHash)
	}

	code, out, _ = runCLI(t, "commit", first.File)
	if code != exitOK || !strings.Contains(out, first.Commitment) {
		t.Fatalf("commit exit %d: %s", code, out)
	}

	code, out, _ = runCLI(t, "verify", "-commitment", first.Commitment, "-proof", first.Proof, first.File)
	if code != exitOK || !strings.Contains(out, `"valid": true`) {
		t.Fatalf("verify exit %d: %s", code, out)
	}
	code, out, _ = runCLI(t, "verify", "-commitment", first.Commitment, "-proof", enc.Blobs[1].Proof, first.File)
	if code != exitInvalid || !strings.Contains(out, `"valid": false`) {
		t.Fatalf("wrong proof: exit %d: %s", code, out)
	}

	z := "0x" + strings.Repeat("00", 31) + "05"
	code, out, errOut = runCLI(t, "prove", "-z", z, first.File)
	if code != exitOK {
		t.Fatalf("prove exit %d: %s", code, errOut)
	}
	var opening map[string]string
	if err := json.Unmarshal([]byte(out), &opening); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = runCLI(t, "verify-point", "-commitment", opening["commitment"], "-z", z, "-y", opening["y"], "-proof", opening["proof"])
	if code != exitOK {
		t.Fatalf("verify-point exit %d: %s", code, errOut)
	}
	code, out, _ = runCLI(t, "point-eval", opening["precompile_input"])
	if code != exitOK || !strings.Contains(out, `"success": true`) {
		t.Fatalf("point-eval exit %d: %s", code, out)
	}
	bad := []byte(opening["precompile_input"])
	bad[len(bad)-200] ^= 1 // corrupt y
	if code, _, _ = runCLI(t, "point-eval", string(bad)); code != exitInvalid {
		t.Fatalf("corrupted point-eval exit %d", code)
	}

	decoded := filepath.Join(dir, "decoded.txt")
	code, _, errOut = runCLI(t, "unpack", "-out", decoded, enc.Blobs[0].File, enc.Blobs[1].File)
	if code != exitOK {
		t.Fatalf("unpack exit %d: %s", code, errOut)
	}
	got, _ := os.ReadFile(decoded)
	if !bytes.Equal(got, payload) {
		t.Fatal("unpack did not restore the input")
	}
}

func TestHexBlobInput(t *testing.T) {
	dir := t.TempDir()
	blob := make([]byte, 131072)
	blob[63] = 7
	path := filepath.Join(dir, "blob.hex")
	if err := os.WriteFile(path, []byte("0x"+hex.EncodeToString(blob)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runCLI(t, "commit", path); code != exitOK {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"nope"},
		{"commit"},
		{"commit", "does-not-exist.bin"},
		{"verify", "-commitment", "0x12", "-proof", "0x34", "x"},
		{"verify-point", "-commitment", "zz"},
		{"point-eval", "0x00"},
		{"prove", "-z", "0x01", "x"},
		{"-setup", "missing-setup.txt", "verify-point",
			"-commitment", "0xc0" + strings.Repeat("00", 47), "-z", "0x" + strings.Repeat("00", 32),
			"-y", "0x" + strings.Repeat("00", 32), "-proof", "0xc0" + strings.Repeat("00", 47)},
	}
	for _, args := range cases {
		if code, _, _ := runCLI(t, args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
	if code, _, _ := runCLI(t, "-h"); code != exitOK {
		t.Errorf("-h exit %d", code)
	}
}

func TestNonCanonicalBlobReported(t *testing.T) {
	dir := t.TempDir()
	blob := bytes.Repeat([]byte{0xff}, 131072)
	path := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, "commit", path)
	if code != exitUsage || !strings.Contains(errOut, "not canonical") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestGoldenExample(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "hello.expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	code, out, errOut := runCLI(t, "pack", "-out-dir", dir, filepath.Join("..", "..", "examples", "hello.txt"))
	if code != exitOK {
		t.Fatalf("pack: %s", errOut)
	}
	var enc struct {
		InputBytes float64 `json:"input_bytes"`
		Blobs      []struct {
			File, Commitment, Proof string
			VersionedHash           string `json:"versioned_hash"`
		}
	}
	if err := json.Unmarshal([]byte(out), &enc); err != nil {
		t.Fatal(err)
	}
	b := enc.Blobs[0]
	checks := map[string]any{
		"input_bytes": enc.InputBytes, "commitment": b.Commitment,
		"versioned_hash": b.VersionedHash, "blob_proof": b.Proof,
	}
	code, out, errOut = runCLI(t, "prove", "-z", want["z"].(string), b.File)
	if code != exitOK {
		t.Fatalf("prove: %s", errOut)
	}
	var opening map[string]string
	if err := json.Unmarshal([]byte(out), &opening); err != nil {
		t.Fatal(err)
	}
	checks["y"], checks["opening_proof"] = opening["y"], opening["proof"]
	for k, got := range checks {
		if got != want[k] {
			t.Errorf("%s: got %v, want %v", k, got, want[k])
		}
	}
}

func TestVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"-version"}} {
		code, out, errOut := runCLI(t, args...)
		if code != exitOK {
			t.Fatalf("%v exit %d: %s", args, code, errOut)
		}
		var res map[string]string
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("%v parse json: %v", args, err)
		}
		if res["version"] != version {
			t.Fatalf("%v: got %q, want %q", args, res["version"], version)
		}
	}
}
