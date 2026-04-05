package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Naveen-6087/kzg-blobs/blobpack"
	"github.com/Naveen-6087/kzg-blobs/kzg"
	"github.com/Naveen-6087/kzg-blobs/pointeval"
)

const (
	exitOK          = 0
	exitInvalid     = 1
	exitUsage       = 2
	defaultMaxBlobs = 6
)

var errInvalid = errors.New("proof is invalid")

type command struct {
	name    string
	summary string
	run     func(env *env, args []string) error
}

type env struct {
	stdout, stderr io.Writer
	setupPath      string
	ctx            *kzg.Context
}

func (e *env) context() (*kzg.Context, error) {
	if e.ctx != nil {
		return e.ctx, nil
	}
	var err error
	if e.setupPath == "" {
		e.ctx, err = kzg.DefaultContext()
	} else {
		e.ctx, err = kzg.LoadContextFile(e.setupPath)
	}
	return e.ctx, err
}

func (e *env) emit(v any) error {
	enc := json.NewEncoder(e.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func commands() []command {
	return []command{
		{"pack", "pack a file into blobs and print their sidecar data", cmdPack},
		{"unpack", "unpack blobs produced by pack", cmdUnpack},
		{"commit", "print a blob's commitment and versioned hash", cmdCommit},
		{"prove", "compute a blob proof, or an opening proof at -z", cmdProve},
		{"verify", "verify a blob proof", cmdVerify},
		{"verify-point", "verify an opening proof (commitment, z, y, proof)", cmdVerifyPoint},
		{"point-eval", "run the 0x0a point evaluation precompile on call data", cmdPointEval},
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: kzgblobs [-setup FILE] <command> [flags] [args]")
	fmt.Fprintln(w, "\ncommands:")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-13s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w, "\nrun 'kzgblobs <command> -h' for command flags")
}

func run(args []string, stdout, stderr io.Writer) int {
	global := flag.NewFlagSet("kzgblobs", flag.ContinueOnError)
	global.SetOutput(stderr)
	setup := global.String("setup", "", "trusted setup file in c-kzg-4844 text format (default: embedded mainnet setup)")
	global.Usage = func() { usage(stderr) }
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	rest := global.Args()
	if len(rest) == 0 {
		usage(stderr)
		return exitUsage
	}
	e := &env{stdout: stdout, stderr: stderr, setupPath: *setup}
	for _, c := range commands() {
		if c.name != rest[0] {
			continue
		}
		err := c.run(e, rest[1:])
		switch {
		case err == nil:
			return exitOK
		case errors.Is(err, flag.ErrHelp):
			return exitOK
		case errors.Is(err, errInvalid):
			return exitInvalid
		default:
			fmt.Fprintf(stderr, "kzgblobs %s: %v\n", c.name, err)
			return exitUsage
		}
	}
	fmt.Fprintf(stderr, "kzgblobs: unknown command %q\n", rest[0])
	usage(stderr)
	return exitUsage
}

func newFlags(e *env, name, args string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	fs.Usage = func() {
		fmt.Fprintf(e.stderr, "usage: kzgblobs %s [flags] %s\n", name, args)
		fs.PrintDefaults()
	}
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string, positional int) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != positional {
		fs.Usage()
		return fmt.Errorf("expected %d positional argument(s), got %d", positional, fs.NArg())
	}
	return nil
}

func hexString(b []byte) string { return "0x" + hex.EncodeToString(b) }

func decodeHex(name, s string, n int) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if n >= 0 && len(b) != n {
		return nil, fmt.Errorf("%s: want %d bytes, got %d", name, n, len(b))
	}
	return b, nil
}

// readBlob accepts the raw blob bytes or their hex encoding; "-" reads stdin.
func readBlob(path string) (*kzg.Blob, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, 4*kzg.BytesPerBlob))
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	if len(data) != kzg.BytesPerBlob {
		data, err = decodeHex(path, string(data), kzg.BytesPerBlob)
		if err != nil {
			return nil, fmt.Errorf("blob must be %d raw bytes or their hex encoding: %w", kzg.BytesPerBlob, err)
		}
	}
	return (*kzg.Blob)(data), nil
}

type sidecar struct {
	File          string `json:"file,omitempty"`
	Commitment    string `json:"commitment"`
	VersionedHash string `json:"versioned_hash"`
	Proof         string `json:"proof,omitempty"`
}

func describe(ctx *kzg.Context, blob *kzg.Blob, withProof bool) (sidecar, error) {
	c, err := ctx.BlobToCommitment(blob)
	if err != nil {
		return sidecar{}, err
	}
	vh := pointeval.VersionedHash(c)
	s := sidecar{Commitment: hexString(c[:]), VersionedHash: hexString(vh[:])}
	if withProof {
		p, err := ctx.ComputeBlobKZGProof(blob, c)
		if err != nil {
			return sidecar{}, err
		}
		s.Proof = hexString(p[:])
	}
	return s, nil
}

func cmdPack(e *env, args []string) error {
	fs := newFlags(e, "pack", "<input-file>")
	outDir := fs.String("out-dir", ".", "directory for blob-NNN.bin files")
	maxBlobs := fs.Int("max-blobs", defaultMaxBlobs, "refuse inputs needing more blobs (0 = unlimited)")
	if err := parseFlags(fs, args, 1); err != nil {
		return err
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	blobs, err := blobpack.Pack(data, *maxBlobs)
	if err != nil {
		return err
	}
	ctx, err := e.context()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	out := struct {
		InputBytes int       `json:"input_bytes"`
		Blobs      []sidecar `json:"blobs"`
	}{InputBytes: len(data)}
	for i := range blobs {
		s, err := describe(ctx, &blobs[i], true)
		if err != nil {
			return err
		}
		s.File = filepath.Join(*outDir, fmt.Sprintf("blob-%03d.bin", i))
		if err := os.WriteFile(s.File, blobs[i][:], 0o644); err != nil {
			return err
		}
		out.Blobs = append(out.Blobs, s)
	}
	return e.emit(out)
}

func cmdUnpack(e *env, args []string) error {
	fs := newFlags(e, "unpack", "<blob-file>...")
	output := fs.String("out", "-", "output file ('-' for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return errors.New("at least one blob file is required")
	}
	blobs := make([]kzg.Blob, fs.NArg())
	for i, path := range fs.Args() {
		b, err := readBlob(path)
		if err != nil {
			return err
		}
		blobs[i] = *b
	}
	data, err := blobpack.Unpack(blobs)
	if err != nil {
		return err
	}
	if *output == "-" {
		_, err = io.Copy(e.stdout, bytes.NewReader(data))
		return err
	}
	return os.WriteFile(*output, data, 0o644)
}

func cmdCommit(e *env, args []string) error {
	fs := newFlags(e, "commit", "<blob-file>")
	if err := parseFlags(fs, args, 1); err != nil {
		return err
	}
	blob, err := readBlob(fs.Arg(0))
	if err != nil {
		return err
	}
	ctx, err := e.context()
	if err != nil {
		return err
	}
	s, err := describe(ctx, blob, false)
	if err != nil {
		return err
	}
	return e.emit(s)
}

func cmdProve(e *env, args []string) error {
	fs := newFlags(e, "prove", "<blob-file>")
	z := fs.String("z", "", "evaluation point (32-byte hex); omit for the blob sidecar proof")
	if err := parseFlags(fs, args, 1); err != nil {
		return err
	}
	blob, err := readBlob(fs.Arg(0))
	if err != nil {
		return err
	}
	ctx, err := e.context()
	if err != nil {
		return err
	}
	if *z == "" {
		s, err := describe(ctx, blob, true)
		if err != nil {
			return err
		}
		return e.emit(s)
	}
	zb, err := decodeHex("z", *z, 32)
	if err != nil {
		return err
	}
	c, err := ctx.BlobToCommitment(blob)
	if err != nil {
		return err
	}
	proof, y, err := ctx.ComputeKZGProof(blob, kzg.Bytes32(zb))
	if err != nil {
		return err
	}
	vh := pointeval.VersionedHash(c)
	call := pointeval.Input{VersionedHash: vh, Z: kzg.Bytes32(zb), Y: y, Commitment: c, Proof: proof}
	return e.emit(map[string]string{
		"commitment":       hexString(c[:]),
		"versioned_hash":   hexString(vh[:]),
		"z":                hexString(zb),
		"y":                hexString(y[:]),
		"proof":            hexString(proof[:]),
		"precompile_input": hexString(call.Encode()),
	})
}

func emitVerdict(e *env, ok bool) error {
	if err := e.emit(map[string]bool{"valid": ok}); err != nil {
		return err
	}
	if !ok {
		return errInvalid
	}
	return nil
}

func cmdVerify(e *env, args []string) error {
	fs := newFlags(e, "verify", "<blob-file>")
	commitment := fs.String("commitment", "", "48-byte commitment (hex, required)")
	proof := fs.String("proof", "", "48-byte blob proof (hex, required)")
	if err := parseFlags(fs, args, 1); err != nil {
		return err
	}
	cb, err := decodeHex("commitment", *commitment, kzg.BytesPerCommitment)
	if err != nil {
		return err
	}
	pb, err := decodeHex("proof", *proof, kzg.BytesPerProof)
	if err != nil {
		return err
	}
	blob, err := readBlob(fs.Arg(0))
	if err != nil {
		return err
	}
	ctx, err := e.context()
	if err != nil {
		return err
	}
	ok, err := ctx.VerifyBlobKZGProof(blob, kzg.Commitment(cb), kzg.Proof(pb))
	if err != nil {
		return err
	}
	return emitVerdict(e, ok)
}

func cmdVerifyPoint(e *env, args []string) error {
	fs := newFlags(e, "verify-point", "")
	commitment := fs.String("commitment", "", "48-byte commitment (hex, required)")
	z := fs.String("z", "", "32-byte evaluation point (hex, required)")
	y := fs.String("y", "", "32-byte claimed evaluation (hex, required)")
	proof := fs.String("proof", "", "48-byte opening proof (hex, required)")
	if err := parseFlags(fs, args, 0); err != nil {
		return err
	}
	cb, err := decodeHex("commitment", *commitment, kzg.BytesPerCommitment)
	if err != nil {
		return err
	}
	zb, err := decodeHex("z", *z, 32)
	if err != nil {
		return err
	}
	yb, err := decodeHex("y", *y, 32)
	if err != nil {
		return err
	}
	pb, err := decodeHex("proof", *proof, kzg.BytesPerProof)
	if err != nil {
		return err
	}
	ctx, err := e.context()
	if err != nil {
		return err
	}
	ok, err := ctx.VerifyKZGProof(kzg.Commitment(cb), kzg.Bytes32(zb), kzg.Bytes32(yb), kzg.Proof(pb))
	if err != nil {
		return err
	}
	return emitVerdict(e, ok)
}

func cmdPointEval(e *env, args []string) error {
	fs := newFlags(e, "point-eval", "<call-data-hex>")
	if err := parseFlags(fs, args, 1); err != nil {
		return err
	}
	input, err := decodeHex("call data", fs.Arg(0), -1)
	if err != nil {
		return err
	}
	ctx, err := e.context()
	if err != nil {
		return err
	}
	out, err := pointeval.Run(ctx, input)
	switch {
	case err == nil:
		return e.emit(map[string]any{"success": true, "gas": pointeval.Gas, "output": hexString(out)})
	case errors.Is(err, pointeval.ErrInputLength):
		return err
	default:
		if emitErr := e.emit(map[string]any{"success": false, "error": err.Error()}); emitErr != nil {
			return emitErr
		}
		return errInvalid
	}
}
