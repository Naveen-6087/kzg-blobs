# kzg-blobs

A Go implementation of the KZG polynomial commitment scheme used by Ethereum
blob transactions ([EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)),
written against the Deneb
[polynomial-commitments specification](https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md)
and checked against all 262 official EIP-4844 reference vectors.

It includes:

- **`kzg`**: commitments, opening proofs, blob proofs and batch verification
  with spec-exact input validation, plus the embedded mainnet trusted setup.
- **`pointeval`**: the `0x0a` point evaluation precompile and blob versioned
  hashes.
- **`blobpack`**: a strict, reversible layout for packing arbitrary bytes into
  blobs.
- **`kzgblobs`**: a CLI for encoding data, committing, proving and verifying.

## Why

Since Dencun, rollups post their data to Ethereum as *blobs*: 128 KiB of
data, interpreted as a polynomial of degree < 4096. Consensus clients never
store a blob forever; instead every blob is bound by a 48-byte KZG
**commitment**. A **proof** then lets anyone check the blob against that
commitment, and the point evaluation precompile lets contracts check
single evaluations `p(z) = y` without the blob being available on chain.

The math is compact, but the details are easy to get wrong: bit-reversed
evaluation domains, canonical field encodings, point-at-infinity edge
cases, subgroup checks and Fiat-Shamir transcripts must all match the
specification byte for byte. This project implements the complete EIP-4844
surface in readable Go and tests every edge case the reference vectors
cover.

## Architecture

```
            kzgblobs (CLI)
          /       |        \
   blobpack    pointeval     |
          \       |        /
                 kzg
                  |
     gnark-crypto (BLS12-381: field, G1/G2, MSM, pairing)
```

| Package | Responsibility |
|---------|----------------|
| `kzg` | Trusted setup loading, evaluation domain, commitments, proofs, verification, batch verification |
| `pointeval` | Precompile input parsing, versioned hash check, return value |
| `blobpack` | Packing bytes into blobs and strict unpacking |
| `cmd/kzgblobs` | JSON-emitting command-line front end |

### How the `kzg` package works

- **Domain.** Blobs hold evaluations over the 4096th roots of unity
  `w^i`, `w = 7^((r-1)/4096)`, stored in bit-reversal order. The Lagrange
  points of the trusted setup are permuted the same way when loading, so a
  commitment is a single multi-scalar multiplication
  `C = sum_i p_i * [L_i(tau)]_1`.
- **Evaluation** uses the barycentric formula
  `p(z) = (z^N - 1)/N * sum_i p_i * w_i / (z - w_i)` with one batch
  inversion, and a direct lookup when `z` is a domain point.
- **Proofs** commit to the quotient `q(X) = (p(X) - y)/(X - z)` in
  evaluation form. When `z` lies in the domain, the undefined entry is
  computed with the spec's `compute_quotient_eval_within_domain`.
- **Verification** is one two-pairing check,
  `e(C - [y], [1]_2) == e(proof, [tau]_2 - [z]_2)`.
- **Batch verification** combines `n` proofs with powers of a Fiat-Shamir
  scalar `r` and still needs only two pairings. Per-blob work (decoding,
  challenge hashing, evaluation) runs in parallel.

### Design decisions

- **Spec-shaped API.** Every exported function corresponds to a function in
  the specification and takes and returns the same byte types, so the
  reference vectors map one to one onto the API.
- **Errors vs. `false`.** Malformed input (a non-canonical field element, an
  invalid point encoding or mismatched batch lengths) returns an error.
  Well-formed input with a wrong proof returns `false, nil`. This matches
  the vectors, where `null` means "rejected" and `false` means "valid
  input, invalid proof".
- **Validation in one place.** Untrusted bytes become field elements or
  points only through `bytesToField` and `bytesToG1`, which enforce
  canonical encodings and the subgroup check (the point at infinity is
  allowed, as the spec requires).
- **Immutable `Context`.** A loaded setup never changes, so one `Context`
  serves any number of goroutines without locking. `DefaultContext` parses
  and validates the embedded mainnet setup once.
- **Minimal dependencies.** The only runtime dependency is
  [gnark-crypto](https://github.com/consensys/gnark-crypto) for BLS12-381
  arithmetic. `gopkg.in/yaml.v3` is used only by tests.

## Install

Requires Go 1.26.8 or newer (gnark-crypto v0.22 needs it); `go.mod` pins
the `go1.26.9` toolchain.

```sh
go install github.com/Naveen-6087/kzg-blobs/cmd/kzgblobs@latest
```

Or as a library:

```sh
go get github.com/Naveen-6087/kzg-blobs
```

## Library usage

This is the runnable [`kzg/example_test.go`](kzg/example_test.go); `go test` checks
its output:

```go
ctx, err := kzg.DefaultContext() // embedded Ethereum mainnet setup
if err != nil {
	log.Fatal(err)
}

blobs, err := blobpack.Pack([]byte("Hello from an EIP-4844 blob!\n"), 6)
if err != nil {
	log.Fatal(err)
}
commitment, err := ctx.BlobToCommitment(&blobs[0])
if err != nil {
	log.Fatal(err)
}
proof, err := ctx.ComputeBlobKZGProof(&blobs[0], commitment)
if err != nil {
	log.Fatal(err)
}
ok, err := ctx.VerifyBlobKZGProof(&blobs[0], commitment, proof)
if err != nil {
	log.Fatal(err)
}
versionedHash := pointeval.VersionedHash(commitment) // 0x01 || sha256(C)[1:]

fmt.Println("valid:", ok)                           // valid: true
fmt.Printf("versioned hash: %x\n", versionedHash)   // 01c8e19a...3c3f23a0
```

| Function | Spec name |
|----------|-----------|
| `(*Context).BlobToCommitment` | `blob_to_kzg_commitment` |
| `(*Context).ComputeKZGProof` | `compute_kzg_proof` |
| `(*Context).ComputeBlobKZGProof` | `compute_blob_kzg_proof` |
| `(*Context).VerifyKZGProof` | `verify_kzg_proof` |
| `(*Context).VerifyBlobKZGProof` | `verify_blob_kzg_proof` |
| `(*Context).VerifyBlobKZGProofBatch` | `verify_blob_kzg_proof_batch` |
| `kzg.ComputeChallenge` | `compute_challenge` |
| `pointeval.Run` | point evaluation precompile (`0x0a`) |
| `pointeval.VersionedHash` | `kzg_to_versioned_hash` |

## CLI usage

```
kzgblobs [-setup FILE] <command> [flags] [args]

  pack          pack a file into blobs and print their sidecar data
  unpack        unpack blobs produced by pack
  commit        print a blob's commitment and versioned hash
  prove         compute a blob proof, or an opening proof at -z
  verify        verify a blob proof
  verify-point  verify an opening proof (commitment, z, y, proof)
  point-eval    run the 0x0a point evaluation precompile on call data
```

Output is JSON. The exit status is `0` on success, `1` when a proof does not
verify (or the precompile reverts) and `2` for usage or input errors. Blob
files may contain the raw 131072 bytes or their hex encoding.

Worked example, using the file in `examples/`. The expected values are
pinned by a test (`TestGoldenExample`), so they stay correct:

```console
$ kzgblobs pack -out-dir out examples/hello.txt
{
  "input_bytes": 29,
  "blobs": [
    {
      "file": "out/blob-000.bin",
      "commitment": "0xaf650052847b885930536fd73b147dd9a18e4328a2aa6d2af7b93ab38f738240f0215a246e1f55d16b8feb0fa0a4156e",
      "versioned_hash": "0x01c8e19a586c6e68ddcab53f098089df1ae5ab2ac094e6c4ad7638234c3f23a0",
      "proof": "0xafce10b4163efc3cf7034a5744b46a4b58b32c58ce2b0d4732354213d8b9dddf63ee188a8da9d02d92486e585cd056be"
    }
  ]
}

$ kzgblobs verify -commitment 0xaf65...156e -proof 0xafce...56be out/blob-000.bin
{
  "valid": true
}

$ kzgblobs prove -z 0x0000000000000000000000000000000000000000000000000000000000000005 out/blob-000.bin
{
  "commitment": "0xaf65...156e",
  "precompile_input": "0x01c8e1...ad271d",
  "proof": "0xb07125c8fa8ec3ad40e621b354a08c98d837b9bbba5a9cd011b556c821daf08501c4bad605360103c59bed288bad271d",
  "versioned_hash": "0x01c8e19a586c6e68ddcab53f098089df1ae5ab2ac094e6c4ad7638234c3f23a0",
  "y": "0x0ea8041fc730018e8c67e1db800a8f59c82711098f3570c9c6fd7992a276adfe",
  "z": "0x0000000000000000000000000000000000000000000000000000000000000005"
}

$ kzgblobs point-eval 0x01c8e1...ad271d
{
  "gas": 50000,
  "output": "0x000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
  "success": true
}

$ kzgblobs unpack out/blob-000.bin
Hello from an EIP-4844 blob!
```

(Long hex values are abbreviated with `...` above; the CLI prints them in
full.)

## Testing

```sh
bash scripts/fetch-spec-tests.sh  # download the official vectors (~65 MB, pinned commit)
go test ./...                 # unit, property, golden and reference tests
go test -race ./...           # as CI runs it (needs cgo)
```

| Kind | What it covers |
|------|----------------|
| Reference vectors | All 262 EIP-4844 `kzg-mainnet` cases: `blob_to_kzg_commitment` (11), `compute_challenge` (9), `compute_kzg_proof` (52), `compute_blob_kzg_proof` (15), `verify_kzg_proof` (122), `verify_blob_kzg_proof` (29), `verify_blob_kzg_proof_batch` (24) |
| Precompile vector | go-ethereum's `pointEvaluation.json`, plus every failure mode (length, version byte, hash, `y`, `z`, encodings) |
| Property tests | Proof round trips at random and in-domain points; agreement of barycentric evaluation with an independent O(n²) Lagrange evaluation; commitment homomorphism; batch soundness against a swapped proof or modified blob; challenge binding (`testing/quick`) |
| Edge cases | Non-canonical field elements, every invalid point encoding class, zero blob → point at infinity, empty and single-element batches, malformed and monomial-form trusted setups |
| Fuzzing | Point decoding (accepted encodings must be canonical and in the subgroup), proof verification, the precompile, and `blobpack` round trips and strict unpacking |
| CLI | End-to-end pack → commit → prove → verify → point-eval → unpack, usage errors, and a golden-output test |

Without the downloaded suites, the corresponding tests are skipped (the
vendored `verify_kzg_proof` suite always runs). Set
`KZG_REQUIRE_SPEC_TESTS=1` to make missing suites a failure, as CI does.

Run the fuzzers locally with, for example:

```sh
go test ./kzg -run '^$' -fuzz FuzzBytesToG1 -fuzztime 1m
```

## Benchmarks

```sh
go test ./kzg -run '^$' -bench . -benchmem
```

Below is one sample run: the fastest of three runs per benchmark, in a
`golang:1.26.9` Linux container (Docker Desktop on Windows) on an Intel Core
i5-12500H (16 threads). Laptop and CI timings vary by tens of percent
between runs, so treat these as orders of magnitude, not guarantees.

| Operation | Time |
|-----------|------|
| Load and validate the trusted setup | 85 ms |
| `BlobToCommitment` | 9.1 ms |
| `ComputeKZGProof` | 19.8 ms |
| `ComputeBlobKZGProof` | 19.1 ms |
| `VerifyKZGProof` | 1.9 ms |
| `VerifyBlobKZGProof` | 2.8 ms |
| `ComputeChallenge` | 0.18 ms |

| Blobs | Batch verify | Verify individually |
|-------|--------------|---------------------|
| 2 | 4.3 ms | 4.9 ms |
| 4 | 5.3 ms | 11.0 ms |
| 6 | 6.6 ms | 11.8 ms |
| 9 | 7.3 ms | 19.3 ms |
| 16 | 9.5 ms | 41.1 ms |

The `Benchmarks` workflow runs the same suite on GitHub's runners and
uploads the results as an artifact.

## Security considerations

- **Trusted setup.** Soundness relies on nobody knowing `tau` from the KZG
  ceremony, which holds if at least one participant destroyed their secret.
  The embedded setup is byte-identical to c-kzg-4844's (SHA-256 in
  `testdata/README.md`). Every point is decompressed and subgroup checked
  when loading, and the setup is rejected if its G1 points are in monomial
  rather than Lagrange form.
- **Input validation** follows the specification exactly; anything accepted
  re-encodes to the same bytes (this is checked by fuzzing).
- **Not constant time.** Proving operates on blob data, which is public in
  Ethereum, so the implementation makes no side-channel guarantees. Do not
  reuse it for secret polynomials.
- **No independent audit.** The arithmetic comes from gnark-crypto, but this
  package itself has not been audited. Production clients should use an
  audited library such as c-kzg-4844 or go-eth-kzg.

## Limitations

- Implements EIP-4844 only. PeerDAS cell proofs (EIP-7594, Fulu) and blob
  recovery are not implemented; the trailing monomial section of newer
  trusted setup files is accepted but unused.
- `blobpack` is this project's own layout, not a rollup's blob format. It is
  intended for tooling and tests.
- Performance is reasonable but not tuned to the level of c-kzg-4844 (for
  example, there is no precomputed fixed-base table for the
  multi-exponentiation).

## Development

```sh
gofmt -l .                                         # must print nothing
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go test -race ./...
```

CI (`.github/workflows/ci.yml`) runs these checks on every push to `main`
and on every pull request, together with a short fuzzing pass.

## References

- [EIP-4844: Shard Blob Transactions](https://eips.ethereum.org/EIPS/eip-4844)
- [Deneb polynomial commitments](https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md)
- [c-kzg-4844](https://github.com/ethereum/c-kzg-4844), the reference C implementation
- [Kate, Zaverucha, Goldberg: Constant-Size Commitments to Polynomials and Their Applications (2010)](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)

## License

MIT, see [LICENSE](LICENSE). Third-party test data and the trusted setup keep
their own licenses; see [testdata/README.md](testdata/README.md).
