# Test data and third-party files

This repository's own code is MIT licensed (see `LICENSE`). The files listed
here come from other projects and keep their original licenses.

| Path | Source | License |
|------|--------|---------|
| `testdata/spec-tests/` | [ethereum/c-kzg-4844](https://github.com/ethereum/c-kzg-4844) `tests/` at commit `a751e2d92abcd63b01d1400789789f5ea289a8b0`, which redistributes the `kzg-mainnet` vectors of [consensus-spec-tests](https://github.com/ethereum/consensus-spec-tests) | consensus-spec-tests: CC0-1.0; c-kzg-4844: Apache-2.0 |
| `kzg/trusted_setup.txt` | `src/trusted_setup.txt` from the same c-kzg-4844 commit; the output of the [Ethereum KZG ceremony](https://ceremony.ethereum.org/) | c-kzg-4844: Apache-2.0 |
| `pointeval/testdata/pointEvaluation.json` | [go-ethereum](https://github.com/ethereum/go-ethereum) `core/vm/testdata/precompiles/pointEvaluation.json` | go-ethereum: LGPL-3.0 |

Only the `verify_kzg_proof` suite (about 190 KB) is committed. The other
EIP-4844 suites (about 65 MB) are downloaded by `scripts/fetch-spec-tests.sh`,
which pins the commit above and checks the number of cases in each suite.

`kzg/trusted_setup.txt` has SHA-256
`8238f38facf65a250bed6dbe7d40fe9f254a57450ab532ed6bbcd6aeff92f937`.
