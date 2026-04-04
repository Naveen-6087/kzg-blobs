#!/usr/bin/env bash
# Fetches the EIP-4844 KZG reference tests from c-kzg-4844 at a pinned commit.
set -euo pipefail

REPO="https://github.com/ethereum/c-kzg-4844.git"
COMMIT="a751e2d92abcd63b01d1400789789f5ea289a8b0"

SUITES=(
  blob_to_kzg_commitment:11
  compute_blob_kzg_proof:15
  compute_challenge:9
  compute_kzg_proof:52
  verify_blob_kzg_proof:29
  verify_blob_kzg_proof_batch:24
  verify_kzg_proof:122
)

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="${1:-$root/testdata/spec-tests}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "fetching c-kzg-4844@${COMMIT:0:12} reference tests..."
git -C "$work" init -q
git -C "$work" config core.longpaths true
git -C "$work" remote add origin "$REPO"
patterns=()
for entry in "${SUITES[@]}"; do
  # No leading slash: Git for Windows rewrites "/tests" into a Windows path.
  patterns+=("tests/${entry%%:*}/")
done
git -C "$work" sparse-checkout set --no-cone "${patterns[@]}"
git -C "$work" fetch -q --depth 1 --filter=blob:none origin "$COMMIT"
git -C "$work" checkout -q FETCH_HEAD

mkdir -p "$dest"
for entry in "${SUITES[@]}"; do
  suite="${entry%%:*}"
  want="${entry##*:}"
  got="$(find "$work/tests/$suite" -name data.yaml | wc -l | tr -d ' ')"
  if [[ "$got" != "$want" ]]; then
    echo "error: $suite has $got cases, expected $want" >&2
    exit 1
  fi
  rm -rf "${dest:?}/$suite"
  cp -R "$work/tests/$suite" "$dest/$suite"
  echo "  $suite: $got cases"
done
echo "done: $dest"
