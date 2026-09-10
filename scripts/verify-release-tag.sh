#!/usr/bin/env bash
#
# Verify a receipt-verifier release tag on a machine that has never seen this project.
#
# ── WHY A SCRIPT AND NOT A DOC LINE ─────────────────────────────────────────────────────────
#
# `git tag -v <tag>` is not self-contained. MEASURED with no signer configuration:
#
#   Good "git" signature with ED25519 key SHA256:7yRXTm9zKGicfFpzL+7lpwFoPaoSwxAJlabB3jwxw2Y
#   Unable to open allowed keys file "": No such file or directory
#   No principal matched.
#
# The signature verifies and the command fails: git can say the bytes were signed by that key and
# cannot say whose key it is. `verification/allowed_signers` supplies the missing half.
#
# ── AND WHY THE FINGERPRINT IS ASSERTED HERE ────────────────────────────────────────────────
#
# `-c gpg.ssh.allowedSignersFile=…` alone proves "signed by SOMEBODY in that file". Today the file
# has one entry, so the two are the same statement — and they stop being the same the moment a
# second signer is added. Pinning the expected fingerprint keeps this script answering the question
# a reader is actually asking: was this release signed by THAT key.
#
# Also measured, and the reason 2>&1 is load-bearing: `git tag -v` writes its verdict to STDERR and
# exits 0. A check reading stdout finds an empty string.
#
# Usage:  ./scripts/verify-release-tag.sh v1.0.1

set -euo pipefail

TAG="${1:-}"
if [[ -z "$TAG" ]]; then
  echo "usage: $0 <tag>   (e.g. $0 v1.0.1)" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGNERS="$REPO_ROOT/verification/allowed_signers"
EXPECTED_FPR="SHA256:7yRXTm9zKGicfFpzL+7lpwFoPaoSwxAJlabB3jwxw2Y"

[[ -f "$SIGNERS" ]] || { echo "FAIL: $SIGNERS is missing — this repo cannot verify its own tags" >&2; exit 1; }

# ANNOTATED FIRST. A lightweight tag has no object to verify, and `git tag -v` reports that in a
# way that reads like a verification failure ("cannot verify a non-tag object of type commit") when
# the real fact is that nothing was ever signed. Naming the difference is the point.
OBJ_TYPE="$(git -C "$REPO_ROOT" cat-file -t "$TAG" 2>/dev/null || echo missing)"
if [[ "$OBJ_TYPE" != "tag" ]]; then
  echo "FAIL: $TAG is not an annotated tag (git cat-file -t says '$OBJ_TYPE')." >&2
  echo "      A lightweight tag carries no signature — it is a name anyone with push access moves." >&2
  exit 1
fi

OUT="$(git -C "$REPO_ROOT" -c gpg.ssh.allowedSignersFile="$SIGNERS" tag -v "$TAG" 2>&1 || true)"

if ! grep -q 'Good .*signature' <<<"$OUT"; then
  echo "FAIL: $TAG does not carry a good signature:" >&2
  echo "$OUT" >&2
  exit 1
fi
if ! grep -qF "$EXPECTED_FPR" <<<"$OUT"; then
  echo "FAIL: $TAG is signed, but NOT by the expected key $EXPECTED_FPR:" >&2
  echo "$OUT" >&2
  exit 1
fi
if ! grep -q 'signature for ' <<<"$OUT"; then
  # "Good signature WITH key" (no principal) vs "Good signature FOR identity" — the difference
  # between "these bytes were signed" and "signed by someone we can name".
  echo "FAIL: the signature verified but matched no principal in $SIGNERS" >&2
  echo "$OUT" >&2
  exit 1
fi

PEELED="$(git -C "$REPO_ROOT" rev-parse "$TAG^{commit}")"
echo "OK: $TAG is annotated and signed by $EXPECTED_FPR"
grep 'Good .*signature' <<<"$OUT" | sed 's/^/    /'
echo "    peels to commit $PEELED"
