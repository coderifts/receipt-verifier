# Attaching a receipt to a commit

**Status: new convention (1961 TAG 1, 2026-09-23).** There was none before — measured, and the
measurement is the reason this file exists.

## What was there before, and what was not

`commit_observation` (a `GuardOutcome` field) and `after_state_token`
(`observation.observed_commit === expected.contract_commit`, `RECEIPT_FORMAT.md` §12) already
connect a receipt to a commit **at decision time**, inside the guard. Both are runtime
measurements held by the process that made them.

What did **not** exist is the other direction: given a commit that is already in history, find the
receipt that authorised it. Measured 2026-09-23 across `coderifts-app`, `receipt-verifier` and
`coderifts-contract-gate`: zero occurrences of a receipt trailer, zero occurrences of a receipt
sidecar path. Nothing in the repository answered "which receipt goes with this SHA".

⚠ **Why that gap matters more than it looks.** A receipt proves an authorisation happened. A
commit proves a change happened. Without a durable join between them, proving that *this* change
was *that* authorisation depends on whoever still has the receipt in a terminal scrollback. The
evidence exists and the link does not.

## The convention

Two carriers, deliberately. Use either; use both when you can.

### 1. Git trailer — `CodeRifts-Receipt`

```
Fix the rate-limit window

CodeRifts-Receipt: eyJ2Ijo0LCJraWQiOiIyMDI2LTA3LWsxIi4uLn0.b2Zhc2Rm...
```

- **Travels with the commit.** Clones, mirrors, `git log`, `format-patch`, and any host that shows
  a commit message all carry it with no extra plumbing.
- **Immutable once pushed** — it is inside the commit object, so the SHA covers it.
- ⚠ **It changes the commit SHA.** The trailer must be written when the commit is *created*.
  Adding it afterwards rewrites history, which is why the sidecar exists.
- ⚠ **A receipt token is long.** Trailers are a single logical line; do not hand-wrap it. Git
  folds long trailer values on read, and `--from-commit` unfolds them.

### 2. Sidecar — `.coderifts/receipts/<sha>.json`

```json
{
  "sha": "9f2c1ab…",
  "receipt": "eyJ2Ijo0…",
  "envelope": { "…": "the decision envelope the receipt was minted for (optional)" }
}
```

- **Addable after the fact** without touching history — the case the trailer cannot serve.
- **Carries the envelope**, which a trailer cannot: v4 receipts bind `bh` to a canonical envelope
  body, and verifying that binding needs the envelope itself.
- ⚠ **It is a file, so it can be edited.** The sidecar is a *pointer*, never the authority. The
  authority is the signature on the receipt, which is checked the same way whichever carrier
  delivered it. A forged sidecar yields `INVALID_SIGNATURE`, not a false pass.
- ⚠ **`<sha>` is the full 40-character commit SHA.** Abbreviations collide, and a verifier
  resolving an abbreviation would be guessing which commit you meant.

### Precedence

`--from-commit` reads the **trailer first**, then the sidecar. The trailer is covered by the
commit SHA and the sidecar is not, so where both exist the immutable one wins. When both are
present and **disagree**, that is reported as a conflict and refused — silently preferring one
would hide exactly the tampering the precedence rule is there to make visible.

## Verifying

```bash
# Node
node cli.js --from-commit 9f2c1ab --keys keys/coderifts-keys.json

# Python
python3 -m coderifts_verifier._verify --from-commit 9f2c1ab
```

Both read the trailer or the sidecar from the repository in the current working directory (or
`--repo <path>`), then verify exactly as if the token had been pasted on the command line. **The
carrier changes nothing about the verification** — same statuses, same exit codes, same offline
default.

## What this does not prove

- **That the commit is authorised.** It proves a receipt is attached to it and that the receipt
  verifies. Whether that receipt *scopes* to this change is the authorisation question, answered
  by the scope/binding fields, not by the attachment.
- **That an unattached commit was unauthorised.** Nothing in this convention is enforced at commit
  time; a missing trailer means "no receipt was attached", which is not the same as "no receipt
  exists".
- **That the sidecar was written by anyone in particular.** It is an unsigned pointer. The
  signature on the receipt is the whole of the assurance.
- **Anything about history rewriting.** A rebase drops sidecars (they key on the old SHA) and
  carries trailers into new SHAs. Re-attaching after a rewrite is an operator step, and neither
  carrier detects that it did not happen.
