# Vendored CodeRifts key snapshot

Pinned copy of `https://app.coderifts.com/.well-known/coderifts-keys.json`.
`coderifts-keys.json.sha256` must match this file. The CLI default (no `--key` /
`--keys` / `--fetch` / `--refresh-keys`) verifies against this snapshot **offline**.

A CA pins roots locally; this file is that pin. Fetching the live registry is
opt-in (`--refresh-keys` or `--keys <url>` / `--fetch <url>`). `--refresh-keys`
does **not** rewrite this snapshot.

Refresh the pin (operator / release step, not verify-time):

```
curl -fsS https://app.coderifts.com/.well-known/coderifts-keys.json -o keys/coderifts-keys.json
shasum -a 256 keys/coderifts-keys.json | awk '{print $1"  coderifts-keys.json"}' > keys/coderifts-keys.json.sha256
```
