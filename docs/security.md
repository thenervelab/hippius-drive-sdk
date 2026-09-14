# Security model

What this SDK protects, what it does not, and why.

This has not been independently audited. It reimplements formats defined by the
Rust client, so it inherits that design's properties rather than choosing them.

## What protects your file contents

Every file is encrypted before it leaves your machine with **XChaCha20-Poly1305**,
in 256 KiB frames. Each frame is authenticated, and the decoder verifies a
frame's tag before handing you a single byte of it — so a tampered or truncated
download fails rather than producing partial plaintext.

Each file gets a fresh 24-byte random base nonce; per-frame nonces derive from
it by XORing the frame index into the low 8 bytes. At 192 bits, random nonces do
not collide in practice.

The key is 32 bytes derived from your recovery phrase:

```
folder_mnemonic = BIP-39(SHA-256(master_seed[:32] || label))
key             = folder_mnemonic.to_seed("")[:32]
```

One key per folder label, derived deterministically, so any device with the
phrase reaches the same files. **The server never receives the phrase or the
key.**

## What the server can see

Encryption hides file *contents*. It does not hide everything, and the gap is
larger than people usually assume.

| The server sees | Why |
|---|---|
| **Plaintext file paths and names** | Sent as `relative_path` and `file_name` so `browse` and `search` work server-side |
| Exact plaintext size of every file | `size_bytes` drives the quota gate and the summaries |
| Upload and modification times | Row metadata |
| Number of files, their revisions, and every change | Ordinary storage bookkeeping |
| `path_hash` = `BLAKE3(path)` | The file's identifier |
| `salted_hash` = `BLAKE3(account_address ‖ plaintext)` | Lets a client tell whether content changed without the nonce |
| Which client family uploaded | The `source` field, for analytics |

Two consequences worth being explicit about:

**Paths are not secret.** `encrypted_path` is also sent, but the plaintext path
travels beside it because the server has to index it. If a filename would
disclose something — a person's name, a diagnosis, a company being acquired —
encryption does not cover you. Use opaque names for anything sensitive.

**`path_hash` is unsalted.** It is a plain BLAKE3 of the path, identical across
all accounts, so anyone holding one can confirm a *guessed* path. `salted_hash`
is salted with the account address, so content fingerprints cannot be correlated
across accounts — but within one account, two files with identical contents are
visibly identical.

Traffic analysis is not addressed: file sizes and timing are visible to anyone
watching the connection, TLS notwithstanding.

## Your recovery phrase

The phrase is the whole security boundary.

- **Anyone who has it can decrypt every file** that account has ever stored,
  including files written before the phrase leaked.
- **Losing it loses the data.** There is no recovery path; nobody can reset it.
- **It cannot be rotated.** Deriving new keys orphans everything already
  encrypted under the old ones. There is no re-encryption flow in v1.

That last point means the phrase has no forward secrecy: a phrase compromised
today exposes everything stored in the past as well as the future.

### At rest

Two formats, both implemented here:

| | KDF | Cipher |
|---|---|---|
| `enc_mnemonic.json` (desktop) | PBKDF2-HMAC-SHA256, 600,000 iterations | AES-256-GCM |
| Sealed blob (console) | Argon2id, 128 MiB, t=3, p=1 | XChaCha20-Poly1305, account address as AAD |

Both derive from a password you choose, so **that password is what stands
between an attacker with the file and your files**. The 600,000-iteration count
matches current OWASP guidance for PBKDF2-SHA256; a blob written with weaker
parameters still opens, since the parameters travel with it — this SDK reads
what it is given rather than assuming. The parameters are also under an
attacker's control if the file is, so the opener caps them and rejects
anything larger instead of hanging: PBKDF2 at 10,000,000 iterations, Argon2id
at 256 MiB, 16 passes and 8 lanes, and only `argon2id`.

The sealed blob binds the account address as associated data, so a server
swapping one account's blob for another's fails the tag check instead of
silently installing the wrong seed.

Writes to `enc_mnemonic.json` are atomic, mode `0600`, keeping the previous
version as `.bak`.

## Authentication and authorisation

Your API token authenticates you; the server resolves it to an account address
and refuses any request naming a different one. The token is a bearer
credential — anyone holding it can act as you.

Uploads carry an Ed25519 signature, but over a narrower scope than it looks:

```
"I here by declare that the file with hash {ciphertext_hash} that i am
uploading is in par with the ToS of the provider"
```

It covers **the ciphertext hash only** — not the size, paths, or revision
fields. Those are metadata the server accepts on trust once the token matches.
Integrity of file content is enforced by the server recomputing BLAKE3 over the
blob it received.

The signing key is not bound to your account: the server reads `signing_key` out
of the manifest and verifies the signature against it. Account binding comes
entirely from the bearer token. A practical consequence is that the recovery
phrase and the account are independent — useful for testing, and the reason the
interop suite can generate a throwaway phrase per run.

## A note on key reuse

The Ed25519 signing seed and the XChaCha20-Poly1305 key are **the same 32
bytes**. Ed25519 consumes only a seed and the AEAD is a separate primitive, so
this does not break either, and it is what the Rust client does — compatibility
requires matching it.

It is still not a pattern to copy into new designs. Separate keys for separate
purposes costs nothing and removes a class of cross-protocol argument you would
otherwise have to make carefully.

## Reporting a vulnerability

Please report privately rather than opening a public issue: use GitHub's
[security advisory](https://github.com/thenervelab/hippius-drive-sdk/security/advisories/new)
form on this repository.
