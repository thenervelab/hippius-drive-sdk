# hippius-drive

Pure-Python SDK and CLI for Hippius Drive (HCFS), an end-to-end encrypted file
store. Files are encrypted and signed on the client; the server only ever holds
ciphertext. The package reimplements the HCFS wire and crypto formats in Python,
with no Rust toolchain required, and is kept in lockstep with the reference Rust
client by known-answer vectors.

```bash
pip install hippius-drive
```

Status: pre-release. The library surface covers identity, folders, files
(single-shot and chunked upload, streaming download), listing, search,
summaries, rename, and delete.
