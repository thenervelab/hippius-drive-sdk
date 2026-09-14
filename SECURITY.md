# Reporting a vulnerability

Please report privately rather than opening a public issue. Use GitHub's
[security advisory form](https://github.com/thenervelab/hippius-drive-sdk/security/advisories/new)
on this repository.

Include what you can: affected version, what an attacker gains, and the steps to
reproduce. A proof of concept helps but is not required to report.

## Scope

This repository is the Python SDK and CLI. Issues in the HCFS server or in the
Rust client belong elsewhere — say so in the report and it will be routed.

Of particular interest here:

- anything that causes plaintext or key material to leave the machine
- a decrypt path that accepts data it should reject, or a frame that reaches the
  caller before its authentication tag verifies
- a divergence from the reference Rust client that would corrupt or orphan a
  user's stored files
- anything that writes the recovery phrase unencrypted, or weakens how it is
  stored at rest

The security model, including what the design deliberately does **not** hide —
file sizes, timestamps, and plaintext paths — is written out in
[docs/security.md](docs/security.md). Behaviour documented there as a known
limitation is not a vulnerability, though an argument that it should change is
welcome as a normal issue.

## Supported versions

Pre-1.0: fixes land on the latest release only.
