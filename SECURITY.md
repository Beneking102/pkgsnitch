# Security

pkgsnitch runs code that may be hostile, so its own weaknesses matter.

## Reporting a vulnerability

Please report privately through GitHub's
[security advisories](https://github.com/Beneking102/pkgsnitch/security/advisories/new)
rather than a public issue. Include what you observed and how to reproduce it.

Things that count:

- observed code affecting the host, or leaving the sandbox network
- a package hiding behavior from the report, or forging a clean one
- crafted package names, versions, lockfiles or traces making pkgsnitch run
  commands, write outside its cache, or crash

## Threat model

The sandbox is a Docker container with every capability dropped,
`no-new-privileges`, process and memory limits, and no network while package
code runs. That stops ordinary malware. It is not a guarantee against a
kernel or container-runtime exploit: run pkgsnitch where that residual risk
is acceptable, such as a CI runner or a virtual machine.

Known gaps are listed under "Limits" in the [README](README.md#limits).
