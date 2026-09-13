# Release verification and public keys

This directory contains public verification material, not private signing
keys. No signed public printer installer is available yet. The current
`0.1.0` candidate must not be treated as an official release.

## Linux package-signing identity

| Property | Value |
| --- | --- |
| Identity | `Fin3000 Linux Releases` |
| Format | OpenPGP, Ed25519 |
| Primary fingerprint | `FDFF3DCD55DDAAECCDB048E14F91CA50AA992F61` |
| Primary expiration | 2029-09-08 |
| Signing subkey fingerprint | `6C1594AE8A48B7D7649BEDA7DA6206688A5862E3` |
| Signing subkey expiration | 2027-09-08 |
| Public certificate | [linux-release-key.asc](linux-release-key.asc) |
| Machine-readable primary fingerprint | [linux-release-key.fingerprint](linux-release-key.fingerprint) |

The primary key certifies the signing subkey. Release verification requires
the exact certified signing subkey, not just any key in a supplied keyring.

A certificate and fingerprint supplied in the same download are not an
independent trust source. Before the first release, the full fingerprint must
also be confirmed through an authenticated Fin3000 channel. Reject unexpected,
expired or revoked signing identities and mismatched artifact hashes.

The initial graphical setup relies on HTTPS/WebPKI. Ubuntu's graphical package
installer does not automatically verify the detached release manifest. After
setup, APT authenticates the archive using its package-owned keyring and exact
`Signed-By` signing-subkey pin. Running `dpkg -i` is not a substitute for
release verification.

## Verify a release bundle offline

With Python 3.11 or newer and GnuPG installed, run from the repository root:

```sh
python3 -I scripts/verify-linux-release.py /absolute/path/to/release-bundle
```

The verifier does not download or install anything. It uses the pinned public
certificate in an isolated verifier directory, without the operator's private
keyring or network key discovery. There are no key, channel or clock overrides.

A bundle contains `release.json`, its detached signature `release.json.asc`,
the versioned printer and setup DEBs, and the versioned CycloneDX SBOM:

```text
release.json
release.json.asc
fin3000-printer_0.X.Y_amd64.deb
fin3000-printer-setup_0.X.Y_amd64.deb
fin3000-printer_0.X.Y.cdx.json
```

Manifest schema 2 has exactly these fields: `schemaVersion`, `product`,
`version`, `channel`, `platform`, `architecture`, `ubuntuVersions`,
`sourceCommit`, `buildId`, `minimumBackendVersion`, `issuedAt`, `expiresAt`,
and `artifacts`. The product is `fin3000-printer`, channel `production`,
platform `linux`, architecture `amd64`, and Ubuntu versions `["24.04", "26.04"]`.
UTC timestamps use `YYYY-MM-DDTHH:MM:SSZ`; validity is at most 31 days.
Each `deb`, `setup` and `sbom` artifact declares its exact filename, byte size
and lowercase SHA-256. Filenames must match the manifest version.

Successful verification binds those bytes to the pinned signer. It does not
prove native compatibility, backend availability or freedom from
vulnerabilities. Offline verification cannot discover a newer revocation
certificate. Installation must use its own verified, private snapshot rather
than a mutable download that was checked earlier.

## Receipt-verification identity

Upload receipts use a separate Ed25519 identity, not the OpenPGP package key:

| Property | Value |
| --- | --- |
| Key identifier | `fin3000-system-print-20260910-01` |
| Audience | `fin3000-printer:production` |
| Public key | [system-print-receipt-public.pem](system-print-receipt-public.pem) |
| SHA-256 of DER SubjectPublicKeyInfo | `791990275977eed393b12cc8cd206b7a41801da29a552caf57d6170d5841cffa` |

The production build profile pins the receipt key together with the permitted
service and upload origins. The presence of that profile does not establish
that account connection or upload is available. The receipt-signing private
key is not a build input and must never be packaged.

## SBOM and third-party materials

The verifier checks the SBOM's signed hash before parsing its narrow, flat
CycloneDX 1.6 release profile:

- The root component is the versioned printer application and its SHA-256
  matches the exact printer DEB.
- Source-commit and build-id properties match the release manifest.
- Components include the matching setup DEB, Node and its embedded
  dependencies. Component references are unique; explicit license declarations
  are required. Placeholder declarations and duplicate JSON keys are rejected.
- The dependency graph uses known references and reaches every component
  from the root. Node identifies its embedded dependencies.
- A complete-composition declaration is the publisher's assertion, not
  independent proof that an inventory is complete.

The inventory must be reconciled with the exact package payload and upstream
source, including required notices and corresponding source. Build-container
packages and source-only test dependencies must not be confused with shipped
runtime components. Structural validation is not a license-compatibility or
vulnerability audit. See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Maintainer workflow

[Building](../docs/BUILDING.md) describes authenticated runtime inputs,
unsigned package assembly, archive staging and verified publication output.
Signing and publication are separate, authorized operations. These build tools
do not sign artifacts or switch a live download directory.

Keep private keys, passphrases, revocation certificates and recovery exports
outside source repositories and build artifacts. Never put a passphrase in a
command line, environment variable or log. Key rotation must update the public
certificate and exact signer policy through the established trusted channel
before expiration. Do not silently accept a different primary identity.

Report suspected compromise using [SECURITY.md](../SECURITY.md).
