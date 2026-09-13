# Security

## Supported versions

There is no production-supported printer release yet. Version `0.1.0` is an
unreleased candidate, not a signed public installer. Development packages must
not be used on production workstations or with real invoices.

Source availability, a successful build or a passing test suite is not a
security certification.

## Reporting a vulnerability

Send a minimal, non-sensitive initial report to `mail@fin3000.com` with the
subject `Fin3000 Printer security report`. Include the affected commit/version,
platform, expected behavior and a synthetic reproduction where possible.

Do not publish credentials, invoice data, private keys or unredacted logs in
issues, pull requests or email. If sensitive evidence is needed, first ask for
an appropriate transfer channel. No response-time or bounty commitment is
implied by this reporting address.

## Release verification

Public verification keys are documented in [signing/README.md](signing/README.md).
Release-signing private keys, receipt-signing private keys and recovery exports
must never enter Git or downloadable artifacts.

An official binary release must have authenticated package metadata, a
reconciled dependency and license inventory, a current vulnerability review,
and native installation checks. A valid signature proves authenticity and
integrity against a trusted key; it does not prove that software has no defects.

This policy covers the printer repository. Do not include data from other
Fin3000 applications or services in a public printer report.
