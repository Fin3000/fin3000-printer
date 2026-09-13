# Contributing to Fin3000 Printer

Fin3000 Printer is an independent desktop application. The first Linux release
is in development; see [README.md](README.md) for availability and the intended
user workflow.

## Development setup

Use Ubuntu with Node.js 22.18 or newer, including TypeScript execution support,
and Python 3.11 or newer. Native checks also use the operating system's GJS
and GTK 4, libsecret, CUPS, AppArmor and build tools. The core process tests
expect the Ubuntu GJS executable layout.

From the repository root, install the pinned development dependencies and run
the relevant checks:

```sh
npm ci
npm run check:core
npm run test:core
npm test
python3 -B -I -m unittest discover -s tests -p test_project_license.py
python3 -B -I -m unittest discover -s tests -p test_linux_package.py
python3 -B -I -m unittest discover -s tests -p test_linux_product_package.py
git diff --check
```

All default tests run from this repository without sibling checkouts. The optional
`npm run test:workspace` tests maintainer workspace integration and is not a
standalone contributor prerequisite.

These checks do not install a product or prove that printing works on a native
desktop. Additional checks are available for Linux ingress, setup, native
backends, GTK presentation, package lifecycle and release verification. See
[Building](docs/BUILDING.md) for dependencies and commands.

## Safe native testing

Use disposable virtual machines and synthetic PDFs for printer installation,
authentication, upload and removal tests. Do not connect development builds to
live accounts or process real invoices. Never run installed root helpers
directly from a writable source checkout.

Some `probe:*` commands start processes or change printer configuration; they
are not part of passive environment inspection. Read their help and source
before running them. Native printer changes require explicit authorization
and the normal operating-system authentication dialog. Do not disable
AppArmor, install passwordless privilege rules or alter another user's queue
to make a test pass.

## Changes and licensing

Work on a feature branch and submit a pull request. Explain the user-visible
change, include focused tests, and add an entry under `Unreleased` in
`CHANGELOG.md`. Do not add generated packages, local reports, real invoices,
credentials, tokens or private signing keys to Git.

By intentionally submitting a contribution for inclusion, you submit it under
Apache-2.0 as described in section 5 of [LICENSE](LICENSE), unless explicitly
stated otherwise. Only contribute material you are entitled to submit. Preserve
upstream attribution and identify the source and license of third-party code.
This is not a copyright assignment or a separate contributor license agreement.

Security issues should follow [SECURITY.md](SECURITY.md), not a public issue
containing exploit details or user data. A source contribution or merge is not
an approval to sign, publish or deploy an official installer.
