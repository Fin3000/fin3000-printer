# Building and verifying Linux packages

These instructions are for contributors and release maintainers, not end-user
installation. The tools produce unsigned development candidates. Version
`0.1.0` has not been published as a signed public installer.

## Prerequisites

Use an ordinary user account on Linux with Git, Docker, Python 3.11 or newer,
GnuPG and the Node development tools described in
[CONTRIBUTING.md](../CONTRIBUTING.md). Product and setup builds require a clean,
committed checkout and compare their source inputs with that commit.

The build image is defined in `packaging/linux/Dockerfile.build`. Building it
downloads authenticated Ubuntu packages and retains Docker image/cache data:

```sh
docker build --file packaging/linux/Dockerfile.build --tag fin3000-printer-build:local .
docker image inspect --format '{{.Id}}' fin3000-printer-build:local
```

Pass the resulting immutable `sha256:` image identifier to package builders.
The image's package inventory records the actual build tools; it is not a
runtime SBOM. Compilation and package assembly subsequently run offline in a
read-only container without Linux capabilities. Do not replace the build image
identifier with a mutable tag.

## Authenticate the bundled runtime

The current runtime policy in `scripts/verify-node-runtime.py` pins Node
22.23.2. Prepare a local directory containing the official upstream inputs:

```text
node-v22.23.2-linux-x64.tar.xz
node-v22.23.2.tar.xz
SHASUMS256.txt
SHASUMS256.txt.sig
```

Verify them before packaging:

```sh
python3 -I scripts/verify-node-runtime.py /absolute/path/to/node-inputs
```

Verification checks the pinned upstream signer, certificate validity, signed
checksums and both archive hashes before parsing archive contents. It does
not extract or execute supplier archives, consult a personal keyring or look
up keys on the network. The binary and source root licenses must agree.

The separately hash-pinned `signing/node-runtime-supplement.json` preserves
additional original notices and corresponding source. It is not covered by
Node's upstream signature. Preserve its original notice bodies, provenance and
the unmodified SmartString source archive; do not replace supplier licenses
with this project's Apache license.

Updating Node requires reviewing the exact new upstream release, signer,
security advisories, source and embedded dependencies, then updating and
verifying all associated pins and notices. Do not follow `latest` or reuse an
inventory solely because a dependency version string looks unchanged.

## Public production build profile

`packaging/linux/production-profile.json` is a committed public build input,
not a secrets file. It defines fixed API/app origins, OAuth client and audience,
allowed quarantine origins, public receipt keys, and the minimum compatible
backend commit/version. Its schema is enforced by `build-linux-product.py`.

The current profile declares backend version `0.19.0`. This is a compatibility
declaration, not a runtime health check or an assertion that the public service
is enabled. Never place receipt private keys, tokens or development endpoints
in the production profile. Product builds have no CLI host/key overrides.

## Build the printer and setup candidates

Replace the placeholders below with real local inputs. Output directories must
be new absolute paths directly below this checkout's `reports/` directory,
with the indicated prefixes. Existing output is never overwritten.

```sh
python3 -I scripts/build-linux-product.py \
  --directory /absolute/printer-checkout/reports/linux-product-build-candidate \
  --node-release /absolute/path/to/node-inputs \
  --image sha256:IMMUTABLE_IMAGE_ID

python3 -I scripts/build-linux-bootstrap.py \
  --directory /absolute/printer-checkout/reports/linux-bootstrap-build-candidate \
  --image sha256:IMMUTABLE_IMAGE_ID
```

The product builder bundles the authenticated runtime, all language catalogs,
public configuration and original license material. It records source hashes,
runtime provenance, package metadata and runtime-component facts. Its manifest
explicitly remains `UNRELEASED` with `backendReadinessVerified: false`.

The setup package is separate. It contains the public archive certificate,
scoped APT configuration and the graphical installer, not the Node runtime.
Both builders produce unsigned DEBs. Neither installs packages, signs a
release, changes APT configuration on the build host or publishes downloads.

`scripts/build-linux-qa.py` builds a separate disposable-test package. Its
explicit loopback origins, receipt public key and package revision are test
inputs; they are never substitutes for the committed production profile.
Use `python3 -I scripts/build-linux-qa.py --help` for its complete argument
list. Do not distribute that package or convert it into a product release.

## Prepare a release bundle and APT archive

Reconcile both DEBs, the final dependency/license inventory, required source
distribution, current security findings and native installation results before
authorizing a release. The signed bundle must include the printer, setup
package and SBOM described in [Release verification](../signing/README.md).
Signing is a separate operation performed by the authorized custodian; the
repository does not supply a general-purpose signing command.

Once the release manifest has been independently signed, verify the bundle and
stage an unsigned archive:

```sh
python3 -I scripts/verify-linux-release.py /absolute/path/to/signed-bundle
python3 -I scripts/build-linux-archive.py /absolute/path/to/signed-bundle \
  --directory /absolute/printer-checkout/reports/linux-archive-build-candidate
```

The archive builder verifies a private snapshot, checks actual DEB identities,
and produces immutable pool files, Packages indexes and SHA-256 By-Hash files.
It intentionally does not create `InRelease`; its output is not publishable.
Archive validity is bounded by seven days and the signed manifest's expiry.

After the custodian has supplied the archive's signed `InRelease`, prepare a
new verified download generation:

```sh
python3 -I scripts/prepare-linux-publication.py \
  /absolute/path/to/signed-bundle /absolute/path/to/signed-archive \
  --directory /absolute/printer-checkout/reports/linux-publication-candidate
```

The command re-verifies the exact pinned signer, validity, canonical Release
metadata, packages and indexes. It writes `active.json` last inside the private
new generation. It does not sign, install, contact production or activate a
web-server mount. Operators must separately authorize and perform publication.

For updates, `--previous /absolute/path/to/prior-generation` accepts only an
operator-controlled prior generation. Its recorded hashes are rechecked;
untrusted downloads are not valid substitutes. Retain prior immutable pool and
By-Hash files needed by clients already updating. Never overwrite an existing
generation or discard locally modified APT configuration without review.

## Focused checks and native test boundaries

```sh
npm run test:linux-ingress
npm run test:linux-setup
npm run test:linux-backend
npm run test:linux-ui
npm run test:release
python3 -B -I -m unittest discover -s tests -p test_linux_archive.py
python3 -B -I -m unittest discover -s tests -p test_linux_publication.py
```

Native C checks need `libcups2-dev`, `libjson-c-dev` and `libssl-dev`.
`FIN3000_NATIVE_INCLUDE` can point to extracted development headers. GTK tests
use GJS/GTK 4 and an isolated Xvfb/D-Bus environment;
`FIN3000_UI_TOOLS` can point to an extracted Xvfb `usr` directory. Their private
test buses and keyrings must not be replaced with a real desktop credential
store. Installer/APT fixtures require Docker and their declared system tools.

`npm run preflight` only reports local prerequisites. Its exit code 3 means
native evidence has not been established; finding executables is not a native
test pass. It does not install software or contact Fin3000.

The explicit `probe:linux` and `probe:secrets` commands start disposable local
CUPS or keyring fixtures. Authorization probes build Docker images, which
download OS packages; their runtime containers are offline. Native printer and
Firefox probes can change an authorized test host's queue configuration and
require normal administrator authentication. The Firefox probe uses a
repository-local WebDriver helper and a fresh Firefox Snap profile; it does
not load any extension. Do not run these
commands on an ordinary workstation simply to check a source contribution.

Virtual-machine, container and unit checks do not replace real install,
upgrade, restart, removal, accessibility and printing checks on each supported
Ubuntu desktop. Keep test reports separate from public product instructions.
