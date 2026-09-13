# Third-party components

Apache-2.0 covers Fin3000 Printer's original code and documentation, not a
relicensing of third-party components. Their original licenses and notices
continue to apply. This document is a guide to those notices, not a complete
software bill of materials (SBOM) or a distribution clearance.

## Repository and development dependencies

- `package-lock.json` records the pinned development dependencies and their
  declared licenses: TypeScript (Apache-2.0), `@types/node` (MIT), and
  `undici-types` (MIT). `npm ci` retrieves their upstream packages, including
  their license files. These packages are not runtime npm dependencies.
- `signing/node-runtime-supplement.json` contains separately attributed original
  upstream notices and the unchanged SmartString 1.0.1 source archive
  (MPL-2.0+), with source URLs and SHA-256 pins. Those embedded third-party
  materials retain their own licenses. The inventory distinguishes resolved
  dependencies, binary observations and selected-source evidence; it is not a
  claim that every listed source component is shipped or that the list is complete.
- Files in `signing/` containing public verification certificates are not private
  signing keys. Their presence does not imply endorsement by their owners or
  that a product release has been signed or published.

## Linux packages

The printer's QA and product builders require an authenticated upstream Node
binary and source archive. They install the following original materials under
`/usr/share/doc/<package>/`:

- `NODE-LICENSE`: the upstream Node license, including its bundled-component
  notices, without replacing them with the printer's Apache license;
- `NODE-SOURCE-NOTICES`: the pinned source notices and supplementary original
  notices. This collection also includes non-shipped build/test material;
- `vendor-source/smartstring-1.0.1.crate`: unchanged corresponding source for
  SmartString, including its upstream MPL license;
- `runtime-provenance.json`: the hashes and source identifiers binding these
  materials to the verified runtime inputs.

All three package builders (printer, QA printer and setup) also install this
document, `NOTICE`, and the project's full Apache license as `copyright` in
their respective documentation directory. The setup package does not bundle
Node and therefore does not include the Node documents above.

Libraries and tools installed separately through Ubuntu/APT retain their own
licenses and package copyright files under `/usr/share/doc/<dependency>/`.
The builders' declared dependencies are not a substitute for reviewing the
actual linked and shipped components.

Before an official binary release, the full dependency and license inventory,
required source distribution, security findings and native installation checks
must be reconciled. Adding the project's Apache license does not close those
release gates. See [README.md](README.md) and [signing/README.md](signing/README.md).
