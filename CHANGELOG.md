# Changelog

## [Unreleased]

- Keep the generated Debian package description and installed README aligned
  with the single-action automatic upload flow.

## [0.1.1] - 2026-09-30

- Upload a print copy automatically after the operating system print action,
  removing the redundant desktop confirmation. Persist admissions before
  transfer, serialize uploads, cap active work, and preserve explicit
  uncertain-result recovery without automatic resending.
- Show account and destination before printing, retain cancellability only for
  queued jobs, and document the single-action privacy and recovery behavior.

- Add a German project page with Fin3000 branding, product-specific search
  metadata, installation guidance and links to Fin3000.com. Include a
  self-contained Tailwind documentation build and branded README navigation.

- Publish the Linux printer source under Apache-2.0, with user, contributor,
  build and release-verification documentation.
- Make default contributor checks independent of other Fin3000 checkouts.
  Add a local Firefox test driver and a separate source-verification workflow.
- Install the GJS, CUPS and AppArmor validation prerequisites explicitly in
  source CI and document them for contributors.
- Preserve missing-driver and interruption errors in the native Firefox
  test probe instead of masking them as a session error.
- Test the QA package's fixed name and prerelease version independently of
  the desktop application's version.

## [0.1.0] — development baseline

This version identifies the initial candidate, not a signed public binary
release. Installer availability and supported platforms are described in
[README.md](README.md).

- Add a per-user Linux print destination and a desktop window for reviewing
  and explicitly confirming PDF uploads to the Fin3000 invoice inbox.
- Add account connection, secure-keyring credential storage, receipt
  verification and recovery of uncertain upload results without resending PDFs.
- Include offline help and native application/setup text in 26 languages.
- Add Ubuntu package builders, graphical setup, release-bundle verification
  and signed-archive preparation tools.
- Preserve third-party licenses and runtime provenance, and include isolated
  core, native integration, packaging and lifecycle tests.

Source availability does not establish production readiness or support for
every Linux distribution. Windows and macOS implementations are not included
in this candidate.
