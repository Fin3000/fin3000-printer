# Fin3000 Printer contributor guidance

- Keep the desktop client, installer and their checks self-contained in this repository.
- Work on a feature branch and submit changes through reviewed pull requests.
- Run the relevant checks in CONTRIBUTING.md before pushing; update CHANGELOG.md.
- The Linux target is Ubuntu 24.04/26.04 LTS on GNOME/Wayland, amd64. The macOS installer is tested on macOS 26 with Apple Silicon. Public Mac packages require Developer ID signing and notarization. Windows is planned.
- Preserve single-action automatic upload, owner binding, receipt verification and recovery without automatic resending.
- Native tests use authorized disposable systems and synthetic PDFs only.
- Never bypass normal administrator authentication, weaken AppArmor or alter unrelated printers.
- Do not include credentials, invoices, private signing keys or local reports in Git or artifacts.
- Source publication, component tests and package builds do not establish a supported binary release.
- Keep upstream license material and required corresponding source intact.
- Document building and verification without assuming a private workspace or sibling repositories.
