<p>
  <a href="https://fin3000.com/">
    <img src="docs/assets/favicon.svg" width="64" height="64" alt="Fin3000 – zur Website">
  </a>
</p>

# Fin3000 Drucker

[Fin3000.com](https://fin3000.com/)
· [Tools & Downloads](https://fin3000.com/tools/)
· [Project page](https://fin3000.github.io/fin3000-printer/)

Send a PDF print copy to Fin3000 from an application's print dialog. Fin3000
Drucker adds **An Fin3000 senden (Cloud-Upload)** as a print destination. Once
you select it and press the operating system's print button, the copy is queued
and uploaded automatically; there is no second send button.

The source project is called `fin3000-printer` and is licensed under
[Apache-2.0](LICENSE).

## Availability and installation

The [Fin3000 tools page](https://fin3000.com/tools/) lists the signed installers available for download and their setup instructions.

The Ubuntu package supports Ubuntu 24.04 and 26.04 on Intel/AMD 64-bit systems with GNOME/Wayland. The macOS package supports macOS 26 on Apple Silicon. Both include their Node.js runtime. Printer setup requests administrator authentication when required. See [Building](docs/BUILDING.md) for developer builds.

## macOS 26 on Apple Silicon

Open Fin3000 Drucker in Applications after installing the package. Connect your Fin3000 account in the browser, choose a destination and authorize the per-user print queue. Choose **An Fin3000 senden (Cloud-Upload)** in the system print dialog. Open the app to view recent jobs or check an uncertain result. Remove the destination from the app before uninstalling it. The installer does not select a new default printer.

On a Mac with Xcode command-line tools, run `npm ci` and `python3 -m unittest discover -s tests -p test_macos.py`. Place the official Node.js 22.23.5 binary archive `node-v22.23.5-darwin-arm64.tar.xz` and source archive `node-v22.23.5.tar.xz` in the same directory. The builder verifies both SHA-256 pins and includes the upstream notices and SmartString source in the app. Build an isolated installer with `python3 scripts/build-macos.py --profile qa --archive /path/to/node-v22.23.5-darwin-arm64.tar.xz --config /path/to/qa-config.json --qa-ca /path/to/qa-ca.crt --output /path/to/new-build`. The QA configuration uses the shared build configuration schema, loopback origins and the QA server’s public receipt key.

For a production build pass `--profile production --team TEAM --app-identity APPLICATION_ID --installer-identity INSTALLER_ID` in place of the QA options. The release script verifies the app, runtime, relay, filter and installer, submits the package to Apple, staples the accepted ticket and checks Gatekeeper before publishing the final hash. Run `scripts/verify-macos-release.sh` without arguments for its inputs. Only a tested, notarized production package qualifies for the public download.

## How printing works

The following describes the Linux application. Account connection and upload
are not yet offered as a supported public service.

1. Open **Fin3000 Printer** and choose **Set up the printer**. Setup creates a
   destination for your Linux user and enables background startup at sign-in.
   Existing printers and your default printer remain unchanged.
2. Choose **Connect to Fin3000**. Sign in and approve the connection in your
   browser. Wait until the desktop app reports that it is ready for the
   intended account and destination.
3. Print from your application to **An Fin3000 senden (Cloud-Upload)**.
   Firefox may display the queue identifier `Fin3000-…` instead of its label.
   In Chromium-based browsers, open the system print dialog with
   **Ctrl+Shift+P**.
4. The app queues and uploads the print copy automatically. While a copy is
   still waiting behind another upload, you can cancel it in the desktop app.
5. Check the result in the app. An accepted copy has reached Fin3000; further
   document processing may still be running.

A print copy can differ from the original invoice and may omit structured
e-invoice data. Upload the original file instead when you need to retain those
data. The printer accepts PDF print copies up to 20 MiB.

## Privacy and interrupted uploads

Printing to this destination is a cloud upload, not a paper printout. Selecting
the destination and pressing the operating system's print button starts that
upload. The app shows the connected account and destination before printing.
Login credentials use the desktop's secure keyring. A locked or unavailable
keyring prevents the app from becoming ready.

Jobs that cannot safely start after a restart or locked session are cancelled
and must be printed again. If a result is uncertain, **check its status before
printing again**. Recovery checks the existing operation; it does not resend
the PDF. The app can save
an unresolved-status file containing technical operation identifiers, not the
invoice or login credentials. Keep that file private: it is a recovery aid,
not proof that a document was received.

## Troubleshooting and removal

- **No printer destination:** open the app and complete printer setup. If it
  reports a configuration conflict, do not overwrite another printer or
  disable the operating system's security controls.
- **Sign-in or keyring problem:** unlock the login keyring or sign in to Linux
  again, then reconnect. Never paste credentials into a public issue.
- **Uncertain result:** use **Open print status in Fin3000** from the original
  account before making another print copy.
- **Remove the destination:** choose **Prepare for removal**, resolve any
  pending jobs, then remove your print queue. Removing the queue does not
  delete documents already in Fin3000 or local recovery records. Uninstall
  the application separately through Ubuntu's package manager.

The app also includes offline help for its controls and status messages.

## Support and development

For questions or bug reports, contact [mail@fin3000.com](mailto:mail@fin3000.com).
Include the app version, Ubuntu version and a short reproduction using a
synthetic document. Do not attach invoices, credentials or unredacted logs.
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

- [Contributing and local checks](CONTRIBUTING.md)
- [Building development packages](docs/BUILDING.md)
- [Release verification and public keys](signing/README.md)
- [Change history](CHANGELOG.md)
- [License](LICENSE), [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES.md)

Third-party components retain their original licenses. This project's license
does not relicense other Fin3000 services or grant permission to brand a
derivative product as Fin3000.
