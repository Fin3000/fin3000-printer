# Fin3000 Drucker

Send a PDF print copy to your Fin3000 invoice inbox from an application's print
dialog. Fin3000 Drucker adds **An Fin3000 senden (Cloud-Upload)** as a print
destination and asks you to confirm each upload in its desktop window.

The source project is called `fin3000-printer` and is licensed under
[Apache-2.0](LICENSE).

## Availability and installation

The first Linux release is being prepared. **There is no signed public
installer or production-supported release yet.** Version `0.1.0` currently
identifies an unreleased candidate. Do not install unsigned candidates on a
production workstation or use them with real invoices.

The initial target is Ubuntu 24.04 and 26.04 LTS on Intel/AMD 64-bit computers,
using GNOME/Wayland. Windows and macOS versions are planned, not available.
Other Linux distributions and desktops are not currently supported targets.

When a signed release is available, use the installer and verification
instructions supplied through Fin3000's official download channel. The setup
application uses Ubuntu's package manager; printer setup asks for normal
administrator authentication. End users do not need to install Node.js.
A source checkout is not an installer. See [Building](docs/BUILDING.md) if you
want to work on development packages.

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
4. Check the destination and print-copy details in the desktop window, then
   choose **Send print copy to Fin3000**. Choose **Cancel** if you do not want
   to upload it. Each copy needs its own confirmation.
5. Check the result in the app. An accepted copy has reached Fin3000; further
   document processing may still be running.

A print copy can differ from the original invoice and may omit structured
e-invoice data. Upload the original file instead when you need to retain those
data. The printer accepts PDF print copies up to 20 MiB.

## Privacy and interrupted uploads

Printing to this destination is a cloud upload, not a paper printout. The app
shows where the copy will go before you send it. Login credentials use the
desktop's secure keyring. A locked or unavailable keyring prevents the app
from becoming ready.

Unconfirmed copies are not automatically sent after you unlock your desktop.
If a result is uncertain, **check its status before printing again**. Recovery
checks the existing operation; it does not resend the PDF. The app can save
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
