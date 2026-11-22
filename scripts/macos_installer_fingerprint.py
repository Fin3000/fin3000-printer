"""Read the installer signer's SHA-256 from a verified, C-locale pkgutil report."""

from pathlib import Path
import re
import sys


def installer_fingerprint(report, team):
    _, heading, chain = report.partition("Certificate Chain:\n")
    signer, _, details = chain.strip().partition("\n")
    expected = rf"1\. Developer ID Installer: .+ \({re.escape(team)}\)"
    if not heading or not re.fullmatch(expected, signer):
        raise ValueError("The first certificate must be a Developer ID Installer for the requested team.")

    # The issuer and the root also have fingerprints. Only inspect the leaf.
    leaf = re.split(r"(?m)^[ \t]*(?:-{4,}[ \t]*$|\d+\.[ \t])", details, maxsplit=1)[0]
    _, label, value = leaf.partition("SHA256 Fingerprint:")
    octets = value.split()
    if not label or len(octets) != 32 or not all(re.fullmatch(r"[0-9A-Fa-f]{2}", byte) for byte in octets):
        raise ValueError("The installer certificate has no valid SHA-256 fingerprint.")
    return "".join(octets).lower()


if __name__ == "__main__":
    try:
        print(installer_fingerprint(Path(sys.argv[1]).read_text(encoding="utf-8"), sys.argv[2]))
    except ValueError as error:
        sys.exit(str(error))
