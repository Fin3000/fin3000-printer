#!/bin/sh
# Signatures were applied by build-macos.py. Authenticate through the local notarytool profile.
set -eu
if [ "$#" != 5 ]; then
  echo "Usage: $0 PACKAGE TEAM_ID NOTARY_PROFILE PRIVACY_SHA256 RELEASE_ROOT" >&2; exit 2
fi
package=$1
team=$2
profile=$3
privacy=$4
root=$5
case "$package" in /*) ;; *) echo 'Use an absolute package path.' >&2; exit 2;; esac
case "$root" in /*) ;; *) exit 2;; esac
printf %s "$team" | /usr/bin/grep -Eq '^[A-Z0-9]{10}$' || exit 2
printf %s "$privacy" | /usr/bin/grep -Eq '^[a-f0-9]{64}$' || exit 2
[ -f "$package" ] && [ ! -L "$package" ] && [ -d "$root" ] && [ ! -L "$root" ] || exit 2
name=$(basename "$package")
version=$(printf '%s\n' "$name" | sed -nE 's/^fin3000-printer_(0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))_arm64\.pkg$/\1/p')
[ -n "$version" ] && [ "$version" != '0.0.0' ] || exit 2
mkdir -p "$root/macos"
[ ! -L "$root/macos" ] || exit 2
stage=$(mktemp -d "$root/macos/.verify.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
target="$stage/$name"
cp "$package" "$target"
pkgutil --check-signature "$target" > "$stage/signature"
grep -E 'Developer ID Installer:.*\('"$team"'\)' "$stage/signature" >/dev/null
pkgutil --expand-full "$target" "$stage/expanded"
/usr/bin/python3 -I - "$stage/expanded" "$version" <<'PY'
from pathlib import Path
import sys,xml.etree.ElementTree as ET
root=Path(sys.argv[1])
distribution=ET.parse(root/'Distribution')
options=distribution.find('options'); supported=distribution.find('.//allowed-os-versions/os-version')
payloads=list(root.rglob('PackageInfo'))
assert options.get('hostArchitectures')=='arm64' and supported.attrib=={'min':'26.0','before':'27.0'}
assert len(payloads)==1
info=ET.parse(payloads[0]).getroot()
assert info.get('identifier')=='com.fin3000.printer.installer' and info.get('version')==sys.argv[2]
PY
payload="$stage/expanded/payload.pkg/Payload"
app="$payload/Applications/Fin3000 Drucker.app"
for component in "$app" "$app/Contents/Resources/node" "$payload/Library/Printers/Fin3000/pdf-filter" "$payload/Library/Printers/Fin3000/relay"; do
  codesign --verify --strict "$component"
  codesign -dv --verbose=4 "$component" 2>"$stage/component"
  grep -Fx "TeamIdentifier=$team" "$stage/component" >/dev/null
  grep -F 'Authority=Developer ID Application:' "$stage/component" >/dev/null
  grep -E 'flags=.*runtime' "$stage/component" >/dev/null
done
mkdir "$stage/certs"
/usr/bin/xar -f "$target" --extract-certs "$stage/certs"
cert=$(find "$stage/certs" -name cert00 -type f)
test -f "$cert"
xcrun notarytool submit "$target" --keychain-profile "$profile" --wait --output-format json > "$stage/submission.json"
id=$(/usr/bin/python3 -I -c 'import json,re,sys; v=json.load(open(sys.argv[1])); assert v["status"]=="Accepted" and re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}",v["id"]); print(v["id"])' "$stage/submission.json")
xcrun stapler staple "$target"
xcrun stapler validate "$target"
spctl --assess --type install --verbose=2 "$target"
pkgutil --check-signature "$target" >/dev/null
/usr/bin/python3 -I - "$root/macos" "$stage" "$name" "$team" "$privacy" "$id" "$version" "$cert" <<'PY'
import fcntl,hashlib,json,os,sys
from pathlib import Path
root,stage=map(Path,sys.argv[1:3]);name,team,privacy,identifier,version,cert=sys.argv[3:]
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as stream:
  for chunk in iter(lambda:stream.read(1<<20),b''):h.update(chunk)
 return h.hexdigest()
package=stage/name
manifest=dict(schemaVersion=1,product='fin3000-printer',channel='production',version=version,platform='macos',architecture='arm64',
 macOSMajor=26,teamId=team,installerCertificateSha256=digest(Path(cert)),notarizationId=identifier,gatekeeper=True,stapled=True,
 privacySha256=privacy,filename=name,size=package.stat().st_size,sha256=digest(package))
generation=stage/'generation';generation.mkdir(mode=0o755)
os.rename(package,generation/name);(generation/'release.json').write_text(json.dumps(manifest,indent=2)+'\n')
active=stage/'active.json';active.write_text(json.dumps(dict(version=version,manifestSha256=digest(generation/'release.json')))+'\n')
with (root/'.publish.lock').open('a') as lock:
 fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
 if (root/version).exists():raise SystemExit('The release version already exists.')
 os.rename(generation,root/version);os.replace(active,root/'active.json')
PY
