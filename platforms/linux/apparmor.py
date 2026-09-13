"""Fixed package profiles; renderer only, never edits or reloads host policies."""
BACKEND = "/usr/lib/cups/backend/fin3000"
VALIDATOR = "/usr/lib/fin3000-printer/bin/pdf-validator"

# Do not include abstractions/base: it permits unrelated Unix peers and user
# .Private paths. Dynamic libraries are OS-owned; neither profile can execute
# a shell or read a desktop keyring, OAuth state or unrelated document.
LIBRARIES = """
  /etc/ld.so.cache r,
  /etc/gnutls/config r,
  /{usr/,}lib/x86_64-linux-gnu/*.so* mr,
  /{usr/,}lib64/ld-linux-x86-64.so* mr,
  /usr/lib/locale/** r,
  /usr/share/locale/** r,
  /usr/share/locale-langpack/** r,
  /etc/locale.alias r,
  /usr/lib/x86_64-linux-gnu/gconv/gconv-modules* r,
  /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.d/ r,
  /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.d/*.conf r,
  /usr/lib/x86_64-linux-gnu/gconv/*.so mr,
  /etc/localtime r,
  /usr/share/zoneinfo/** r,
  /dev/null rw,
  /dev/zero rw,
  /dev/urandom r,
  /proc/[0-9]*/attr/current r,
  /proc/[0-9]*/{maps,auxv,status} r,
  /proc/sys/crypto/fips_enabled r,
"""


def backend_profile():
    return f"""#include <tunables/global>
profile fin3000-printer-backend {BACKEND} flags=(attach_disconnected) {{
  {BACKEND} mr,
{LIBRARIES}
  / r,
  /var/ r,
  /var/lib/ r,
  /var/lib/fin3000-printer/ r,
  /var/lib/fin3000-printer/lifecycle/ r,
  /var/lib/fin3000-printer/lifecycle/lease rk,
  /var/lib/fin3000-printer/lifecycle/ready r,
  /etc/ r,
  /etc/{{nsswitch.conf,passwd,group}} r,
  /etc/ssl/openssl.cnf r,
  /etc/cups/client.conf r,
  /etc/fin3000-printer/ r,
  /etc/fin3000-printer/installations/ r,
  /etc/fin3000-printer/installations/[0-9]*.json r,
  /var/spool/cups/d[0-9]*-[0-9]* r,
  /run/cups/cups.sock rw,
  /run/user/[0-9]*/fin3000-printer/ingest.sock rw,
  unix (create, getopt, setopt, shutdown) type=stream,
  unix (connect, send, receive) type=stream peer=(label=/usr/sbin/cupsd),
  unix (create, getopt, setopt) type=seqpacket addr=none,
  unix (connect, send, receive) type=seqpacket peer=(label=unconfined),
  deny unix (connect, send, receive) type=seqpacket peer=(addr=@**),
  deny network inet,
  deny network inet6,
  deny /etc/shadow r,
  deny /home/** rwklmx,
  deny /run/user/[0-9]*/{{bus,keyring/**}} rwklmx,
  signal (receive) peer=/usr/sbin/cupsd,
  signal (receive) peer=unconfined,
  signal (send) set=chld peer=/usr/sbin/cupsd,
}}
"""


def validator_profile():
    return f"""#include <tunables/global>
profile fin3000-printer-pdf-validator {VALIDATOR} flags=(attach_disconnected) {{
  {VALIDATOR} mr,
  /usr/lib/fin3000-printer/bin/no-core.so mr,
  /usr/bin/pdfinfo rix,
{LIBRARIES}
  /etc/fonts/** r,
  /usr/share/fonts/** r,
  /var/cache/fontconfig/** r,
  /usr/share/poppler/** r,
  deny network,
  deny /home/** rwklmx,
  deny /run/user/** rwklmx,
  deny /etc/shadow r,
  signal (receive) peer=unconfined,
  signal (send) set=chld peer=unconfined,
}}
"""


def cups_transition():
    return f"""{BACKEND} Px -> fin3000-printer-backend,
signal peer=fin3000-printer-backend,
unix peer=(label=fin3000-printer-backend),
"""
