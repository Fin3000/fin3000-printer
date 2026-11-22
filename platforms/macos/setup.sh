#!/bin/sh
# Installed root-owned. Only manage this user's own registered queue.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
vendor='/Library/Printers/@VENDOR@'
service='@SERVICE@'
[ "$(id -u)" = 0 ] && { [ "$#" = 2 ] || [ "$#" = 3 ]; } || exit 1
action=$1
uid=$2
case "$uid" in ''|*[!0-9]*) exit 1;; esac
[ "$uid" -ge 501 ] && [ "$uid" -le 2147483647 ] || exit 1
user=$(id -nu "$uid")
[ "$(stat -f %u /dev/console)" = "$uid" ] || exit 1
queue="@VENDOR@-$uid"
record="$vendor/users/$uid"
parent="/private/var/tmp/$service"
dir="$parent/$uid"
ppd="/etc/cups/ppd/$queue.ppd"
# The package pre-installs both fixed parent directories, owned by root.
for root in "$vendor" "$vendor/users" "$parent"; do
  [ -d "$root" ] && [ ! -L "$root" ] && [ "$(stat -f %u:%Lp "$root")" = '0:755' ] || exit 1
done
if [ "$#" = 2 ]; then
  exec /usr/bin/lockf -k -t 10 "$vendor/users/.$uid.lock" "$0" "$action" "$uid" locked
fi
[ "$3" = locked ] || exit 1
lock=$(mktemp -d "$vendor/users/.configure.XXXXXXXX")
tmp=''
created_dir=0
created_queue=0
created_plist=0
bootstrapped=0
label="$service.cups.$uid"
plist="/Library/LaunchDaemons/$label.plist"
case "$user" in ''|*[!A-Za-z0-9_.-]*) exit 1;; esac
cat > "$lock/service.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>$label</string><key>UserName</key><string>$user</string>
<key>ProgramArguments</key><array><string>$vendor/relay</string></array>
<key>Sockets</key><dict><key>Cups</key><dict><key>SockPathName</key><string>$parent/cups-$uid.sock</string>
<key>SockPathMode</key><integer>438</integer><key>SockType</key><string>stream</string></dict></dict>
</dict></plist>
PLIST
remove_endpoint() {
  endpoint="$parent/cups-$uid.sock"
  if [ -e "$endpoint" ] || [ -L "$endpoint" ]; then
    [ -S "$endpoint" ] && [ ! -L "$endpoint" ] && [ "$(stat -f %u "$endpoint")" = 0 ] || return 1
    rm -f "$endpoint"
  fi
}
enable_relay() {
  if [ -e "$plist" ] || [ -L "$plist" ]; then
    [ -f "$plist" ] && [ ! -L "$plist" ] && cmp -s "$lock/service.plist" "$plist" || return 1
  else
    [ ! -e "$parent/cups-$uid.sock" ] || return 1
    install -o root -g wheel -m 0644 "$lock/service.plist" "$plist"
    created_plist=1
  fi
  if ! launchctl print "system/$label" >/dev/null 2>&1; then
    launchctl bootstrap system "$plist"
    bootstrapped=1
  fi
}
cleanup() {
  if [ "$bootstrapped" = 1 ]; then launchctl bootout "system/$label" && remove_endpoint || :; fi
  if [ "$created_plist" = 1 ]; then rm -f "$plist"; fi
  rm -f "$lock/service.plist"
  if [ "$created_queue" = 1 ]; then lpadmin -x "$queue" || :; fi
  if [ "$created_dir" = 1 ]; then rmdir "$dir" 2>/dev/null || :; fi
  if [ -n "$tmp" ]; then rm -f "$tmp"; fi
  rmdir "$lock"
}
trap cleanup EXIT
if [ -f "$record" ] && [ ! -L "$record" ]; then
  generation=$(cat "$record")
  [ -f "$ppd" ] && grep -Fqx "*Fin3000Generation: \"$generation\"" "$ppd" || exit 1
  case "$action" in
    configure) enable_relay; bootstrapped=0; created_plist=0; exit 0 ;;
    remove)
      [ -z "$(lpstat -W not-completed -o "$queue")" ] || exit 1
      if [ -f "$plist" ]; then
        cmp -s "$lock/service.plist" "$plist" || exit 1
        if launchctl print "system/$label" >/dev/null 2>&1; then launchctl bootout "system/$label"; fi
        remove_endpoint
        rm -f "$plist"
      fi
      lpadmin -x "$queue"
      rm -f "$record"
      # A running agent owns the socket. It closes and unlinks it before removal.
      rmdir "$dir"
      exit 0 ;;
    *) exit 1 ;;
  esac
fi
[ "$action" = configure ] || exit 1
if lpstat -p "$queue" >/dev/null 2>&1 || [ -e "$ppd" ] || [ -e "$dir" ] || [ -L "$dir" ]; then exit 1; fi
generation=$(uuidgen | tr A-F a-f)
tmp=$(mktemp "$lock/ppd.XXXXXX")
cat "$vendor/Fin3000.ppd" > "$tmp"
printf '*Fin3000Generation: "%s"\n' "$generation" >> "$tmp"
mkdir -m 0750 "$dir"
created_dir=1
chown "$uid:_lp" "$dir"
enable_relay
lpadmin -p "$queue" -D '@DISPLAY@' -E -v file:///dev/null -P "$tmp" -u "allow:$user" -o printer-is-shared=false -o printer-error-policy=abort-job -o printer-op-policy=authenticated
created_queue=1
printf '%s\n' "$generation" > "$lock/binding"
chmod 0644 "$lock/binding"
mv "$lock/binding" "$record"
created_queue=0
created_dir=0
bootstrapped=0
created_plist=0
