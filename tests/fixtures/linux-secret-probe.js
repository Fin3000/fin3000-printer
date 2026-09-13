// Native GJS fixture. Deliberately synchronous and bounded by its parent process;
// this is not UI code. Never run against a desktop session bus.
imports.gi.versions.Secret = '1';
const { GLib, Gio, Secret } = imports.gi;
const root = GLib.getenv('FIN3000_SECRET_PROBE_ROOT');
if (!root || !/^\/tmp\/fin3000-secret-probe-[A-Za-z0-9]+$/.test(root) ||
    GLib.getenv('XDG_DATA_HOME') !== root + '/data' ||
    GLib.getenv('XDG_RUNTIME_DIR') !== root + '/runtime' ||
    GLib.getenv('DBUS_SESSION_BUS_ADDRESS')?.split(',')[0] !== `unix:path=${root}/runtime/bus` ||
    GLib.getenv('DISPLAY') || GLib.getenv('WAYLAND_DISPLAY')) {
    throw new Error('Private test bus required');
}

// Wait for our explicit keyring daemon, not D-Bus autoactivation of a second one.
const bus = Gio.bus_get_sync(Gio.BusType.SESSION, null);
let ready = false;
for (let attempt = 0; attempt < 40; attempt++) {
    const reply = bus.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus',
        'org.freedesktop.DBus', 'NameHasOwner', new GLib.Variant('(s)', ['org.freedesktop.secrets']),
        new GLib.VariantType('(b)'), Gio.DBusCallFlags.NONE, 1000, null);
    if (reply.deep_unpack()[0]) { ready = true; break; }
    GLib.usleep(50000);
}
if (!ready) throw new Error('Disposable keyring service did not start');
const schema = new Secret.Schema('com.fin3000.Printer.SyntheticProbe', Secret.SchemaFlags.NONE,
    { fixture: Secret.SchemaAttributeType.STRING });
const attributes = { fixture: GLib.uuid_string_random() };
const secret = GLib.uuid_string_random();
if (!Secret.password_store_sync(schema, attributes, 'login', 'Fin3000 SYNTHETIC ONLY', secret, null)) {
    throw new Error('Synthetic secret storage failed');
}
if (Secret.password_lookup_sync(schema, attributes, null) !== secret) throw new Error('Secret round trip failed');
if (!Secret.password_clear_sync(schema, attributes, null) || Secret.password_lookup_sync(schema, attributes, null) !== null) {
    throw new Error('Synthetic secret deletion failed');
}
Secret.password_store_sync(schema, attributes, 'login', 'Fin3000 SYNTHETIC ONLY', secret, null);
const service = Secret.Service.get_sync(Secret.ServiceFlags.OPEN_SESSION, null);
const collection = Secret.Collection.for_alias_sync(service, 'login', Secret.CollectionFlags.NONE, null);
if (!collection) throw new Error('Disposable login collection missing');
const [lockedCount] = service.lock_sync([collection], null);
if (lockedCount !== 1) throw new Error('Collection did not lock');
// A new item proxy with no UNLOCK/LOAD_SECRETS flags: cached secrets would make
// this test meaningless. Missing access must not turn into an unlock prompt.
const items = service.search_sync(schema, attributes, Secret.SearchFlags.NONE, null);
if (items.length !== 1 || !items[0].get_locked()) throw new Error('Expected a locked fresh item');
let denied = false;
try { items[0].load_secret_sync(null); }
catch (error) { denied = error.matches(Secret.error_get_quark(), Secret.Error.IS_LOCKED); }
if (!denied || items[0].get_secret() !== null) throw new Error('Locked secret was readable');
print(JSON.stringify({ stored: true, roundTrip: true, deleted: true, lockedReadDenied: true }));
