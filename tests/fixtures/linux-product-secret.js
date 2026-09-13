// Exercise the PRODUCT libsecret adapter only on our explicit disposable bus.
import GLib from 'gi://GLib';
import Gio from 'gi://Gio';
import Secret from 'gi://Secret?version=1';
import { secretOperation } from '../../platforms/linux/secret-store.js';

const root = GLib.getenv('FIN3000_SECRET_PROBE_ROOT');
if (!root || !/^\/tmp\/fin3000-secret-probe-[A-Za-z0-9]+$/.test(root) ||
    GLib.getenv('XDG_DATA_HOME') !== `${root}/data` || GLib.getenv('XDG_RUNTIME_DIR') !== `${root}/runtime` ||
    GLib.getenv('DBUS_SESSION_BUS_ADDRESS')?.split(',')[0] !== `unix:path=${root}/runtime/bus` ||
    GLib.getenv('DISPLAY') || GLib.getenv('WAYLAND_DISPLAY')) throw new Error('Private test bus required');
const bus = Gio.bus_get_sync(Gio.BusType.SESSION, null);
let ready = false;
for (let index = 0; index < 40; index++) {
    if (bus.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'NameHasOwner',
        new GLib.Variant('(s)', ['org.freedesktop.secrets']), new GLib.VariantType('(b)'), Gio.DBusCallFlags.NONE, 1000, null).deep_unpack()[0]) { ready = true; break; }
    GLib.usleep(50000);
}
if (!ready) throw new Error('Disposable keyring did not start');
const call = (action, value) => secretOperation({ environment: 'qa', action, ...(value === undefined ? {} : { value }) });
if (call('load').value !== null) throw new Error('Fixture must start empty');
const first = JSON.stringify({ test: 'Änderung', secret: GLib.uuid_string_random() });
call('save', first);
if (call('load').value !== first) throw new Error('Product store/read failed');
if (secretOperation({ action: 'load', environment: 'production' }).value !== null) throw new Error('QA leaked into production namespace');
const second = JSON.stringify({ test: GLib.uuid_string_random() });
call('save', second);
if (call('load').value !== second) throw new Error('Product refresh overwrite failed');
call('clear');
if (call('load').value !== null) throw new Error('Product clear failed');
call('save', first);
const service = Secret.Service.get_sync(Secret.ServiceFlags.OPEN_SESSION, null);
const collection = Secret.Collection.for_alias_sync(service, 'login', Secret.CollectionFlags.NONE, null);
const [count] = service.lock_sync([collection], null);
if (count !== 1) throw new Error('Collection lock failed');
for (const action of ['load', 'save', 'clear']) {
    let denied = false;
    try { call(action, action === 'save' ? second : undefined); }
    catch (error) { denied = error.message === 'KEYRING_LOCKED'; }
    if (!denied) throw new Error(`Locked ${action} did not fail closed`);
}
print(JSON.stringify({ stored: true, roundTrip: true, deleted: true, lockedReadDenied: true,
    productAdapter: true, refreshOverwrite: true, environmentSeparated: true, lockedWriteDenied: true }));
