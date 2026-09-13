/** OS-keyring adapter. Invoked in a bounded private-pipe child, never with secrets in argv. */
import Secret from 'gi://Secret?version=1';
import GioUnix from 'gi://GioUnix?version=2.0';
import GLib from 'gi://GLib';
import System from 'system';

const schema = new Secret.Schema('com.fin3000.Printer.OAuth', Secret.SchemaFlags.NONE,
    { environment: Secret.SchemaAttributeType.STRING, client: Secret.SchemaAttributeType.STRING });

export function secretOperation(request) {
    if (!request || !['production', 'qa'].includes(request.environment) ||
        !['load', 'save', 'clear'].includes(request.action) ||
        Object.keys(request).some(key => !['action', 'environment', 'value'].includes(key)) ||
        (request.action === 'save' && (typeof request.value !== 'string' || new TextEncoder().encode(request.value).length > 16384)) ||
        (request.action !== 'save' && request.value !== undefined)) throw new Error('SECRET_REQUEST_INVALID');
    const service = Secret.Service.get_sync(Secret.ServiceFlags.OPEN_SESSION, null);
    const collection = Secret.Collection.for_alias_sync(service, 'login', Secret.CollectionFlags.NONE, null);
    // No session collection, implicit unlock dialog, or plaintext fallback.
    if (!collection) throw new Error('SECRET_COLLECTION_MISSING');
    if (collection.get_locked()) throw new Error('KEYRING_LOCKED');
    const attributes = { environment: request.environment, client: `fin3000-system-print${request.environment === 'qa' ? '-qa' : ''}` };
    const items = collection.search_sync(schema, attributes, Secret.SearchFlags.NONE, null);
    if (items.length > 1) throw new Error('SECRET_STATE_AMBIGUOUS');
    const item = items[0];
    if (item?.get_locked()) throw new Error('KEYRING_LOCKED');
    if (request.action === 'load') {
        if (!item) return { value: null };
        item.load_secret_sync(null);
        const value = item.get_secret()?.get_text();
        if (typeof value !== 'string' || new TextEncoder().encode(value).length > 16384) throw new Error('SECRET_STATE_INVALID');
        return { value };
    }
    if (request.action === 'clear') {
        if (item && !item.delete_sync(null)) throw new Error('SECRET_STORE_UNAVAILABLE');
        return { ok: true };
    }
    const value = Secret.Value.new(request.value, -1, 'text/plain; charset=utf-8');
    if (item) {
        if (!item.set_secret_sync(value, null)) throw new Error('SECRET_STORE_UNAVAILABLE');
    } else {
        Secret.Item.create_sync(collection, schema, attributes,
            request.environment === 'qa' ? 'Fin3000-Drucker (isolierter Test)' : 'Fin3000-Drucker', value, Secret.ItemCreateFlags.REPLACE, null);
    }
    return { ok: true };
}

if (ARGV[0] === '--stdio') {
    if (GLib.getenv('FIN3000_CORE_GUARD') !== '1') System.exit(70);
    GLib.unsetenv('FIN3000_CORE_GUARD');
    try {
        if (ARGV.length !== 1) throw new Error('SECRET_REQUEST_INVALID');
        const input = new GioUnix.InputStream({ fd: 0, close_fd: false });
        const parts = []; let length = 0;
        while (length <= 32768) {
            const chunk = input.read_bytes(Math.min(4096, 32769 - length), null).get_data();
            if (!chunk.length) break;
            parts.push(chunk); length += chunk.length;
        }
        if (length > 32768) throw new Error('SECRET_REQUEST_INVALID');
        const bytes = new Uint8Array(length); let offset = 0;
        for (const part of parts) { bytes.set(part, offset); offset += part.length; }
        const request = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
        print(JSON.stringify(secretOperation(request)));
    } catch (error) {
        const code = ['SECRET_REQUEST_INVALID', 'SECRET_COLLECTION_MISSING', 'KEYRING_LOCKED', 'SECRET_STATE_AMBIGUOUS', 'SECRET_STATE_INVALID'].includes(error.message)
            ? error.message : 'SECRET_STORE_UNAVAILABLE';
        print(JSON.stringify({ error: code }));
    }
}
