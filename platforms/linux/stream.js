/** GIO owns immutable bytes for the full async write, including partial writes. */
import GLib from 'gi://GLib';

export function writeOwnedBytes(stream, bytes, cancellable = null) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > 16384) return Promise.reject(new Error('IO_WRITE_INVALID'));
    const owned = GLib.Bytes.new(bytes), length = bytes.length;
    return new Promise((resolve, reject) => {
        let offset = 0;
        const next = () => {
            try {
                // GJS 1.80 (Ubuntu 24.04) does not expose new_from_bytes as
                // the same static factory as newer GJS. GBytes.new copies
                // the bounded remainder and owns it until GIO completes.
                const remaining = offset === 0 ? owned : GLib.Bytes.new(owned.get_data().slice(offset));
                stream.write_bytes_async(remaining, GLib.PRIORITY_DEFAULT, cancellable, (source, result) => {
                    try {
                        const count = source.write_bytes_finish(result);
                        if (!Number.isSafeInteger(count) || count <= 0 || count > length - offset) throw new Error('IO_WRITE_FAILED');
                        offset += count;
                        if (offset === length) resolve(); else next();
                    } catch (error) { reject(error); }
                });
            } catch (error) { reject(error); }
        };
        next();
    });
}
