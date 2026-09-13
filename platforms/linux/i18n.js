import Gio from 'gi://Gio';
import GLib from 'gi://GLib';

// Native package resources, independent of Angular. German source, English
// fallback. Release validation requires all 26 catalogs before packaging.
export function translator(directory = `${GLib.path_get_dirname(GLib.filename_from_uri(import.meta.url)[0])}/locales`) {
    const read = language => {
        const [, bytes] = Gio.File.new_for_path(`${directory}/${language}.json`).load_contents(null);
        return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
    };
    const fallback = read('en');
    let catalog = fallback;
    for (const name of GLib.get_language_names()) {
        const language = name.split(/[_.@-]/)[0];
        if (!/^[a-z]{2}$/.test(language)) continue;
        try { catalog = read(language); break; } catch { /* English is explicit fallback. */ }
    }
    return (key, values = {}) => {
        let text = catalog[key] ?? fallback[key] ?? fallback.actionFailed;
        for (const [name, value] of Object.entries(values)) text = text.replaceAll(`{${name}}`, String(value));
        return text;
    };
}
