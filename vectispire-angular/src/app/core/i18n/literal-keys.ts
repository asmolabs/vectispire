/**
 * The key a value is spelt by, or `undefined` for a value this client does not know.
 *
 * **The keys stay literal, in the caller's map** (decision 0019). A key built from the value —
 * `` `soa.divergence.${value}` `` — is one `check-i18n-keys.mjs` cannot read: the day the server
 * adds a value, or a bundle loses an entry, the reader is shown the key path itself. Written as a
 * `Record<Union, 'a.b'>`, every key is a literal the check counts, and a union member without an
 * entry fails the compiler.
 *
 * **An unknown value builds no key.** The server can be newer than this client, and several fields
 * are typed `string` by the document; the lookup answers `undefined` rather than indexing blindly,
 * so the caller shows the value as sent — never a path, never an empty cell. `Object.hasOwn` and not
 * `in`: `'constructor' in keys` is true.
 */
export function keyFor<V extends string>(
    keys: Readonly<Record<V, string>>,
    value: string | null | undefined
): string | undefined {
    return value != null && Object.hasOwn(keys, value) ? keys[value as V] : undefined;
}
