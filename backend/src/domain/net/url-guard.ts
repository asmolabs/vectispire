import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

/**
 * Validation of the URLs Zanshin will send a request to.
 *
 * Three settings become server-side requests: the notification webhook, the Ollama
 * server, and the local scan API. Each is a string set by an administrator and then
 * called by the server — that is a server-side request forgery primitive, whose classic
 * target is the metadata endpoint (`169.254.169.254`), which hands the instance's
 * credentials to whoever asks.
 *
 * "Only an administrator can set it" is a mitigation, not an answer: a Zanshin
 * administrator is not necessarily someone cleared to read the host's IAM credentials,
 * and that is exactly the pivot an attacker who has phished an account is looking for.
 *
 * **The problem with private addresses.** Blocking them outright would break two of the
 * three settings by construction — Ollama and the scan side-car are *meant* to be on
 * loopback or the internal network. The rule is therefore per use:
 *
 * - `allowPrivate: false` (the webhook): public destinations only.
 * - `allowPrivate: true` (the side-car): private and loopback accepted, but link-local —
 *   the metadata range — never. Nothing legitimate lives in 169.254.0.0/16, and that is
 *   precisely the address the attack wants.
 * - `requirePrivate: true` (Ollama): the mirror image, and the one that is easy to miss.
 *   Ollama receives the scanned repository's **source code**: the risk is not that the URL
 *   points inward, it is that it points **outward**. A well-formed public URL is exactly
 *   what an exfiltration channel looks like, and no anti-SSRF check would flag it.
 *
 * DNS is resolved here so that a name pointing at a blocked address is refused too. That
 * leaves a rebinding window between this check and the request itself, which this cannot
 * close: it would take pinning the resolved address in the HTTP client. Recorded as a
 * known limit rather than hidden.
 */

const ALLOWED_SCHEMES = ['https:', 'http:'];

/** The URL is not a destination Zanshin will call. */
export class UnsafeUrlError extends Error {}

export interface UrlGuardOptions {
    allowPrivate: boolean;
    requirePrivate?: boolean;
    label?: string;
    /** Injectable: DNS resolution must not be a dependency of the tests. */
    resolve?: (hostname: string) => Promise<string[]>;
}

/** Returns the cleaned URL, or throws `UnsafeUrlError`. */
export async function validateOutboundUrl(url: string, options: UrlGuardOptions): Promise<string> {
    const { allowPrivate, requirePrivate = false, label = 'URL', resolve = resolveHostname } = options;
    const candidate = (url ?? '').trim();
    if (!candidate) throw new UnsafeUrlError(`${label}: empty value.`);

    let parsed: URL;
    try {
        parsed = new URL(candidate);
    } catch {
        throw new UnsafeUrlError(`${label}: unreadable URL.`);
    }

    if (!ALLOWED_SCHEMES.includes(parsed.protocol.toLowerCase())) {
        throw new UnsafeUrlError(`${label}: scheme "${parsed.protocol || '(none)'}" is not allowed (expected: https, http).`);
    }
    // `URL` strips the brackets from a literal IPv6 address; `hostname` is therefore
    // directly comparable.
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
    if (!hostname) throw new UnsafeUrlError(`${label}: missing host.`);

    const addresses = await resolve(hostname);

    if (requirePrivate && addresses.length === 0) {
        // Failing open is defensible for "is this private?": the request would fail
        // anyway. It is not defensible for "this **must** be private" — an unresolvable
        // name proves nothing, and this check is what separates the scanned source code
        // from an external host.
        throw new UnsafeUrlError(
            `${label}: the host could not be resolved, so it cannot be verified as internal — ` + 'and this endpoint receives source code.'
        );
    }

    for (const address of addresses) {
        if (isLinkLocal(address)) {
            throw new UnsafeUrlError(`${label}: the host resolves to a link-local address (${address}), used by instance metadata services.`);
        }
        const global = isGlobal(address);
        if (!allowPrivate && !global) {
            throw new UnsafeUrlError(`${label}: the host resolves to a private or local address (${address}). A public destination is expected here.`);
        }
        if (requirePrivate && global) {
            throw new UnsafeUrlError(
                `${label}: the host resolves to a public address (${address}). A local or internal destination is expected ` +
                    'here — this endpoint receives source code.'
            );
        }
    }
    return candidate;
}

/** Non-throwing variant: the reason, or `null` when the URL is acceptable. */
export async function unsafeReason(url: string, options: UrlGuardOptions): Promise<string | null> {
    try {
        await validateOutboundUrl(url, options);
        return null;
    } catch (error) {
        if (error instanceof UnsafeUrlError) return error.message;
        throw error;
    }
}

/**
 * Every address a name resolves to.
 *
 * **Every one, not the first**: a name can return a public address and a private one, and
 * checking only one would let the other through.
 */
async function resolveHostname(hostname: string): Promise<string[]> {
    if (isIP(hostname)) return [hostname];

    try {
        const results = await lookup(hostname, { all: true });
        return results.map((entry) => entry.address);
    } catch {
        // Refusing on a resolution failure would make the settings screen unusable at the
        // slightest DNS hiccup, and the request itself would fail anyway.
        return [];
    }
}

/**
 * An address's bytes, or `null` if it is not one.
 *
 * **The decision is taken on the bytes, never on the text.** The previous version compared
 * string prefixes, and `new URL()` normalizes an IPv6 address before we read it:
 * `::ffff:127.0.0.1` comes back in the hexadecimal form `::ffff:7f00:1`, which the regular
 * expression matching did not see. Loopback, the private networks and the metadata
 * endpoint all passed the webhook's guard written that way.
 */
function addressBytes(address: string): Buffer | null {
    const family = isIP(address);
    if (family === 4) return ipv4Bytes(address);
    if (family === 6) return ipv6Bytes(address);
    return null;
}

function ipv4Bytes(address: string): Buffer | null {
    const octets = address.split('.').map(Number);
    if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return null;
    return Buffer.from(octets);
}

function ipv6Bytes(address: string): Buffer | null {
    let text = address.toLowerCase();

    // A last group written as four dotted numbers — `::ffff:127.0.0.1` — becomes two
    // hexadecimal groups, so that only one form has to be parsed afterwards.
    const dotted = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text);
    if (dotted) {
        const quad = ipv4Bytes(dotted[1]);
        if (!quad) return null;
        text = text.slice(0, dotted.index) + quad.readUInt16BE(0).toString(16) + ':' + quad.readUInt16BE(2).toString(16);
    }

    const halves = text.split('::');
    if (halves.length > 2) return null;
    const head = halves[0] ? halves[0].split(':') : [];
    const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    const missing = 8 - head.length - tail.length;
    // Without `::`, all eight groups must be written; with it, at least one is missing.
    if (halves.length === 1 ? missing !== 0 : missing < 0) return null;

    const groups = [...head, ...(halves.length === 2 ? Array<string>(missing).fill('0') : []), ...tail];
    const bytes = Buffer.alloc(16);
    for (const [index, group] of groups.entries()) {
        const value = Number.parseInt(group, 16);
        if (!Number.isInteger(value) || value < 0 || value > 0xffff) return null;
        bytes.writeUInt16BE(value, index * 2);
    }
    return bytes;
}

/** The first twelve bytes of an IPv6 that wraps an IPv4. */
const V4_MAPPED = Buffer.from('00000000000000000000ffff', 'hex');
/** `64:ff9b::/96`, the NAT64 translation prefix: the last four bytes are the IPv4. */
const NAT64 = Buffer.from('0064ff9b0000000000000000', 'hex');

/**
 * The IPv4 an IPv6 carries, if there is one.
 *
 * Three wrappings, and all three are needed: `::ffff:a.b.c.d` (the common one),
 * `64:ff9b::a.b.c.d` (NAT64, which genuinely reaches the IPv4 wherever the translation
 * exists) and `::a.b.c.d` (obsolete, still accepted by the stacks). Each is one more
 * spelling for the same destination, and missing just one is enough to reopen the bypass.
 */
function embeddedV4(bytes: Buffer): Buffer | null {
    const prefix = bytes.subarray(0, 12);
    if (prefix.equals(V4_MAPPED) || prefix.equals(NAT64)) return bytes.subarray(12);
    // `::` and `::1` are not wrapped IPv4s: they are the unspecified address and
    // loopback, handled as such below.
    if (prefix.every((octet) => octet === 0) && bytes.readUInt32BE(12) > 1) return bytes.subarray(12);
    return null;
}

/** The instance metadata range, in IPv4 as in IPv6. */
function isLinkLocal(address: string): boolean {
    const bytes = addressBytes(address);
    if (!bytes) return false;

    if (bytes.length === 16) {
        const embedded = embeddedV4(bytes);
        if (embedded) return isLinkLocalV4(embedded);
        // `fe80::/10` covers fe80 through febf.
        return bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80;
    }
    return isLinkLocalV4(bytes);
}

function isLinkLocalV4(bytes: Buffer): boolean {
    return bytes[0] === 169 && bytes[1] === 254;
}

/**
 * Is the address routable on the public Internet?
 *
 * Written by hand for want of a `ipaddress.is_global` equivalent in Node: every range
 * omitted here is an internal destination a public webhook could reach.
 *
 * An unreadable address is declared non-public, which makes it **refused** on the webhook
 * side and **accepted** on the Ollama side. The asymmetry is accepted: the values examined
 * come either from a literal already validated by `isIP` or from a DNS resolution, so this
 * case has no real path — and of the two, the webhook is the one exposed outward.
 */
function isGlobal(address: string): boolean {
    const bytes = addressBytes(address);
    if (!bytes) return false;
    return bytes.length === 16 ? isGlobalV6(bytes) : isGlobalV4(bytes);
}

function isGlobalV4(bytes: Buffer): boolean {
    const [a, b] = bytes;

    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT, 100.64.0.0/10
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0) return false; // 192.0.0.0/24 and 192.0.2.0/24
    if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
    if (a === 198 && b === 51) return false;
    if (a === 203 && b === 0) return false;
    if (a >= 224) return false; // multicast and reserved

    return true;
}

function isGlobalV6(bytes: Buffer): boolean {
    // The decision belongs to the IPv4 part as soon as there is one.
    const embedded = embeddedV4(bytes);
    if (embedded) return isGlobalV4(embedded);

    if (bytes.every((octet) => octet === 0)) return false; // `::`, unspecified
    if (bytes.subarray(0, 15).every((octet) => octet === 0) && bytes[15] === 1) return false; // `::1`
    if ((bytes[0] & 0xfe) === 0xfc) return false; // fc00::/7, unique local
    if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return false; // fe80::/10, link-local
    if (bytes[0] === 0xff) return false; // multicast

    return true;
}
