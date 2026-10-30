import { version as RELEASE } from '../../../../package.json';

/** How a repository authenticates its clone. At most one credential: the server refuses both. */
export type CredentialKind = 'none' | 'ssh' | 'https';

/**
 * The transport a URL names, as far as the credential choice cares.
 *
 * `unknown` is an empty or unfinished URL: every choice stays offered rather than hiding one the
 * operator is about to need. The scp form `git@host:path` is SSH although it carries no scheme.
 */
export function urlTransport(url: string): 'https' | 'ssh' | 'unknown' {
    const value = url.trim().toLowerCase();
    if (value.startsWith('https://')) return 'https';
    if (value.startsWith('ssh://') || value.startsWith('git://') || /^[^\s/:@]+@[^\s/:]+:/.test(value)) return 'ssh';
    return 'unknown';
}

/** The host of an https:// URL, lowercased, or null while it does not parse. */
export function httpsHost(url: string): string | null {
    if (urlTransport(url) !== 'https') return null;
    try {
        return new URL(url.trim()).hostname.toLowerCase() || null;
    } catch {
        return null;
    }
}

/**
 * Whether an https:// URL carries a secret in its user-info (`https://user:token@host/…`).
 *
 * Only a hint: the server is what refuses a new one. It exists so that the operator learns the
 * alternative — a managed token — before the refusal, not only from it.
 */
export function urlCarriesSecret(url: string): boolean {
    if (urlTransport(url) !== 'https') return false;
    try {
        return new URL(url.trim()).password !== '';
    } catch {
        return false;
    }
}

/**
 * The CLI the snippets download: the `vectispire-cli.sh` asset of the release this interface is,
 * run only at the digest that release shipped.
 *
 * <p>The snippets used to fetch `scripts/vectispire-cli.sh` from the raw URL at the tag and run it
 * unchecked — a file nobody had signed, whose bytes were whatever the forge served that day. The
 * release now publishes the script with a Sigstore bundle, as it does the gate script, and every
 * snippet compares its SHA-256 with the one below before executing it. The interface and the asset
 * come from the same tag, so this is the digest of `scripts/vectispire-cli.sh` in this tree;
 * `ci/check-cli-pin.sh` fails the push and the release when the two drift apart.
 */
export const CLI_SCRIPT_URL = `https://github.com/asmolabs/vectispire/releases/download/v${RELEASE}/vectispire-cli.sh`;
export const CLI_SCRIPT_SHA256 = '0397ab0375e60e4a9793e85a3aa95e2a61f1dec906df2522ab8011b29cce359a';
/** The identity the release workflow signs with — per tag, naming the workflow file, never the repository alone. */
export const CLI_SIGNER = `https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v${RELEASE}`;

/** The RFC 9457 `type` of a duplicate target — the cause the routes publish, never the English sentence. */
export const TARGET_ALREADY_REGISTERED = 'urn:vectispire:problem:target-already-registered';
