import { Pipe, PipeTransform } from '@angular/core';
import type { GitTokenSummary } from '../../core/api.models';
import { CredentialKind, httpsHost, urlCarriesSecret, urlTransport } from './repository-model';

/**
 * What the repository dialog derives from the URL being typed, as pure pipes over `form.url`.
 *
 * **Pipes, not `computed`**: `form` is a plain object bound with `ngModel` and rewritten by the specs,
 * so a computed over it would never recompute. A pure pipe given the URL — a string, compared by value
 * — and whatever else it reads as arguments is called again when one of them changes, and never on a
 * pass where none did, which the methods the template called before were on every pass.
 */

/** The words of each credential kind, from the dialog's language-following computed. */
export type CredentialLabels = Readonly<Record<CredentialKind, string>>;

/**
 * The credential kinds the URL allows. **Read from the URL rather than offered in full and refused on
 * save**: an SSH key is useless to an https:// clone and a token to an SSH one, and the server refuses
 * both combinations.
 */
export function credentialKindsFor(url: string, labels: CredentialLabels): { label: string; value: CredentialKind }[] {
    const transport = urlTransport(url);
    return [
        { label: labels.none, value: 'none' as const },
        ...(transport !== 'https' ? [{ label: labels.ssh, value: 'ssh' as const }] : []),
        ...(transport !== 'ssh' ? [{ label: labels.https, value: 'https' as const }] : [])
    ];
}

/**
 * The tokens bound to the URL's host — the only ones the server would accept here (decision 0022).
 * While the host does not parse yet, all of them, so the choice is not empty mid-typing.
 */
export function httpsTokenOptionsFor(
    url: string,
    tokens: readonly GitTokenSummary[]
): { label: string; value: string }[] {
    const host = httpsHost(url);
    return tokens
        .filter((token) => host === null || token.host.toLowerCase() === host)
        .map((token) => ({ label: `${token.name} (${token.host})`, value: token.id }));
}

/** `form.url | credentialKinds: credentialLabels()` */
@Pipe({ name: 'credentialKinds' })
export class CredentialKindsPipe implements PipeTransform {
    transform(url: string, labels: CredentialLabels): { label: string; value: CredentialKind }[] {
        return credentialKindsFor(url, labels);
    }
}

/** `form.url | httpsTokenOptions: page.gitTokens()` */
@Pipe({ name: 'httpsTokenOptions' })
export class HttpsTokenOptionsPipe implements PipeTransform {
    transform(url: string, tokens: readonly GitTokenSummary[]): { label: string; value: string }[] {
        return httpsTokenOptionsFor(url, tokens);
    }
}

/** `form.url | httpsHost` — the host the URL names, for the "no token for this host" hint. */
@Pipe({ name: 'httpsHost' })
export class HttpsHostPipe implements PipeTransform {
    transform(url: string): string | null {
        return httpsHost(url);
    }
}

/** `form.url | urlCarriesSecret` — a credential typed into the URL itself, which the dialog warns of. */
@Pipe({ name: 'urlCarriesSecret' })
export class UrlCarriesSecretPipe implements PipeTransform {
    transform(url: string): boolean {
        return urlCarriesSecret(url);
    }
}
