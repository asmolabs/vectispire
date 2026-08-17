/**
 * Validation of a repository URL.
 *
 * **This is not input validation, it is a security control.** The URL lands in a `git clone`
 * run by an agent: an uncontrolled value there is arbitrary code execution on the machine
 * doing the scanning, not a badly filled field. It is therefore checked at entry *and*
 * before every clone, because rows predating this validation exist in the database.
 *
 * Two forms accepted and nothing else: a URL with an explicit scheme among
 * `https`/`ssh`/`git`, or the short SCP form `git@host:path` everyone copies from GitHub.
 */

const ALLOWED_SCHEMES = ['https:', 'ssh:', 'git:'];
const SCP_FORM = /^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._\/-]+$/;

/** `null` if the URL is acceptable, otherwise the message to show. */
export function validateRepositoryUrl(url: string): string | null {
    if (!url) return 'The repository URL is required.';
    if (SCP_FORM.test(url)) return null;

    let parsed: URL;
    try {
        parsed = new URL(url);
    } catch {
        return 'Invalid URL. Expected "https://…", "ssh://…" or "git@host:path".';
    }

    if (!ALLOWED_SCHEMES.includes(parsed.protocol)) {
        // `file://` would clone a local path on the agent; `ext::` makes git itself run an
        // arbitrary command. An allowlist is the only safe shape here.
        return `Scheme "${parsed.protocol.replace(':', '')}" is not allowed. Expected https, ssh or git.`;
    }
    if (!parsed.hostname) return 'The URL must name a host.';
    return null;
}
