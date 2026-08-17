import { createHash } from 'node:crypto';

/**
 * An issue's identity across scans.
 *
 * **The most critical data contract in the system.** Two successive scans produce raw
 * findings with no identity; it is this fingerprint that decides whether what the
 * scanner just saw is *the same issue as yesterday* — with its history, its occurrence
 * count and above all its triage decision — or a new one.
 *
 * A one-byte divergence from the Python implementation fails nowhere: it simply means
 * no fingerprint computed here matches the ones already in the database. On the first
 * scan after the switchover, the whole existing backlog would be resolved ("these
 * issues are no longer seen") and recreated from scratch, **triage lost** — every
 * argued `not_affected` decision, every VEX justification, every review date. With no
 * error, no log entry, and a dashboard that looks normal.
 *
 * Hence `test/vectors/issue-fingerprint.json`, generated from the Python code.
 *
 * ## What goes in, and what does not
 *
 * `SHA-256("repo:{id}|{type}|{identifier}|{purl or name}|{path}")`
 *
 * **Deliberately excluded**:
 *
 * - **the package version.** An outdated dependency that stays outdated across three
 *   version bumps is one issue with a history, not three separate issues — and a triage
 *   decision would evaporate on every patch release;
 * - **whether the dependency is direct or transitive**: a dependency that goes from
 *   direct to transitive is the same issue seen differently;
 * - **the line number**: a secret that moves down three lines is the same secret.
 *
 * The `purl` takes precedence over the package name because it is the ecosystem-qualified
 * identity; falling back to the name keeps findings that have no purl — secrets, IaC,
 * licenses — fingerprintable.
 *
 * ## A weakness reproduced on purpose
 *
 * The separator is a vertical bar, not the audit chain's NUL byte. A file path containing
 * `|` can therefore, in principle, imitate a field boundary and produce a collision. **Do
 * not fix this here.** Changing the separator would change every fingerprint already
 * stored, which is exactly the scenario described above. If it is ever to be fixed, it
 * will be by a migration that recomputes the fingerprints in the database within the same
 * transaction.
 */
export interface FingerprintInput {
    /** Mutually exclusive with `containerId`: an issue belongs to one target. */
    repoId: number | null;
    containerId: number | null;
    findingType: string | null;
    identifier: string | null;
    purl: string | null;
    packageName: string | null;
    filePath: string | null;
}

export function buildFingerprint(input: FingerprintInput): string {
    // `repo_id is not None` in Python: presence is what decides, not truthiness. A
    // `repoId` of 0 names repository 0, not the absence of a repository — hence
    // `!= null` rather than a truthiness test, which would file that case as a container.
    const target = input.repoId != null ? `repo:${input.repoId}` : `container:${input.containerId}`;

    const parts = [
        target,
        input.findingType || '',
        input.identifier || '',
        // `purl or package_name or ""`: the empty string and null behave alike, as in
        // Python. An empty purl therefore falls back to the package name.
        input.purl || input.packageName || '',
        input.filePath || ''
    ];

    return createHash('sha256').update(parts.join('|'), 'utf8').digest('hex');
}
