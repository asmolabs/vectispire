/**
 * What a ticket says, and who it is for.
 *
 * SARIF closes the loop towards the developer: a finding appears on the merge request that
 * introduced it. This closes it towards the organization — an issue nobody will fix this
 * afternoon has to exist where people plan their work, not only in a dashboard nothing
 * obliges them to open.
 *
 * **Driven by the gate policy, not by a second threshold.** "Open a ticket for what would
 * fail a build" is a rule an operator already knows how to reason about, and it leaves
 * **one single place** where "serious enough to act on" is defined. Inventing a
 * `ticket_min_severity` would create two vocabularies that would diverge, and the first bug
 * report would be "why did it open a ticket for that without failing the build".
 *
 * Pure functions: the formatting is tested with no ticket tracker.
 */

/** What the formatting reads from an issue. Narrower than the entity, by design. */
export interface TicketableIssue {
    id: number;
    type: string;
    identifier: string | null;
    severity: string | null;
    packageName: string | null;
    packageVersion: string | null;
    fixVersions: string | null;
    fixState: string | null;
    isDirectDependency: boolean | null;
    filePath: string | null;
    line: number | null;
    isKev: boolean;
    epssScore: number | null;
    link: string | null;
    description: string | null;
    fingerprint: string;
}

export const PROVIDER_NONE = 'none';
export const PROVIDER_GITLAB = 'gitlab';
export const PROVIDER_JIRA = 'jira';
export const VALID_PROVIDERS = [PROVIDER_NONE, PROVIDER_GITLAB, PROVIDER_JIRA] as const;

export const DEFAULT_JIRA_ISSUE_TYPE = 'Bug';
export const DEFAULT_LABELS = 'zanshin,security';

/**
 * Cap per sweep.
 *
 * A first pass over a mature backlog would otherwise open several hundred tickets at once
 * — a rate-limiting problem, and above all a social one.
 */
export const MAX_TICKETS_PER_SWEEP = 20;

/** Short enough for a ticket list, precise enough to be searchable. */
export function buildTitle(issue: TicketableIssue, targetName: string): string {
    const subject = issue.identifier || issue.type;
    const packageName = issue.packageName ? ` — ${issue.packageName}` : '';
    const severity = (issue.severity ?? 'unknown').toUpperCase();
    return `[Zanshin][${severity}] ${subject}${packageName} (${targetName})`;
}

/**
 * The ticket body, written for whoever picks it up with no context.
 *
 * **The fixed version comes first among the details**, because it is what makes the
 * difference between a ticket closed today and a ticket dragged across three iterations.
 */
export function buildBody(issue: TicketableIssue, targetName: string): string {
    const lines = [
        `Detected by Zanshin on **${targetName}**.`,
        '',
        `- Type: ${issue.type}`,
        `- Identifier: ${issue.identifier || '—'}`,
        `- Severity: ${issue.severity ?? 'unknown'}`
    ];

    if (issue.fixVersions) lines.push(`- **Fixed in: ${issue.fixVersions}**`);
    else if (issue.fixState === 'not-fixed' || issue.fixState === 'wont-fix') lines.push('- No published fix to date');

    if (issue.packageName) {
        lines.push(`- Component: ${issue.packageName}${issue.packageVersion ? ` ${issue.packageVersion}` : ''}`);
    }
    if (issue.isDirectDependency !== null) {
        lines.push(`- Dependency: ${issue.isDirectDependency ? 'direct (declared by the project)' : 'transitive'}`);
    }
    if (issue.filePath) lines.push(`- Location: ${issue.filePath}${issue.line ? `:${issue.line}` : ''}`);
    if (issue.isKev) lines.push('- ⚠️ Known active exploitation (CISA KEV catalog)');
    if (issue.epssScore !== null) lines.push(`- Exploitation probability (EPSS): ${(issue.epssScore * 100).toFixed(1)}%`);
    if (issue.link) lines.push(`- Reference: ${issue.link}`);

    // Truncated: a CVE description can run to several kilobytes, and a ticket you have to
    // scroll through to find the conclusion does not get read.
    if (issue.description) lines.push('', issue.description.slice(0, 1000));

    lines.push(
        '',
        `Zanshin issue #${issue.id} — fingerprint \`${issue.fingerprint}\`.`,
        'This ticket was opened because this issue would fail a build under the gate policy in force for this ' +
            'target.'
    );
    return lines.join('\n');
}

/** The labels, read from the setting. An empty list is a valid state. */
export function parseLabels(raw: string): string[] {
    return raw
        .split(',')
        .map((label) => label.trim())
        .filter((label) => label !== '');
}

/** The provider, normalized. Anything outside the vocabulary counts as "none". */
export function parseProvider(raw: string): string {
    const value = (raw ?? '').trim().toLowerCase();
    return (VALID_PROVIDERS as readonly string[]).includes(value) ? value : PROVIDER_NONE;
}
