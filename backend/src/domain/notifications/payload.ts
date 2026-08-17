import { isAtLeast } from '../gate/policy-gate';
import { TYPE_QUALITY } from '../issues/types';

/**
 * What a scan changed, formatted for a webhook.
 *
 * **A generic webhook, not a Slack integration.** An HTTP POST with a documented JSON body
 * reaches Slack, Teams (through a flow), Discord, Mattermost, an internal bus or a
 * three-line script. A vendor-specific payload would buy prettier formatting in one place
 * at the cost of every other — hence a `text` field first, so chat receivers display
 * something readable anyway.
 *
 * **Only on change, and only above a threshold.** One notification per scan teaches people
 * to filter the channel.
 *
 * These functions are pure and the message is a **snapshot**: it says what the scan found,
 * not what the issues look like once somebody has triaged half of them.
 */

export const SETTING_WEBHOOK_URL = 'notification_webhook_url';
export const SETTING_MIN_SEVERITY = 'notification_min_severity';
export const SETTING_NOTIFY_ON_KEV = 'notification_always_on_kev';
/** Escape hatch for an internal bus. Off by default: a webhook URL resolving to a private
 *  address is far more often an SSRF attempt than an intranet endpoint. */
export const SETTING_ALLOW_PRIVATE_URL = 'notification_allow_private_url';

export const DEFAULT_MIN_SEVERITY = 'high';

/**
 * How many issues are named in the payload. The rest are counted: a webhook body with four
 * hundred entries is a denial of service against its reader, and the API is there for the
 * full list.
 */
export const MAX_DETAILED_ISSUES = 10;

/** What an issue contributes to the message. Deliberately narrower than the entity. */
export interface NotifiableIssue {
    id: number;
    identifier: string | null;
    type: string;
    /** Nullable as on the entity: a finding can arrive with no severity, and `isAtLeast`
     *  treats absence as the lowest value. */
    severity: string | null;
    isKev: boolean;
    epssScore: number | null;
    packageName: string | null;
    filePath: string | null;
    fixVersions: string | null;
    link: string | null;
}

export interface SelectionOptions {
    minSeverity: string;
    alwaysOnKev: boolean;
}

/**
 * Which of the new or reappeared issues deserve a message.
 *
 * An actively exploited vulnerability passes **whatever its severity** when `alwaysOnKev`
 * is set — that is the whole point of the KEV signal, and severity alone would discard a
 * "medium" being exploited today.
 *
 * **Quality findings never qualify**, whatever their severity. Semgrep maps its `ERROR`
 * level to `high`, which clears the default threshold: the first scan of a repository with
 * the SAST step enabled would therefore fire a webhook announcing several hundred issues.
 * Excluding the type is the honest fix; lowering their severity to silence them would be a
 * lie about severity, and would also change their place in the backlog's ordering.
 */
export function selectNotable(issues: NotifiableIssue[], options: SelectionOptions): NotifiableIssue[] {
    return issues.filter((issue) => {
        if (issue.type === TYPE_QUALITY) return false;
        if (options.alwaysOnKev && issue.isKev) return true;
        return isAtLeast(issue.severity, options.minSeverity);
    });
}

export interface DeltaInput {
    targetName: string;
    scanId: number;
    newIssues: NotifiableIssue[];
    reopenedIssues: NotifiableIssue[];
    resolvedCount: number;
    minSeverity: string;
}

/** The webhook body. `text` first, for receivers that read only that field. */
export function buildPayload(input: DeltaInput): Record<string, unknown> {
    const { targetName, scanId, newIssues, reopenedIssues, resolvedCount, minSeverity } = input;

    const parts: string[] = [];
    if (newIssues.length > 0) parts.push(`${newIssues.length} new issue(s)`);
    if (reopenedIssues.length > 0) parts.push(`${reopenedIssues.length} reappeared`);

    const all = [...newIssues, ...reopenedIssues];
    const kevCount = all.filter((issue) => issue.isKev).length;
    if (kevCount > 0) parts.push(`${kevCount} actively exploited`);

    let text = `Zanshin — ${targetName}: ${parts.join(', ')}`;
    if (resolvedCount > 0) text += ` (${resolvedCount} resolved)`;

    return {
        text,
        target: targetName,
        scan_id: scanId,
        new_count: newIssues.length,
        reopened_count: reopenedIssues.length,
        resolved_count: resolvedCount,
        kev_count: kevCount,
        min_severity: minSeverity,
        issues: all.slice(0, MAX_DETAILED_ISSUES).map(issuePayload),
        truncated: Math.max(0, all.length - MAX_DETAILED_ISSUES)
    };
}

function issuePayload(issue: NotifiableIssue): Record<string, unknown> {
    return {
        id: issue.id,
        identifier: issue.identifier,
        type: issue.type,
        severity: issue.severity,
        is_kev: issue.isKev,
        epss_score: issue.epssScore,
        package: issue.packageName,
        file_path: issue.filePath,
        // The most useful field for whoever reads the alert.
        fix_versions: issue.fixVersions,
        link: issue.link
    };
}
