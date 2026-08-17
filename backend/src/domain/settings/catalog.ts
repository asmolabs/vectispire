import { DEFAULT_WARN_DAYS } from '../eol/matching';
import {
    DEFAULT_MIN_SEVERITY,
    SETTING_ALLOW_PRIVATE_URL,
    SETTING_MIN_SEVERITY,
    SETTING_NOTIFY_ON_KEV,
    SETTING_WEBHOOK_URL
} from '../notifications/payload';
import { DEFAULT_KEEP_PER_TARGET, DEFAULT_MAX_AGE_DAYS, SETTING_RETENTION_KEEP_PER_TARGET, SETTING_RETENTION_MAX_AGE_DAYS } from '../retention/policy';
import {
    SETTING_ENRICHMENT_ENABLED,
    SETTING_EOL_ENABLED,
    SETTING_EOL_WARN_DAYS,
    SETTING_LICENSE_BLOCKLIST,
    SETTING_SAST_ENABLED,
    SETTING_TICKET_ALLOW_PRIVATE_URL,
    SETTING_TICKET_BASE_URL,
    SETTING_TICKET_ISSUE_TYPE,
    SETTING_TICKET_LABELS,
    SETTING_TICKET_PROJECT,
    SETTING_TICKET_PROVIDER,
    SETTING_TICKET_USER
} from './keys';
import { DEFAULT_JIRA_ISSUE_TYPE, DEFAULT_LABELS, PROVIDER_NONE } from '../tickets/ticket';
import { DEFAULT_AI_REVIEW_MODEL, DEFAULT_OLLAMA_URL, SETTING_AI_REVIEW_ALLOW_REMOTE, SETTING_AI_REVIEW_ENABLED, SETTING_AI_REVIEW_MODEL, SETTING_AI_REVIEW_OLLAMA_URL } from '../ai-review/prompt';

/**
 * The settings the application exposes, and **only those a service actually reads**.
 *
 * That is the rule governing this file: a form that accepts a value and does nothing with
 * it is worse than a form that does not offer it. The operator believes they have
 * configured something, the behaviour does not change — and they conclude the tool is
 * broken, or worse, never notice.
 *
 * A setting therefore enters this catalog **only once its reader has been ported**. The
 * keys of services still missing are not here, and that is deliberate, not an oversight.
 *
 * The catalog also carries the type and the label, so the screen can render generically:
 * adding a setting must not require touching the UI.
 */

export type SettingType = 'boolean' | 'integer' | 'text' | 'severity';

export interface SettingDefinition {
    key: string;
    type: SettingType;
    /**
     * Its **value** is a secret, even though its key is not.
     *
     * A Slack, Teams or Discord webhook URL is not configuration: it is a bearer
     * capability. Whoever knows it can post in the channel — the very channel where the
     * team awaits Zanshin's alerts, hence the one where a forged message carries most
     * weight. Reading it requires no write permission, which made it reachable by any
     * account.
     *
     * The screen then receives `configured` without the value, as for the ticket token.
     */
    sensitive?: boolean;
    /** The group the screen files the setting under. */
    section: string;
    label: string;
    /** What this setting changes, and above all what it does not. */
    help: string;
    default: string;
}

export const SETTINGS_CATALOG: SettingDefinition[] = [
    {
        key: SETTING_ENRICHMENT_ENABLED,
        type: 'boolean',
        section: 'Enrichment',
        label: 'Query EPSS and the KEV catalog',
        help:
            'Only CVE identifiers leave the machine — never code, never a SBOM. Switched off, the "actively exploited" ' +
            'counter stays at zero, which then means "we did not ask" and not "there are none".',
        default: 'true'
    },
    {
        key: SETTING_EOL_ENABLED,
        type: 'boolean',
        section: 'End of life',
        label: 'Detect platforms past their support window',
        help:
            'A class of risk with no CVE attached: an expired environment will receive no fix for the next ' +
            'vulnerability, whatever it turns out to be. Switching this off leaves existing findings **open** rather ' +
            'than resolving them — "we stopped looking" is not "it is fixed".',
        default: 'true'
    },
    {
        key: SETTING_EOL_WARN_DAYS,
        type: 'integer',
        section: 'End of life',
        label: 'Warning window (days)',
        help:
            'A cycle whose end falls inside this window is reported at medium severity. Beyond it, nothing: everything ' +
            'reaches end of life one day, and flagging a version supported for another three years would teach people ' +
            'to filter this type out.',
        default: String(DEFAULT_WARN_DAYS)
    },
    {
        key: SETTING_SAST_ENABLED,
        type: 'boolean',
        section: 'Source code analysis',
        label: 'Analyze the code with Semgrep',
        help:
            'Off by default, and that is an operational decision: the first scan of an ordinary repository takes its ' +
            'backlog from a few dozen vulnerabilities to a few thousand findings. Quality findings never fail a build ' +
            'and never trigger a notification. Switching this off leaves existing findings open rather than resolving ' +
            'them.',
        default: 'false'
    },
    {
        key: SETTING_RETENTION_KEEP_PER_TARGET,
        type: 'integer',
        section: 'Retention',
        label: 'Raw payloads kept per target',
        help:
            'The SBOMs and scanner output of each target\'s last N scans are kept whatever their age. Zero means "no ' +
            'limit on this axis". Findings, issues and summaries are never purged.',
        default: String(DEFAULT_KEEP_PER_TARGET)
    },
    {
        key: SETTING_RETENTION_MAX_AGE_DAYS,
        type: 'integer',
        section: 'Retention',
        label: 'Maximum age of raw payloads (days)',
        help:
            'The two rules combine: a payload is purged only if it is **both** outside the window above and older ' +
            'than this age. Both at zero disables purging.',
        default: String(DEFAULT_MAX_AGE_DAYS)
    },
    {
        key: SETTING_WEBHOOK_URL,
        type: 'text',
        sensitive: true,
        section: 'Notifications',
        label: 'Webhook URL',
        help:
            'A generic JSON POST, which reaches Slack, Teams, Discord, Mattermost or a script. Empty disables ' +
            'notifications. The URL is validated on every send: a private destination is refused unless explicitly ' +
            'allowed.',
        default: ''
    },
    {
        key: SETTING_MIN_SEVERITY,
        type: 'severity',
        section: 'Notifications',
        label: 'Minimum severity notified',
        help: 'Nothing new above this threshold, no message. One notification per scan teaches people to filter the channel.',
        default: DEFAULT_MIN_SEVERITY
    },
    {
        key: SETTING_NOTIFY_ON_KEV,
        type: 'boolean',
        section: 'Notifications',
        label: 'Notify any actively exploited vulnerability',
        help: 'Whatever its severity: the threshold alone would discard a "medium" being exploited today.',
        default: 'true'
    },
    {
        key: SETTING_ALLOW_PRIVATE_URL,
        type: 'boolean',
        section: 'Notifications',
        label: 'Allow a private webhook URL',
        help:
            'For an internal bus. Off by default: a webhook URL resolving to a private address is far more often a ' +
            'server-side request forgery attempt than an intranet endpoint. The instance metadata endpoint stays ' +
            'refused in every case.',
        default: 'false'
    },
    {
        key: SETTING_LICENSE_BLOCKLIST,
        type: 'text',
        section: 'Licenses',
        label: 'Forbidden licenses',
        help:
            'Comma-separated SPDX identifiers, for example "GPL-3.0-only,AGPL-3.0-only". Empty, nothing is reported: ' +
            'which licenses are forbidden is an organizational decision, not a technical one. Read from the SBOM ' +
            'already produced — no extra tool is needed.',
        default: ''
    },
    {
        key: SETTING_TICKET_PROVIDER,
        type: 'text',
        section: 'Ticket tracker',
        label: 'Provider',
        help:
            '"gitlab", "jira", or "none" to disable. A ticket is opened for any issue that would fail a build under ' +
            'the gate policy — there is no second threshold, so that one single place defines "serious enough to act ' +
            'on".',
        default: PROVIDER_NONE
    },
    {
        key: SETTING_TICKET_BASE_URL,
        type: 'text',
        // Not a secret in the webhook's sense, but a map of the internal network that an
        // unprivileged account has no reason to read.
        sensitive: true,
        section: 'Ticket tracker',
        label: 'Tracker URL',
        help:
            'An internal destination is accepted here, unlike the webhook: a self-hosted GitLab or Jira commonly ' +
            'lives on an internal network. The instance metadata endpoint stays refused.',
        default: ''
    },
    {
        key: SETTING_TICKET_PROJECT,
        type: 'text',
        section: 'Ticket tracker',
        label: 'Project',
        help: 'The GitLab path ("group/project") or the Jira project key ("SEC").',
        default: ''
    },
    {
        key: SETTING_TICKET_USER,
        type: 'text',
        section: 'Ticket tracker',
        label: 'Jira account',
        help: 'The account address, required by Jira alongside the token for basic authentication. GitLab does not use it.',
        default: ''
    },
    {
        key: SETTING_TICKET_ISSUE_TYPE,
        type: 'text',
        section: 'Ticket tracker',
        label: 'Jira issue type',
        help: 'The type name in the target project. GitLab does not use it.',
        default: DEFAULT_JIRA_ISSUE_TYPE
    },
    {
        key: SETTING_TICKET_LABELS,
        type: 'text',
        section: 'Ticket tracker',
        label: 'Labels',
        help: 'Comma-separated, applied to every ticket opened.',
        default: DEFAULT_LABELS
    },
    {
        key: SETTING_TICKET_ALLOW_PRIVATE_URL,
        type: 'boolean',
        section: 'Ticket tracker',
        label: 'Allow an internal URL',
        help: 'On by default. Clear it for a deployment that only uses a hosted tracker.',
        default: 'true'
    },
    {
        key: SETTING_AI_REVIEW_ENABLED,
        type: 'boolean',
        section: 'Model review',
        label: 'Review the code with a local model',
        help:
            'A light complement to the scanners, not a SAST engine: a single prompt, with no guaranteed ' +
            'reproducibility. Its findings are tagged as coming from a model and excluded from the gate by default — ' +
            'that is the structural mitigation against prompt injection, the analyzed code being an input controlled ' +
            'by a third party.',
        default: 'false'
    },
    {
        key: SETTING_AI_REVIEW_OLLAMA_URL,
        type: 'text',
        sensitive: true,
        section: 'Model review',
        label: 'Ollama service URL',
        help:
            '**This endpoint receives the scanned repository\'s source code.** The risk is therefore not that it ' +
            'points inward, but outward: a well-formed public URL is exactly what an exfiltration channel looks like. ' +
            'A public destination is refused unless explicitly acknowledged below.',
        default: DEFAULT_OLLAMA_URL
    },
    {
        key: SETTING_AI_REVIEW_MODEL,
        type: 'text',
        section: 'Model review',
        label: 'Model',
        help: 'The name as Ollama knows it. It does not have to be installed already to be saved here.',
        default: DEFAULT_AI_REVIEW_MODEL
    },
    {
        key: SETTING_AI_REVIEW_ALLOW_REMOTE,
        type: 'boolean',
        section: 'Model review',
        label: 'Allow a remote Ollama',
        help:
            'Off by default, and it is the most consequential setting on this screen: turning it on allows source ' +
            'code to be sent to a public host.',
        default: 'false'
    }
];

/** The catalog's defaults, so the screen knows what an absent key is worth. */
export function catalogDefaults(): Record<string, string> {
    return Object.fromEntries(SETTINGS_CATALOG.map((definition) => [definition.key, definition.default]));
}

/** A key's definition, or `undefined` if it is not exposed. */
export function definitionFor(key: string): SettingDefinition | undefined {
    return SETTINGS_CATALOG.find((definition) => definition.key === key);
}

/**
 * An acceptable value for this setting, or a message saying why it is not.
 *
 * Validated at the point of entry rather than on read: an unreadable integer would
 * silently read as its default, and the operator would never learn their value was
 * ignored.
 */
export function validate(definition: SettingDefinition, value: string): string | null {
    switch (definition.type) {
        case 'boolean':
            return value === 'true' || value === 'false' ? null : 'Expected value: "true" or "false".';
        case 'integer': {
            const parsed = Number(value);
            return value.trim() !== '' && Number.isInteger(parsed) && parsed >= 0 ? null : 'Expected value: a positive integer or zero.';
        }
        case 'severity':
            return ['critical', 'high', 'medium', 'low'].includes(value)
                ? null
                : 'Expected value: critical, high, medium or low.';
        default:
            return null;
    }
}
