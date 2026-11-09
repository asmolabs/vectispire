import { inject, signal } from '@angular/core';
import { IntegrationsApi } from '../core/api/integrations.api';
import type { Integration } from '../core/api.models';
import type { I18nService } from '../core/i18n/i18n.service';
import { keyFor } from '../core/i18n/literal-keys';

/**
 * The integrations' registry as the screens read it (decision 0040): which outside systems the platform
 * governor has switched on, and the words for them.
 *
 * **One list of keys, one of families.** A key is `<family>.<name>` and the server writes it; the forms
 * build the key of the value they offer — `forge.` and the forge kind, `siem.` and the protocol in lower
 * case — rather than keeping a second spelling of the seventeen. A key this client does not know is shown
 * as sent, never dropped: Bitbucket arrives later (D8), disabled, and must appear on the screen the day the
 * server lists it.
 */

/** The families in the order the screen groups them, each with its heading and what switching it off suspends. */
export const INTEGRATION_FAMILIES = ['forge', 'siem', 'ai', 'notification', 'tracker'] as const;
export type IntegrationFamily = (typeof INTEGRATION_FAMILIES)[number];

export const INTEGRATION_FAMILY_KEYS = {
    forge: 'integrations.families.forge',
    siem: 'integrations.families.siem',
    ai: 'integrations.families.ai',
    notification: 'integrations.families.notification',
    tracker: 'integrations.families.tracker'
} as const satisfies Record<IntegrationFamily, string>;

/**
 * What switching an integration of the family off does, said in the confirmation before it is done: what
 * stops, what is kept. Decision 0040 §2 and §3 — suspended, never deleted — family by family.
 */
export const INTEGRATION_SUSPENDS_KEYS = {
    forge: 'integrations.suspends.forge',
    siem: 'integrations.suspends.siem',
    ai: 'integrations.suspends.ai',
    notification: 'integrations.suspends.notification',
    tracker: 'integrations.suspends.tracker'
} as const satisfies Record<IntegrationFamily, string>;

/**
 * The seventeen integrations of this version by name, family by family; a key missing here is shown as the
 * server spells it. Nested rather than keyed `'ai.ollama'`: a literal of that shape reads to the i18n check
 * as a key of the bundle's `ai` namespace, and would be counted as one.
 */
export const INTEGRATION_NAME_KEYS = {
    forge: { github: 'integrations.names.forge_github', gitlab: 'integrations.names.forge_gitlab' },
    siem: {
        webhook: 'integrations.names.siem_webhook',
        syslog_udp: 'integrations.names.siem_syslog_udp',
        syslog_tcp: 'integrations.names.siem_syslog_tcp',
        syslog_tls: 'integrations.names.siem_syslog_tls'
    },
    ai: { ollama: 'integrations.names.ai_ollama', openai: 'integrations.names.ai_openai' },
    notification: {
        webhook: 'integrations.names.notification_webhook',
        teams: 'integrations.names.notification_teams',
        slack: 'integrations.names.notification_slack',
        discord: 'integrations.names.notification_discord',
        mail: 'integrations.names.notification_mail'
    },
    tracker: {
        gitlab: 'integrations.names.tracker_gitlab',
        github: 'integrations.names.tracker_github',
        jira: 'integrations.names.tracker_jira',
        servicenow: 'integrations.names.tracker_servicenow'
    }
} as const satisfies Record<IntegrationFamily, Record<string, string>>;

/** Every name the map holds, for the spec that checks both bundles spell them. */
export const INTEGRATION_NAME_KEY_LIST: readonly string[] = Object.values(INTEGRATION_NAME_KEYS).flatMap(
    (names): string[] => Object.values(names)
);

export function integrationLabel(i18n: Pick<I18nService, 't'>, key: string | null | undefined): string {
    if (!key) return '—';
    const dot = key.indexOf('.');
    const names: Readonly<Record<string, string>> | undefined =
        dot > 0 && Object.hasOwn(INTEGRATION_NAME_KEYS, key.slice(0, dot))
            ? INTEGRATION_NAME_KEYS[key.slice(0, dot) as IntegrationFamily]
            : undefined;
    const name = names ? keyFor(names, key.slice(dot + 1)) : undefined;
    return name ? i18n.t(name) : key;
}

export function familyLabel(i18n: Pick<I18nService, 't'>, family: string): string {
    const key = keyFor(INTEGRATION_FAMILY_KEYS, family);
    return key ? i18n.t(key) : family;
}

/**
 * The registry's key of a value a form offers, `<family>.<name>` in lower case. Not a translation key — the
 * family is a parameter, so the i18n check, which refuses a key built from a literal prefix, does not
 * mistake `ai.` for the bundle's `ai` namespace.
 */
function integrationKey(family: IntegrationFamily, name: string): string {
    return `${family}.${name.toLowerCase()}`;
}

/** The key of a forge connection's kind, a SIEM protocol, an AI provider or a tracker, as the registry spells it. */
export const forgeIntegration = (kind: string): string => integrationKey('forge', kind);
export const siemIntegration = (protocol: string): string => integrationKey('siem', protocol);
export const aiIntegration = (provider: string): string => integrationKey('ai', provider);
export const trackerIntegration = (provider: string): string => integrationKey('tracker', provider);

/**
 * The notification settings that configure a channel — its URL, or its recipients — and the channel's key.
 * Teams' own switch is not among them: it is on by default with no URL, and would read as a configured
 * channel that is not.
 */
export const NOTIFICATION_SETTING_INTEGRATIONS: Readonly<Record<string, string>> = {
    notification_webhook_url: 'notification.webhook',
    notification_teams_url: 'notification.teams',
    notification_slack_url: 'notification.slack',
    notification_discord_url: 'notification.discord',
    notification_mail_to: 'notification.mail'
};

/** `GET /api/v1/notifications/channels` names a channel by its event type, `scan_delta_teams`. */
export const NOTIFICATION_CHANNEL_INTEGRATIONS: Readonly<Record<string, string>> = {
    scan_delta: 'notification.webhook',
    scan_delta_teams: 'notification.teams',
    scan_delta_slack: 'notification.slack',
    scan_delta_discord: 'notification.discord',
    scan_delta_mail: 'notification.mail'
};

/** The route of *Administration → Integrations*, which every suspended configuration links to. */
export const INTEGRATIONS_ROUTE = '/integrations';

/**
 * The registry as one form reads it. Built with `new` in a field initializer — `inject` needs the
 * component's injection context — and loaded by the form when it loads its own state, so it is never a
 * cache kept across screens: a switch made on the integrations screen shows on the next form opened.
 *
 * **An unread registry offers everything.** A failed read, or an answer that is not a list, leaves
 * `entries` null and every choice offered: the server refuses a disabled one with 409
 * `integration-disabled` all the same (decision 0040 §1), and a form that offered nothing because a read
 * failed would read as an installation with every integration switched off.
 */
export class IntegrationRegistry {
    private readonly api = inject(IntegrationsApi);

    readonly entries = signal<Integration[] | null>(null);

    load(): void {
        this.api.listIntegrations().subscribe({
            next: (entries) => this.entries.set(Array.isArray(entries) ? entries : null),
            error: () => this.entries.set(null)
        });
    }

    /** Switched off, by what the registry answered. A key it does not list is not: the server decides. */
    isDisabled(key: string | null | undefined): boolean {
        if (!key) return false;
        return this.entries()?.find((entry) => entry.key === key)?.enabled === false;
    }

    /**
     * Whether a form offers this integration: enabled, or the one already configured — kept in the list so
     * the form does not show a choice it was never given, and marked suspended beside it.
     */
    offers(key: string, current?: string | null): boolean {
        return !this.isDisabled(key) || key === current;
    }
}
