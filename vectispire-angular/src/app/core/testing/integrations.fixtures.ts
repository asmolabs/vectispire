import type { HttpTestingController } from '@angular/common/http/testing';
import type { Integration } from '../api.models';
import { asSchema, asSchemaList } from './contract';

/** The seventeen integrations this version seeds (V94), every one enabled, as `GET /api/v1/integrations` lists them. */
export const INTEGRATION_KEYS = [
    'forge.github',
    'forge.gitlab',
    'siem.webhook',
    'siem.syslog_udp',
    'siem.syslog_tcp',
    'siem.syslog_tls',
    'ai.ollama',
    'ai.openai',
    'notification.webhook',
    'notification.teams',
    'notification.slack',
    'notification.discord',
    'notification.mail',
    'tracker.gitlab',
    'tracker.github',
    'tracker.jira',
    'tracker.servicenow'
] as const;

/** One entry, never switched unless `changes` says otherwise; checked against the published schema. */
export function integration(key: string, changes: Partial<Integration> = {}): Integration {
    const dot = key.indexOf('.');
    return asSchema('IntegrationView', {
        key,
        family: key.slice(0, dot),
        name: key.slice(dot + 1),
        enabled: true,
        updatedAt: null,
        updatedBy: null,
        ...changes
    });
}

/** The registry with the named keys switched off — by `governor` on 28/10/2026 — and every other one on. */
export function registry(disabled: readonly string[] = []): Integration[] {
    return asSchemaList(
        'IntegrationView',
        INTEGRATION_KEYS.map((key) =>
            disabled.includes(key)
                ? integration(key, { enabled: false, updatedAt: '2026-10-28T09:15:00Z', updatedBy: 'governor' })
                : integration(key)
        )
    );
}

/** Answers every pending read of the registry, as a form issues it when it loads. */
export function flushRegistry(http: HttpTestingController, disabled: readonly string[] = []): void {
    for (const call of http.match({ method: 'GET', url: '/api/v1/integrations' })) call.flush(registry(disabled));
}
