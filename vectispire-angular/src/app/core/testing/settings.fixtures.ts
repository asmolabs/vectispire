import type {
    SettingDefinition,
    SiemConfig,
    ThreatIntelSyncStatus,
    TicketCaState,
    TicketTokenState
} from '../api.models';
import type { SettingsApi } from '../api/settings.api';
import { asSchema, type AnswerOf } from './contract';

/**
 * The tracker token's state as `GET /api/v1/settings/ticket-token` sends it: what a case does not
 * set is unknown, which the server writes as null — and with no tracker chosen, neither a state nor an
 * integration key (decision 0040 §3). The specs sent `{ configured, expirySource }`
 * alone, and four fields the screen reads arrived `undefined`, a value no server sends.
 */
export function ticketTokenState(changes: Partial<TicketTokenState> = {}): TicketTokenState {
    return {
        configured: false,
        expiresAt: null,
        expirySource: 'unknown',
        refusedStatus: null,
        refusedSince: null,
        checkedAt: null,
        state: null,
        integration: null,
        ...changes
    };
}

/**
 * Whether a write-only secret is stored — the webhook signing key, the tracker's inbound secret, the
 * model provider's key. The three routes answer the same `{ configured }` map, which the document
 * declares as a bare map; the client's declaration is the type.
 */
export function secretState(configured: boolean): AnswerOf<SettingsApi['webhookSecretState']> {
    return { configured };
}

/** No CA pinned for the tracker: `GET /api/v1/settings/ticket-ca` before anyone pastes one. */
export const NO_TICKET_CA: TicketCaState = asSchema('TicketCaState', { pinned: false, subject: null, notAfter: null });

/**
 * The SIEM export never configured — the very answer `SiemController.getConfig` builds when nothing is
 * stored. Specs about other cards answered this read with `{}`, a configuration with no `enabled` flag.
 */
export const SIEM_UNCONFIGURED: SiemConfig = asSchema('SiemConfigResponse', {
    enabled: false,
    protocol: 'WEBHOOK',
    endpoint: null,
    hasAuthHeader: false,
    minSeverity: 'HIGH',
    tlsCaPem: null,
    tlsCaSubject: null,
    tlsCaNotAfter: null,
    updatedAt: null
});

/** Threat intelligence on an install that never fetched a feed: both feeds `NEVER_SYNCED`, nothing counted. */
export const THREAT_INTEL_NEVER_SYNCED: ThreatIntelSyncStatus = asSchema('ThreatIntelSyncStatus', {
    status: 'NEVER_SYNCED',
    lastSyncedAt: null,
    totalCves: 0,
    totalKev: 0,
    backlogUpdatedCount: 0,
    kevCatalogVersion: null,
    kevReleasedAt: null,
    lastAttemptAt: null,
    lastError: null,
    epss: {
        status: 'NEVER_SYNCED',
        lastSyncedAt: null,
        modelVersion: null,
        scoreDate: null,
        totalScored: 0,
        lastAttemptAt: null,
        lastError: null,
        backlogUpdatedCount: 0,
        inProgress: false
    }
});

/**
 * What each read the settings page's cards make answers on an install where none of them was set up.
 *
 * <p>The suites about one card answered every other card's read with `{}` — "their answers do not
 * matter here" — which no route sends: a SIEM configuration without `enabled`, a tracker token without
 * `expirySource`, which the cards then rendered in a state that does not exist. A read this map does not
 * know is refused by {@link unconfigured} rather than answered with a guess, so a new card's read gets
 * its typed answer here.
 */
const UNCONFIGURED: Record<string, object> = {
    '/api/v1/settings/ticket-token': ticketTokenState(),
    '/api/v1/settings/webhook-secret': secretState(false),
    '/api/v1/settings/ticket-webhook-secret': secretState(false),
    '/api/v1/settings/ai-openai-key': secretState(false),
    '/api/v1/settings/ticket-ca': NO_TICKET_CA,
    '/api/v1/siem/config': SIEM_UNCONFIGURED,
    '/api/v1/threat-intel/status': THREAT_INTEL_NEVER_SYNCED
};

export function unconfigured(url: string): object {
    const answer = UNCONFIGURED[url];
    if (!answer) throw new Error(`No unconfigured answer for ${url}: add its typed fixture to settings.fixtures.ts`);
    return answer;
}

/** What `PUT /api/v1/settings` answers: how many values it wrote, the map the client reads it as. */
export function settingsUpdated(updated: number): AnswerOf<SettingsApi['updateSettings']> {
    return { updated };
}

/**
 * One entry of the settings catalogue as `GET /api/v1/settings` lists it. Every entry carries its
 * section, label and help — the server reads them off the `Setting` constant — and the catalogue specs
 * listed entries without `help`, or with nothing but a key and a value.
 */
export function settingDefinition(key: string, changes: Partial<SettingDefinition> = {}): SettingDefinition {
    return asSchema('SettingView', {
        key,
        type: 'text',
        section: 'General',
        label: key,
        help: '',
        default: '',
        value: '',
        configured: false,
        governor_only: false,
        administrator_only: false,
        ...changes
    });
}
