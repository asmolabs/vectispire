import type { EncryptionState } from '../core/api.models';
import type { I18nService } from '../core/i18n/i18n.service';
import { keyFor } from '../core/i18n/literal-keys';

/**
 * Where a stored secret stands with respect to the encryption keys, as the deploy-key and the
 * Git-token tables show it — one badge, two pages, so written once.
 *
 * **Literal keys** (decision 0019): both pages built `ssh_keys.encryption_status.${state}`, which the
 * i18n check could not read. The label is shared; the hint is each page's, since a key and a token
 * are rotated differently.
 */
export const ENCRYPTION_STATE_KEYS = {
    current: 'ssh_keys.encryption_status.current',
    previous_key: 'ssh_keys.encryption_status.rotate',
    unreadable: 'ssh_keys.encryption_status.unreadable'
} as const satisfies Record<EncryptionState, string>;

export const SSH_KEY_HINT_KEYS = {
    current: 'ssh_keys.encryption_status.current_hint',
    previous_key: 'ssh_keys.encryption_status.previous_key_hint',
    unreadable: 'ssh_keys.encryption_status.unreadable_hint'
} as const satisfies Record<EncryptionState, string>;

export const GIT_TOKEN_HINT_KEYS = {
    current: 'git_tokens.encryption_status.current_hint',
    previous_key: 'git_tokens.encryption_status.previous_key_hint',
    unreadable: 'git_tokens.encryption_status.unreadable_hint'
} as const satisfies Record<EncryptionState, string>;

const SEVERITIES = {
    current: 'success',
    previous_key: 'warn',
    unreadable: 'danger'
} as const satisfies Record<EncryptionState, 'success' | 'warn' | 'danger'>;

export interface EncryptionBadge {
    label: string;
    severity: 'success' | 'warn' | 'danger';
    hint: string;
}

/**
 * The badge for a state. **Anything unknown reads as unreadable**: a healthy badge on a value nobody
 * recognises would be the one wrong answer that hides a failing clone.
 */
export function encryptionBadge(
    i18n: I18nService,
    state: string,
    hints: Readonly<Record<EncryptionState, string>>
): EncryptionBadge {
    const known: EncryptionState = keyFor(SEVERITIES, state) ? (state as EncryptionState) : 'unreadable';
    return {
        label: i18n.t(ENCRYPTION_STATE_KEYS[known]),
        severity: SEVERITIES[known],
        hint: i18n.t(hints[known])
    };
}
