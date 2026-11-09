import { provideHttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from '../core/i18n/i18n.service';
import { missingFromBundles } from '../core/testing/bundles';
import { useEnglish } from '../core/testing/english';
import english from '../../../public/i18n/en.json';
import { ENCRYPTION_STATE_KEYS, encryptionBadge, GIT_TOKEN_HINT_KEYS, SSH_KEY_HINT_KEYS } from './encryption-state';

/** The encryption badge both secret tables show, through literal keys (decision 0019). */
describe('the encryption badge', () => {
    beforeEach(() => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({ providers: [provideHttpClient()] });
    });

    it('spells every state with keys both bundles hold', () => {
        const maps = [ENCRYPTION_STATE_KEYS, SSH_KEY_HINT_KEYS, GIT_TOKEN_HINT_KEYS];
        expect(missingFromBundles(maps.flatMap((map) => Object.values(map)))).toEqual([]);
    });

    it('says each state in words, with the hint of the page it is on', () => {
        useEnglish();
        const i18n = TestBed.inject(I18nService);

        expect(encryptionBadge(i18n, 'current', SSH_KEY_HINT_KEYS)).toEqual({
            label: english.ssh_keys.encryption_status.current,
            severity: 'success',
            hint: english.ssh_keys.encryption_status.current_hint
        });
        expect(encryptionBadge(i18n, 'previous_key', GIT_TOKEN_HINT_KEYS)).toEqual({
            label: english.ssh_keys.encryption_status.rotate,
            severity: 'warn',
            hint: english.git_tokens.encryption_status.previous_key_hint
        });
    });

    it('reads a state it does not know as unreadable, never as healthy and never as a key', () => {
        useEnglish();
        const i18n = TestBed.inject(I18nService);

        // `constructor` is "in" every object: an `in` test would have taken it for a known state.
        for (const state of ['sealed_by_hsm', 'constructor']) {
            expect(encryptionBadge(i18n, state, SSH_KEY_HINT_KEYS)).toEqual({
                label: english.ssh_keys.encryption_status.unreadable,
                severity: 'danger',
                hint: english.ssh_keys.encryption_status.unreadable_hint
            });
        }
    });
});
