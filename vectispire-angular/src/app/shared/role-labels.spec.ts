import { provideHttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from '../core/i18n/i18n.service';
import { missingFromBundles } from '../core/testing/bundles';
import { useEnglish } from '../core/testing/english';
import english from '../../../public/i18n/en.json';
import { ROLE_KEYS, roleLabel } from './role-labels';
import { TRIAGE_STATUS_KEYS, triageStatusLabel } from './triage-status';

/** Two server vocabularies the document types as plain strings, spelt with literal keys (decision 0019). */
describe('roles and triage statuses in words', () => {
    let i18n: I18nService;

    beforeEach(() => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({ providers: [provideHttpClient()] });
        useEnglish();
        i18n = TestBed.inject(I18nService);
    });

    it('spells every role and every triage status with a key both bundles hold', () => {
        expect(missingFromBundles([...Object.values(ROLE_KEYS), ...Object.values(TRIAGE_STATUS_KEYS)])).toEqual([]);
    });

    it('names a role as the accounts screen does, and one it does not know as the server sent it', () => {
        expect(roleLabel(i18n, 'SECURITY_CHAMPION')).toBe(english.roles.security_champion);
        expect(roleLabel(i18n, 'AUDITOR')).toBe(english.roles.auditor);
        expect(roleLabel(i18n, 'RISK_OWNER')).toBe('RISK_OWNER');
        // The lower-case spelling is the bundle's, not the server's: it is not a role.
        expect(roleLabel(i18n, 'admin')).toBe('admin');
    });

    it('names a triage status, the older ones included, and one it does not know as sent', () => {
        expect(triageStatusLabel(i18n, 'pending_approval')).toBe(english.issues.triage_status.pending_approval);
        expect(triageStatusLabel(i18n, 'false_positive')).toBe(english.issues.triage_status.false_positive);
        expect(triageStatusLabel(i18n, 'deferred')).toBe('deferred');
    });
});
