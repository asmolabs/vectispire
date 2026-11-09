import { provideHttpClient, withXhr } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from '../core/i18n/i18n.service';
import { missingFromBundles } from '../core/testing/bundles';
import { useEnglish, useFrench } from '../core/testing/english';
import type { GateViolation } from '../core/api.models';
import { OBSERVATION_SENTENCE_KEYS, RULE_SENTENCE_KEYS, gateReason } from './gate-reason';

/**
 * Why the gate refused, in the reader's language. The French screens printed the server's English
 * sentence: the one line that says why a build stopped was the one line not translated.
 */
describe('a gate violation in words', () => {
    let i18n: I18nService;

    const violation = (rule: string, severity: string | null, reason: string) =>
        ({ rule, severity, reason }) as Pick<GateViolation, 'rule' | 'severity' | 'reason'>;

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr())] });
        i18n = TestBed.inject(I18nService);
    });

    it('has a sentence in both bundles for every rule and every observation', () => {
        expect(
            missingFromBundles([...Object.values(RULE_SENTENCE_KEYS), ...Object.values(OBSERVATION_SENTENCE_KEYS)])
        ).toEqual([]);
    });

    it('speaks French from the rule and its values, not from the English sentence', () => {
        useFrench();

        expect(gateReason(i18n, violation('kev', 'high', 'actively exploited vulnerability (CISA KEV catalog)'))).toBe(
            'Vulnérabilité activement exploitée (catalogue KEV de la CISA).'
        );
        expect(gateReason(i18n, violation('severity', 'high', 'severity high >= threshold high'))).toBe(
            'Sévérité Élevée, au seuil de la politique ou au-delà.'
        );
        expect(gateReason(i18n, violation('coverage', null, 'no installed rule covers go'))).toContain(
            'Aucune règle installée'
        );
    });

    it('names which examination is missing when the screen knows the observation', () => {
        useFrench();
        const observation = violation('observation', null, 'the last scan of this target failed');

        expect(gateReason(i18n, observation, 'last_scan_failed')).toContain('La dernière analyse');
        expect(gateReason(i18n, observation, 'never_scanned')).toContain("n'a jamais été examinée");
        expect(gateReason(i18n, observation)).toContain("Aucune analyse de cette cible n'est allée à son terme");
    });

    it("shows a rule this client does not know in the server's words", () => {
        // Enum values are open (decision 0043 §1): a newer server's rule must not read as one of these.
        useFrench();

        expect(gateReason(i18n, violation('licence', null, 'licence GPL-3.0 is blocked'))).toBe(
            'licence GPL-3.0 is blocked'
        );
        expect(gateReason(i18n, violation('severity', null, 'severity ? >= threshold high'))).toBe(
            'severity ? >= threshold high'
        );
    });

    it('reads English when the interface is in English', () => {
        useEnglish();

        expect(gateReason(i18n, violation('kev', 'critical', 'x'))).toBe(
            'Actively exploited vulnerability (CISA KEV catalog).'
        );
    });
});
