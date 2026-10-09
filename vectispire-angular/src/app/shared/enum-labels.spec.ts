import { provideHttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from '../core/i18n/i18n.service';
import { missingFromBundles } from '../core/testing/bundles';
import { useEnglish, useFrench } from '../core/testing/english';
import {
    COMPLIANCE_STATUS_KEYS,
    FRAMEWORK_DESCRIPTION_KEYS,
    FRAMEWORK_KEYS,
    GATE_STATUS_KEYS,
    complianceStatusLabel,
    frameworkLabel,
    gateStatusLabel
} from './compliance-labels';
import { ISSUE_STATE_KEYS, SCAN_STATUS_KEYS, issueStateLabel, scanStatusLabel } from './scan-status';
import { SEVERITY_KEYS, severityLabel } from './severity';
import { TARGET_KIND_KEYS, targetKindLabel } from './target-kind';

/**
 * Severities, verdicts, frameworks and statuses in words, spelt with literal keys (decision 0019).
 *
 * The French screenshots showed `critical`, `PARTIAL`, `NON_COMPLIANT` and `ISO_27001` as the server
 * spells them. Each map is checked against both bundles, each label in both languages, and a value the
 * client does not know is shown as sent — never a key path, never an empty cell.
 */
describe('server vocabularies in words', () => {
    let i18n: I18nService;

    beforeEach(() => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({ providers: [provideHttpClient()] });
        i18n = TestBed.inject(I18nService);
    });

    it('spells every value with a key both bundles hold', () => {
        const maps = [
            SEVERITY_KEYS,
            COMPLIANCE_STATUS_KEYS,
            FRAMEWORK_KEYS,
            FRAMEWORK_DESCRIPTION_KEYS,
            GATE_STATUS_KEYS,
            SCAN_STATUS_KEYS,
            ISSUE_STATE_KEYS,
            TARGET_KIND_KEYS
        ];
        expect(missingFromBundles(maps.flatMap((map) => Object.values(map)))).toEqual([]);
    });

    it('names a severity in English and in French, whatever case the server wrote it in', () => {
        useEnglish();
        expect(severityLabel(i18n, 'critical')).toBe('Critical');
        expect(severityLabel(i18n, 'HIGH')).toBe('High');
        useFrench();
        expect(severityLabel(i18n, 'critical')).toBe('Critique');
        expect(severityLabel(i18n, 'high')).toBe('Élevée');
        expect(severityLabel(i18n, 'MEDIUM')).toBe('Moyenne');
        expect(severityLabel(i18n, 'negligible')).toBe('Négligeable');
    });

    it('shows a severity it does not know as sent, and none as a dash', () => {
        useFrench();
        expect(severityLabel(i18n, 'catastrophic')).toBe('catastrophic');
        expect(severityLabel(i18n, 'constructor')).toBe('constructor');
        expect(severityLabel(i18n, null)).toBe('—');
    });

    it('names a verdict, and a framework by its standard rather than its constant', () => {
        useEnglish();
        expect(complianceStatusLabel(i18n, 'NON_COMPLIANT')).toBe('Non-compliant');
        expect(frameworkLabel(i18n, 'ISO_27001')).toBe('ISO/IEC 27001:2022');
        expect(frameworkLabel(i18n, 'NIS_2')).toBe('NIS 2 Directive');
        useFrench();
        expect(complianceStatusLabel(i18n, 'PARTIAL')).toBe('Partiel');
        expect(complianceStatusLabel(i18n, 'NON_COMPLIANT')).toBe('Non conforme');
        expect(complianceStatusLabel(i18n, 'COMPLIANT')).toBe('Conforme');
        expect(complianceStatusLabel(i18n, 'NO_DATA')).toBe('Aucune donnée');
        expect(frameworkLabel(i18n, 'NIS_2')).toBe('Directive NIS 2');
        expect(frameworkLabel(i18n, 'SOC_2')).toBe('SOC 2');
    });

    it('shows a framework or a verdict it does not know as sent', () => {
        useFrench();
        // A declaration's framework is a plain string, and the OWASP Top 10 is one of them.
        expect(frameworkLabel(i18n, 'OWASP_2021')).toBe('OWASP_2021');
        expect(complianceStatusLabel(i18n, 'WAIVED')).toBe('WAIVED');
    });

    it('names a gate, a scan status and an issue state in both languages', () => {
        useEnglish();
        expect(gateStatusLabel(i18n, 'PASSED')).toBe('Passed');
        expect(scanStatusLabel(i18n, 'pending')).toBe('Queued');
        expect(issueStateLabel(i18n, 'resolved')).toBe('Resolved');
        useFrench();
        expect(gateStatusLabel(i18n, 'FAILED')).toBe('Échouée');
        expect(gateStatusLabel(i18n, 'NEVER_SCANNED')).toBe('Jamais analysé');
        expect(scanStatusLabel(i18n, 'completed')).toBe('Terminé');
        expect(issueStateLabel(i18n, 'open')).toBe('Ouvert');
        expect(scanStatusLabel(i18n, 'paused')).toBe('paused');
    });

    it('names a target kind whether the server sent the constant or the wire name', () => {
        useEnglish();
        expect(targetKindLabel(i18n, 'REPOSITORY')).toBe('Repository');
        expect(targetKindLabel(i18n, 'container')).toBe('Image');
        useFrench();
        expect(targetKindLabel(i18n, 'repository')).toBe('Dépôt');
        expect(targetKindLabel(i18n, 'CONTAINER')).toBe('Image');
        expect(targetKindLabel(i18n, 'helm_chart')).toBe('helm_chart');
    });
});
