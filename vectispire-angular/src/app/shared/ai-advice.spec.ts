import { provideHttpClient, withXhr } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { AiDeterministic } from '@/app/core/api.models';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { adviceExploitation, adviceFix, adviceSummary, epssPercent } from './ai-advice';

/**
 * The advisor's own sentences, and what they may not say.
 *
 * Both screens formatted a missing EPSS score as 85 %, and read `activelyExploited: false` — sent
 * before any catalogue had been read — as "not exploited". The server made up the rest: 75 % for
 * every CVE the estate does not carry, and "the component", version "current", "the latest fixed
 * version" where nothing was recorded.
 */
describe('the advisor wording', () => {
    let i18n: I18nService;

    const OWN: AiDeterministic = {
        packageName: 'log4j-core',
        currentVersion: '2.14.1',
        targetVersion: '2.17.1',
        kev: 'LISTED',
        exploitProbability: 0.94358
    };

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr())] });
        i18n = TestBed.inject(I18nService);
        i18n.translations.set({
            ai: {
                summary: 'S {{id}} {{package}} {{version}}',
                summary_no_component: 'S-NONE {{id}}',
                unknown: 'UNKNOWN',
                kev_listed: 'KEV-LISTED',
                kev_not_listed: 'KEV-NOT-LISTED',
                kev_unknown: 'KEV-UNKNOWN',
                epss: 'EPSS {{chance}}',
                epss_unknown: 'EPSS-UNKNOWN',
                fix_action: 'FIX {{package}} {{version}} {{target}}',
                fix_action_no_component: 'FIX-ANY {{target}}',
                fix_none: 'FIX-NONE'
            }
        });
    });

    it('states the listing and the score the feeds hold', () => {
        expect(adviceExploitation(i18n, OWN)).toBe('KEV-LISTED EPSS 94.358');
    });

    it('says unknown for a listing nobody read and a score nobody published — never 85 %', () => {
        const text = adviceExploitation(i18n, { ...OWN, kev: 'UNKNOWN', exploitProbability: null });

        expect(text).toBe('KEV-UNKNOWN EPSS-UNKNOWN');
        expect(text).not.toContain('85');
    });

    it('tells a CVE the catalogue does not list from one nobody looked up', () => {
        expect(adviceExploitation(i18n, { ...OWN, kev: 'NOT_LISTED' })).toContain('KEV-NOT-LISTED');
    });

    it('fills in no component, version or fix nobody recorded', () => {
        const nothing: AiDeterministic = {
            packageName: null,
            currentVersion: null,
            targetVersion: null,
            kev: 'UNKNOWN',
            exploitProbability: null
        };

        expect(adviceSummary(i18n, 'CVE-2021-44228', nothing)).toBe('S-NONE CVE-2021-44228');
        expect(adviceFix(i18n, nothing)).toBe('FIX-NONE');
        expect(adviceSummary(i18n, 'CVE-2021-44228', { ...OWN, currentVersion: null })).toBe(
            'S CVE-2021-44228 log4j-core UNKNOWN'
        );
        expect(adviceFix(i18n, { ...nothing, targetVersion: '2.17.1' })).toBe('FIX-ANY 2.17.1');
        expect(adviceFix(i18n, OWN)).toBe('FIX log4j-core 2.14.1 2.17.1');
    });

    it('does not round a small measured score to zero', () => {
        expect(epssPercent(0.00043)).toBe('0.043');
        expect(epssPercent(0.975)).toBe('97.5');
    });
});
