import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { Epss } from './epss';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The screen where one looks at a CVE before knowing whether it concerns them.
 *
 * <p><b>This is where the question "what is it" gets asked, and there was nowhere to ask it.</b>
 * The advisor was reachable only from a finding in the estate — that is, only once the answer was
 * already "yes, it concerns you". The route explaining an arbitrary CVE existed, with a
 * deterministic fallback for those the estate does not carry, and no component called it.
 */
describe('EPSS prioritisation', () => {
    let fixture: ComponentFixture<Epss>;
    let http: HttpTestingController;

    const RECORD = asSchema('ThreatIntelRecord', {
            cveId: 'CVE-2021-44228',
            epssScore: 0.97,
            epssPercentile: 0.99,
            isKev: true,
            notes: null
    });

    /** Mounts the screen and answers the two start-up calls. */
    async function mount(aiEnabled: boolean): Promise<void> {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Epss],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            common: { close: 'Close' },
            epss: { explain: 'Explain this CVE (AI)', explain_failed: 'The model did not answer. Nothing was produced.' },
            // Deliberately not the English the server carries: a case asserting on the same words
            // could not tell a translated sentence from the fallback printed as it stands.
            ai: { summary: 'TRANSLATED: {{id}} touche {{package}} {{version}}' }
        });

        fixture = TestBed.createComponent(Epss);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        http.expectOne((call) => call.url === '/api/v1/epss/priorities')
            .flush({
                totalVulnerabilities: 0, activeKevCount: 0, highEpssCount: 0, reachableEpssCount: 0,
                averageFleetEpss: 0, topPriorities: [], breakdownByTier: {}
            });
        http.expectOne((call) => call.url === '/api/v1/ai-advisor/status')
            .flush({ enabled: aiEnabled, selectedModel: aiEnabled ? 'llama3' : null, availableModels: [] });
        fixture.detectChanges();
    }

    /** Searches for a CVE and renders the card. */
    function lookup(): void {
        fixture.componentInstance.cveSearchQuery = 'CVE-2021-44228';
        fixture.componentInstance.searchCve();
        http.expectOne((call) => call.url.includes('/api/v1/epss/cve/')).flush(RECORD);
        fixture.detectChanges();
    }

    beforeEach(async () => {
        await mount(true);
    }, 20_000);

    it('explains the CVE on screen, and not the one typed in the field', () => {
        lookup();

        // The card is authoritative: the field may have been edited since the search, and
        // explaining one CVE under another's numbers is the worst of both worlds.
        fixture.componentInstance.cveSearchQuery = 'CVE-2000-0000';
        fixture.componentInstance.explain();

        const call = http.expectOne((request) => request.url.includes('/ai-advisor/explain/cve/'));
        expect(call.request.url).toContain('CVE-2021-44228');
        call.flush({
            identifier: 'CVE-2021-44228', title: 'Log4Shell', summaryExplanation: 'Remote code execution.',
            exploitMechanics: '', exposureAssessment: '',
            remediation: { fixAction: 'Upgrade to 2.17.1', suggestedVersion: '2.17.1', codeSnippetOrDiff: '', cliCommand: '' },
            vexSuggestion: { status: 'affected', justification: '', impactStatement: '', actionStatement: '' },
            references: []
        });
        fixture.detectChanges();

        // On the signal and not on the DOM: the dialog renders into an overlay attached outside the
        // component's own element.
        expect(fixture.componentInstance.advice()?.summaryExplanation).toBe('Remote code execution.');
    });

    it('clears the explanation when another CVE is searched for', () => {
        lookup();
        fixture.componentInstance.explain();
        http.expectOne((request) => request.url.includes('/ai-advisor/explain/cve/')).flush({
            identifier: 'CVE-2021-44228', title: '', summaryExplanation: 'Remote code execution.',
            exploitMechanics: '', exposureAssessment: '',
            remediation: { fixAction: '', suggestedVersion: '', codeSnippetOrDiff: '', cliCommand: '' },
            vexSuggestion: { status: '', justification: '', impactStatement: '', actionStatement: '' },
            references: []
        });

        // An analysis left under another CVE's numbers reads as that CVE's own.
        lookup();
        expect(fixture.componentInstance.advice()).toBeNull();
    });

    /**
     * **Whose words are on the screen.**
     *
     * These fields carry a model's own prose when a model answers, so they cannot become tokens.
     * What the server says instead is who wrote them: `deterministic` is set only when the product
     * wrote them itself, and then the screen must render the reader's language rather than the
     * English the response carries.
     *
     * Before this, the fallback was French for everybody — including the English reader — and the
     * screen printed whatever arrived.
     */
    it('translates the wording the product wrote itself', () => {
        lookup();
        fixture.componentInstance.explain();
        http.expectOne((request) => request.url.includes('/ai-advisor/explain/cve/')).flush({
            identifier: 'CVE-2021-44228', title: '', summaryExplanation: 'ENGLISH FALLBACK FROM THE SERVER',
            exploitMechanics: '', exposureAssessment: '',
            remediation: { fixAction: '', suggestedVersion: '', codeSnippetOrDiff: '', cliCommand: '' },
            vexSuggestion: { status: '', justification: '', impactStatement: '', actionStatement: '' },
            references: [],
            deterministic: {
                packageName: 'log4j-core', currentVersion: '2.14.1', targetVersion: '2.17.1',
                exposure: 'NOT_MENTIONED', activelyExploited: false, exploitProbability: null
            }
        });
        fixture.detectChanges();

        const text = document.body.textContent ?? '';
        expect(text).toContain('TRANSLATED: CVE-2021-44228 touche log4j-core 2.14.1');
        expect(text).not.toContain('ENGLISH FALLBACK FROM THE SERVER');
    });

    it("leaves a model's own words alone", () => {
        lookup();
        fixture.componentInstance.explain();
        http.expectOne((request) => request.url.includes('/ai-advisor/explain/cve/')).flush({
            identifier: 'CVE-2021-44228', title: '', summaryExplanation: 'What the model actually wrote.',
            exploitMechanics: '', exposureAssessment: '',
            remediation: { fixAction: '', suggestedVersion: '', codeSnippetOrDiff: '', cliCommand: '' },
            vexSuggestion: { status: '', justification: '', impactStatement: '', actionStatement: '' },
            references: []
        });
        fixture.detectChanges();

        // Rewriting a model's sentence in this product's words would be putting words in its mouth,
        // on a screen whose whole point is to show what the model said.
        const text = document.body.textContent ?? '';
        expect(text).toContain('What the model actually wrote.');
        expect(text).not.toContain('TRANSLATED:');
    });

    it('says the model did not answer, rather than showing nothing', () => {
        lookup();
        fixture.componentInstance.explain();
        http.expectOne((request) => request.url.includes('/ai-advisor/explain/cve/'))
            .error(new ProgressEvent('failed'));
        fixture.detectChanges();

        expect(fixture.componentInstance.adviceError()).toContain('did not answer');
        expect(fixture.componentInstance.adviceLoading()).toBe(false);
    });

    it('offers nothing to explain when no model is configured', async () => {
        await mount(false);
        lookup();

        // An absent option must be absent, not present and refusing.
        expect(fixture.componentInstance.aiEnabled()).toBe(false);
        expect(document.body.textContent).not.toContain('Explain this CVE');
    });
});
