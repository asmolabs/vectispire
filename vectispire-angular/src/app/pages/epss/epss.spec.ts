import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { Epss } from './epss';
import { I18nService } from '@/app/core/i18n/i18n.service';

/**
 * L'écran où l'on regarde une CVE avant de savoir si elle vous concerne.
 *
 * <p><b>C'est ici que la question « qu'est-ce que c'est » se pose, et il n'y avait aucun endroit
 * pour la poser.</b> Le conseiller n'était atteignable que depuis un constat du parc — c'est-à-dire
 * seulement quand la réponse était déjà « oui, elle vous concerne ». La route qui explique une CVE
 * quelconque existait, avec un repli déterministe pour celles que le parc ne porte pas, et aucun
 * composant ne l'appelait.
 */
describe("la priorisation EPSS", () => {
    let fixture: ComponentFixture<Epss>;
    let http: HttpTestingController;

    const RECORD = {
        cveId: 'CVE-2021-44228',
        epssScore: 0.97,
        epssPercentile: 0.99,
        isKev: true,
        notes: null
    };

    /** Monte l'écran et répond aux deux appels de démarrage. */
    async function mount(aiEnabled: boolean): Promise<void> {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Epss],
            providers: [provideHttpClient(), provideHttpClientTesting()]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            common: { close: 'Close' },
            epss: { explain: 'Explain this CVE (AI)', explain_failed: 'The model did not answer. Nothing was produced.' }
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

    /** Cherche une CVE et rend la fiche. */
    function lookup(): void {
        fixture.componentInstance.cveSearchQuery = 'CVE-2021-44228';
        fixture.componentInstance.searchCve();
        http.expectOne((call) => call.url.includes('/api/v1/epss/cve/')).flush(RECORD);
        fixture.detectChanges();
    }

    beforeEach(async () => {
        await mount(true);
    }, 20_000);

    it("explique la CVE affichée, et non celle qui est tapée dans le champ", () => {
        lookup();

        // La fiche fait foi : le champ peut avoir été modifié depuis la recherche, et expliquer
        // une CVE sous les chiffres d'une autre est le pire des deux mondes.
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

        // Sur le signal et non sur le DOM : la fenêtre est rendue \, donc hors
        // de l'élément du composant.
        expect(fixture.componentInstance.advice()?.summaryExplanation).toBe('Remote code execution.');
    });

    it("efface l'explication quand on cherche une autre CVE", () => {
        lookup();
        fixture.componentInstance.explain();
        http.expectOne((request) => request.url.includes('/ai-advisor/explain/cve/')).flush({
            identifier: 'CVE-2021-44228', title: '', summaryExplanation: 'Remote code execution.',
            exploitMechanics: '', exposureAssessment: '',
            remediation: { fixAction: '', suggestedVersion: '', codeSnippetOrDiff: '', cliCommand: '' },
            vexSuggestion: { status: '', justification: '', impactStatement: '', actionStatement: '' },
            references: []
        });

        // Une analyse laissée sous les chiffres d'une autre CVE se lit comme la sienne.
        lookup();
        expect(fixture.componentInstance.advice()).toBeNull();
    });

    it("dit que le modèle n'a pas répondu, plutôt que de ne rien montrer", () => {
        lookup();
        fixture.componentInstance.explain();
        http.expectOne((request) => request.url.includes('/ai-advisor/explain/cve/'))
            .error(new ProgressEvent('failed'));
        fixture.detectChanges();

        expect(fixture.componentInstance.adviceError()).toContain('did not answer');
        expect(fixture.componentInstance.adviceLoading()).toBe(false);
    });

    it("n'offre rien à expliquer quand aucun modèle n'est configuré", async () => {
        await mount(false);
        lookup();

        // Une option absente doit être absente, pas présente et refusante.
        expect(fixture.componentInstance.aiEnabled()).toBe(false);
        expect(document.body.textContent).not.toContain('Explain this CVE');
    });
});
