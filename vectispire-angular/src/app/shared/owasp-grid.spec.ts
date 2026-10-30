import { HttpHeaders, provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
    DECLARED_KEYS,
    GRID_IMPLEMENTATION_KEYS,
    OWASP_GAP_KEYS,
    OWASP_REASON_KEYS,
    OWASP_STATE_KEYS,
    OwaspGridComponent
} from './owasp-grid';
import { missingFromBundles } from '@/app/core/testing/bundles';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import english from '../../../public/i18n/en.json';
import french from '../../../public/i18n/fr.json';
import type { DeclarationRequest, OwaspCoverageLine, OwaspGrid, OwaspState } from '@/app/core/api.models';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
import { asSchema, newerServerWord } from '@/app/core/testing/contract';

/**
 * The grid of ten, and the distinction that justifies it.
 *
 * **"Nothing found" and "nothing looks" produce the same green.** Two states cannot separate them,
 * hence four — and the assertions here are about the three that are not "nothing found", because
 * those are the ones a two-state grid gets wrong while looking right.
 */
describe('la grille OWASP', () => {
    let fixture: ComponentFixture<OwaspGridComponent>;
    let http: HttpTestingController;

    // Typed: the lines lacked the `declaration` and the grid the `scope` the server sends as null, and
    // a cast at the one use that needed the type had kept that from showing.
    function line(id: string, state: OwaspState, findings = 0): OwaspCoverageLine {
        return { id, title: id, state, findings, because: 'parce que.', declaration: null };
    }

    const GRID: OwaspGrid = asSchema('DeclaredGrid', {
        lines: [
            line('A01', 'NOT_COVERED'),
            line('A05', 'FINDINGS', 3),
            line('A06', 'NO_FINDING'),
            line('A07', 'NOT_MEASURED')
        ],
        covered: 3,
        withFindings: 1,
        unmeasured: 1,
        unplacedCode: 0,
        scope: null
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [OwaspGridComponent],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(OwaspGridComponent);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/owasp/coverage').flush(GRID);
        fixture.detectChanges();
    }, 20_000);

    it('does not paint "no scanner here" the colour of "nothing found"', () => {
        const component = fixture.componentInstance;

        expect(component.colourOf('NOT_COVERED')).not.toBe(component.colourOf('NO_FINDING'));
        expect(component.colourOf('NOT_MEASURED')).not.toBe(component.colourOf('NO_FINDING'));
    });

    it('shows a count only where something was counted', () => {
        // A "0" beside a category nothing looks at is the figure this whole grid exists not to
        // write.
        const cells = (fixture.nativeElement as HTMLElement).querySelectorAll<HTMLElement>('tbody tr td:nth-child(3)');
        expect([...cells].map((cell) => cell.textContent.trim())).toEqual(['—', '3', '—', '—']);
    });

    /**
     * The state column through literal keys (decision 0019): it built `'owasp_grid.state.' + state`,
     * so a state a newer server sends would have shown as a key path in the column that matters.
     */
    it('names each state in words, and a state it does not know as sent', () => {
        useEnglish();
        fixture.componentInstance.grid.set({
            ...GRID,
            lines: [...GRID.lines, line('A10', newerServerWord('PARTLY_MEASURED'))]
        } satisfies OwaspGrid);
        fixture.detectChanges();

        const cells = [...(fixture.nativeElement as HTMLElement).querySelectorAll('tbody tr td:nth-child(2)')].map(
            (cell: Element) => cell.textContent.trim()
        );
        expect(cells).toEqual([
            english.owasp_grid.state.NOT_COVERED,
            english.owasp_grid.state.FINDINGS,
            english.owasp_grid.state.NO_FINDING,
            english.owasp_grid.state.NOT_MEASURED,
            'PARTLY_MEASURED'
        ]);
        expect(
            missingFromBundles([
                ...Object.values(OWASP_STATE_KEYS),
                ...Object.values(DECLARED_KEYS),
                ...Object.values(GRID_IMPLEMENTATION_KEYS)
            ])
        ).toEqual([]);
    });

    it('says how many open code findings no category holds, and nothing when there are none', () => {
        const unplaced = () => (fixture.nativeElement as HTMLElement).querySelector('[data-testid="owasp-unplaced"]');
        expect(unplaced()).toBeNull();

        useEnglish();
        fixture.componentInstance.grid.set(asSchema('DeclaredGrid', { ...GRID, unplacedCode: 3 }));
        fixture.detectChanges();

        expect(unplaced()?.textContent).toContain('3 open code findings are in no category');
    });

    it("garde l'ordre du serveur, qui est celui du standard", () => {
        expect(fixture.componentInstance.lines().map((l) => l.id)).toEqual(['A01', 'A05', 'A06', 'A07']);
    });

    it('stays quiet when the grid cannot be read', async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [OwaspGridComponent],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        const failed = TestBed.createComponent(OwaspGridComponent);
        const client = TestBed.inject(HttpTestingController);
        failed.detectChanges();
        client.expectOne((call) => call.url === '/api/v1/owasp/coverage').error(new ProgressEvent('failed'));
        failed.detectChanges();

        // The report below carries its own errors; an empty grid is better than a red banner above
        // valid data.
        expect((failed.nativeElement as HTMLElement).textContent.trim()).toBe('');
    });

    /**
     * **A grey square with no declaration is an admission nobody reviews.**
     *
     * Two Top 10 categories are beyond any static analysis — insecure design cannot be read out of
     * code, and a missing log leaves, by definition, no trace. Saying so is honest; leaving it
     * there indefinitely is not. A declaration carries a name, evidence and a due date, and that is
     * what this row shows.
     */
    it('shows what the organisation states about a category nothing measures', () => {
        // The labels come from the bundle: asserting on unresolved keys would prove `t()` was
        // called and nothing about what a reader sees.
        TestBed.inject(I18nService).translations.set({
            owasp_grid: {
                declared: { APPLICABLE: 'Declared applicable' },
                implementation: { PARTIALLY_IMPLEMENTED: 'partially in place' },
                evidence: 'Evidence:',
                reviewed: 'Reviewed',
                due: 'next'
            }
        });

        // Typed first, checked second: the annotation gives the literals the client's narrow
        // unions, and `asSchema` confronts the same value with the document.
        const declared: OwaspGrid = {
            lines: [
                {
                    id: 'A04',
                    title: 'Insecure Design',
                    state: 'NOT_COVERED',
                    findings: 0,
                    because: 'No scanner in this deployment produces a finding in this category.',
                    declaration: {
                        framework: 'OWASP_2021',
                        controlId: 'A04',
                        applicability: 'APPLICABLE',
                        implementation: 'PARTIALLY_IMPLEMENTED',
                        justification: 'Revue de conception à chaque évolution majeure.',
                        evidenceSource: 'EXTERNAL',
                        externalEvidence: 'Comptes rendus de revue, dossier QUAL-2026',
                        owner: 'c.moreau',
                        decidedBy: 'c.moreau',
                        decidedAt: '2026-09-01T00:00:00Z',
                        reviewedAt: '2026-09-01T00:00:00Z',
                        reviewDueAt: '2027-03-01T00:00:00Z'
                    }
                }
            ],
            covered: 0,
            withFindings: 0,
            unmeasured: 0,
            unplacedCode: 0,
            scope: null
        };
        asSchema('DeclaredGrid', declared);

        fixture.componentInstance.grid.set(declared);
        fixture.detectChanges();

        const text = (fixture.nativeElement as HTMLElement).textContent;
        expect(text).toContain('Declared applicable');
        expect(text).toContain('partially in place');
        expect(text).toContain('c.moreau');
        expect(text).toContain('QUAL-2026');
    });

    /**
     * The declaration form, and the two places it refuses.
     *
     * These are the server's refusals, said by a dead button rather than after the typing — and
     * they are ISO 27001's, which name no framework: an exclusion with no reason is a line stepping
     * out of scope without saying why, and evidence declared elsewhere without saying where is the
     * same omission moved.
     */
    describe('the declaration', () => {
        function asSecurityLead(): void {
            TestBed.inject(SessionStore).open('a-token', {
                username: 'c.moreau',
                displayName: null,
                role: 'CISO',
                mustChangePassword: false,
                mfaEnabled: false
            });
        }

        it('is offered only where nothing measures', () => {
            asSecurityLead();
            const component = fixture.componentInstance;

            // A05 carries findings: a declaration set beside a measurement is a second source, and
            // it is the measurement that would lose.
            expect(component.declarable(component.lines()[1])).toBe(false);
            expect(component.declarable(component.lines()[0])).toBe(true);
        });

        it('is not offered to somebody who cannot write it', () => {
            // The server refuses, and a button that answers 403 says the product is broken rather
            // than that the action is not theirs.
            expect(fixture.componentInstance.declarable(fixture.componentInstance.lines()[0])).toBe(false);
        });

        it('refuses an exclusion with no reason, and external evidence with no address', () => {
            asSecurityLead();
            const component = fixture.componentInstance;
            component.openDeclare(component.lines()[0]);

            component.applicability = 'EXCLUDED';
            component.justification = '';
            expect(component.incomplete()).toBe(true);

            component.justification = 'Traitée par la revue de conception.';
            expect(component.incomplete()).toBe(false);

            component.applicability = 'APPLICABLE';
            component.evidenceSource = 'EXTERNAL';
            component.externalEvidence = '';
            expect(component.incomplete()).toBe(true);

            component.externalEvidence = 'Dossier QUAL-2026';
            expect(component.incomplete()).toBe(false);
        });

        /**
         * **`EXTERNAL` by default, not `VECTISPIRE`.** The category being declared is the one this
         * product does not measure: offering its own evidence by default would invite ticking the
         * one answer the square contradicts.
         */
        it('defaults to external evidence, since this product does not hold it', () => {
            asSecurityLead();
            const component = fixture.componentInstance;

            component.openDeclare(component.lines()[0]);

            expect(component.evidenceSource).toBe('EXTERNAL');
        });

        it("sends the declaration on the row's category, and reloads the grid", () => {
            asSecurityLead();
            const component = fixture.componentInstance;
            component.openDeclare(component.lines()[0]);
            component.justification = 'Revue de conception à chaque évolution majeure.';
            component.externalEvidence = 'Dossier QUAL-2026';
            component.owner = 'c.moreau';

            component.submit();

            const sent = http.expectOne({ method: 'PUT', url: '/api/v1/owasp/coverage/A01/declaration' });
            expect((sent.request.body as DeclarationRequest).applicability).toBe('APPLICABLE');
            expect((sent.request.body as DeclarationRequest).evidence_source).toBe('EXTERNAL');
            expect((sent.request.body as DeclarationRequest).external_evidence).toBe('Dossier QUAL-2026');
            sent.flush(
                asSchema('Declaration', {
                    framework: 'OWASP_2021',
                    controlId: 'A01',
                    applicability: 'APPLICABLE',
                    implementation: null,
                    justification: 'Revue de conception à chaque évolution majeure.',
                    evidenceSource: 'EXTERNAL',
                    externalEvidence: 'Dossier QUAL-2026',
                    owner: 'c.moreau',
                    decidedBy: 'c.moreau',
                    decidedAt: '2026-10-15T08:00:00Z',
                    reviewedAt: null,
                    reviewDueAt: null
                })
            );

            // Reloaded rather than merged in place: the grid carries counters, and recomputing
            // them in the browser would make a second implementation of them.
            http.expectOne((call) => call.url === '/api/v1/owasp/coverage').flush(GRID);
            expect(component.editing()).toBeNull();
        });
    });
    /**
     * **The reason in the reader's language** (decision 0019). The grid's `because` is built in English on
     * the server, and the French screen printed it as it stood. The code and its values travel beside it;
     * the screen writes the sentence, putting the counts, the types and the reasons where French puts them.
     */
    describe('the reason, as a code', () => {
        // Typed, where a cast at each use had hidden that every line lacked its `declaration` and the
        // grid its `scope`, both of which the server sends as null when there is none.
        const reasoned: OwaspGrid = asSchema('DeclaredGrid', {
            lines: [
                {
                    id: 'A06',
                    title: 'Vulnerable and Outdated Components',
                    state: 'NO_FINDING',
                    findings: 0,
                    because:
                        'Scanned by vulnerability, eol — the latest scan of every target it applies to examined it — with nothing open.',
                    declaration: null,
                    reason: {
                        code: 'EXAMINED_NOTHING_OPEN',
                        types: ['vulnerability', 'eol'],
                        missing: null,
                        applicable: null,
                        gaps: []
                    }
                },
                {
                    id: 'A07',
                    title: 'Identification and Authentication Failures',
                    state: 'NOT_MEASURED',
                    findings: 0,
                    because: 'two of three targets were not examined (in English).',
                    declaration: null,
                    reason: {
                        code: 'TARGETS_NOT_EXAMINED',
                        types: ['secret'],
                        missing: 2,
                        applicable: 3,
                        gaps: [
                            { gap: 'NEVER_SCANNED', targets: 1 },
                            { gap: 'LAST_SCAN_FAILED', targets: 1 }
                        ]
                    }
                },
                {
                    id: 'A03',
                    title: 'Injection',
                    state: 'NOT_MEASURED',
                    findings: 0,
                    because: 'One repository was not examined (in English).',
                    declaration: null,
                    reason: {
                        code: 'REPOSITORIES_NOT_EXAMINED',
                        types: [],
                        missing: 1,
                        applicable: 1,
                        gaps: [{ gap: 'NO_RULE_FOR_ITS_LANGUAGES', targets: 1 }]
                    }
                }
            ],
            covered: 3,
            withFindings: 0,
            unmeasured: 2,
            unplacedCode: 0,
            scope: null
        });

        function reasons(): string[] {
            return [...(fixture.nativeElement as HTMLElement).querySelectorAll('tbody tr td:nth-child(4)')].map(
                (cell: Element) => cell.textContent.trim()
            );
        }

        it('writes the French sentence, with its counts, types and reasons, to a French reader', () => {
            useFrench();
            fixture.componentInstance.grid.set(reasoned);
            fixture.detectChanges();

            expect(reasons()).toEqual([
                'Examinée par vulnérabilité, fin de support — le dernier scan de chaque cible concernée ' +
                    "l'a examinée — sans rien d'ouvert.",
                '2 des cibles concernées par cette catégorie (3 au total) ' +
                    "n'ont pas été examinées pour elle par secret exposé (1 n'a jamais terminé de scan, " +
                    '1 dont le dernier scan a échoué) : un zéro ici ne serait pas un résultat.',
                '1 des dépôts concernés par cette catégorie (1 au total) ' +
                    "n'a pas été examiné pour elle par l'analyse de code (1 dans les langages desquels aucune " +
                    'règle installée ne déclare cette catégorie) : un zéro ici ne serait pas un résultat.'
            ]);
        });

        it('writes the English one to an English reader', () => {
            useEnglish();
            fixture.componentInstance.grid.set(reasoned);
            fixture.detectChanges();

            expect(reasons()[0]).toBe(
                'Scanned by vulnerability, end of life — the latest scan of every target it applies to examined ' +
                    'it — with nothing open.'
            );
            expect(reasons()[1]).toBe(
                '2 of the targets this category applies to (3 in all) were not examined for it by exposed secret ' +
                    '(1 never finished a scan, 1 whose latest scan failed), so a zero here would not be a result.'
            );
        });

        /**
         * A newer server can send a code, or a gap, this client has no words for: the server's English sentence
         * is shown whole rather than a key path, an empty cell, or half a sentence in French around it.
         */
        it("falls back on the server's sentence for a code or a gap it does not know, and for no reason at all", () => {
            useFrench();
            const [first, second, third] = reasoned.lines;
            fixture.componentInstance.grid.set({
                ...reasoned,
                lines: [
                    { ...first, reason: { ...first.reason!, code: newerServerWord('PARTLY_EXAMINED') } },
                    {
                        ...second,
                        reason: { ...second.reason!, gaps: [{ gap: newerServerWord('SCANNER_ON_STRIKE'), targets: 2 }] }
                    },
                    { ...third, reason: undefined }
                ]
            });
            fixture.detectChanges();

            expect(reasons()).toEqual([first.because, second.because, third.because]);
        });

        it('has every code and every reason in both bundles', () => {
            const plural = (key: string) => [`${key}_one`, `${key}_other`];
            // The two that count targets are plural pairs, read with the count of those not examined.
            const counted: string[] = [
                OWASP_REASON_KEYS.TARGETS_NOT_EXAMINED,
                OWASP_REASON_KEYS.REPOSITORIES_NOT_EXAMINED
            ];
            const reasonKeys = Object.values(OWASP_REASON_KEYS).flatMap((key) =>
                counted.includes(key) ? plural(key) : [key]
            );
            expect(missingFromBundles([...reasonKeys, ...Object.values(OWASP_GAP_KEYS).flatMap(plural)])).toEqual([]);
            // The French sentence is not the English one copied over: one assertion that the bundles differ.
            expect(french.owasp_grid.reason.NO_SCANNER).not.toBe(english.owasp_grid.reason.NO_SCANNER);
        });
    });

    /**
     * The grid as a file: the scope on screen and the reader's language go with the request, and the file
     * comes through `HttpClient` — a navigation carries no token and saves the 401's empty body.
     */
    describe('the CSV export', () => {
        const saved: string[] = [];

        beforeEach(() => {
            saved.length = 0;
            vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
                saved.push(this.download);
            });
            vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:test/1');
            vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
        });

        afterEach(() => vi.restoreAllMocks());

        function exportButton(): HTMLButtonElement {
            const button = (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>(
                '[data-testid="grid-export-csv"] button'
            );
            expect(button).not.toBeNull();
            return button!;
        }

        it("asks for the scope on screen in the reader's language, and saves the server's file", () => {
            useFrench();
            fixture.componentRef.setInput('scope', { kind: 'project', id: 7 });
            fixture.detectChanges();
            http.expectOne((call) => call.url === '/api/v1/owasp/coverage').flush(GRID);
            fixture.detectChanges();

            exportButton().click();

            const request = http.expectOne((call) => call.url === '/api/v1/owasp/coverage/export.csv');
            expect(request.request.method).toBe('GET');
            expect(request.request.responseType).toBe('blob');
            expect(request.request.params.get('project_id')).toBe('7');
            expect(request.request.params.has('solution_id')).toBe(false);
            expect(request.request.params.get('language')).toBe('fr');
            request.flush(new Blob(['category\r\n']), {
                headers: new HttpHeaders({
                    'Content-Disposition': 'attachment; filename="vectispire-owasp-coverage-project-7.csv"'
                })
            });

            expect(saved).toEqual(['vectispire-owasp-coverage-project-7.csv']);
        });

        it('sends no scope for the estate, and says so when the file does not arrive', () => {
            useEnglish();
            exportButton().click();

            const request = http.expectOne((call) => call.url === '/api/v1/owasp/coverage/export.csv');
            expect(request.request.params.keys()).toEqual(['language']);
            expect(request.request.params.get('language')).toBe('en');
            request.error(new ProgressEvent('failed'));
            fixture.detectChanges();

            expect(saved).toEqual([]);
            const message = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="grid-export-error"]');
            expect(message?.textContent.trim()).toBe(english.owasp_grid.export_failed);
            expect(missingFromBundles(['owasp_grid.export_csv', 'owasp_grid.export_failed'])).toEqual([]);
        });
    });
});
