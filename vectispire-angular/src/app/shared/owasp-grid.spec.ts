import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { OwaspGridComponent } from './owasp-grid';
import type { OwaspGrid } from '@/app/core/api.models';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
import { asSchema } from '@/app/core/testing/contract';

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

    function line(id: string, state: string, findings = 0) {
        return { id, title: id, state, findings, because: 'parce que.' };
    }

    const GRID = asSchema('DeclaredGrid', {
        lines: [
            line('A01', 'NOT_COVERED'),
            line('A05', 'FINDINGS', 3),
            line('A06', 'NO_FINDING'),
            line('A07', 'NOT_MEASURED')
        ],
        covered: 3,
        withFindings: 1,
        unmeasured: 1
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
        const cells = fixture.nativeElement.querySelectorAll('tbody tr td:nth-child(3)');
        expect([...cells].map((cell: HTMLElement) => cell.textContent!.trim())).toEqual(['—', '3', '—', '—']);
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
        expect(failed.nativeElement.textContent.trim()).toBe('');
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
            unmeasured: 0
        };
        asSchema('DeclaredGrid', declared);

        fixture.componentInstance.grid.set(declared);
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent as string;
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
            expect(sent.request.body.applicability).toBe('APPLICABLE');
            expect(sent.request.body.evidence_source).toBe('EXTERNAL');
            expect(sent.request.body.external_evidence).toBe('Dossier QUAL-2026');
            sent.flush({});

            // Reloaded rather than merged in place: the grid carries counters, and recomputing
            // them in the browser would make a second implementation of them.
            http.expectOne((call) => call.url === '/api/v1/owasp/coverage').flush(GRID);
            expect(component.editing()).toBeNull();
        });
    });
});
