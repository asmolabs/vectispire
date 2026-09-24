import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Soa } from './soa';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The statement of applicability, and the order it opens in.
 *
 * **The server returns the rows in the standard's order, which is right for printing the document
 * and wrong for opening it.** The question asked in front of this screen is "what is wrong", and
 * it is answered at the top. A contradicted control filed twelfth because its identifier begins
 * with an eight is a finding nobody sees.
 *
 * The second case pins the two refusals the server makes, said here by a disabled button rather
 * than by a message after the keystroke.
 */
describe('the statement of applicability', () => {
    let fixture: ComponentFixture<Soa>;
    let http: HttpTestingController;

    function line(id: string, divergence: string, declared: boolean) {
        return {
            control: { id, name: id, requirement: '', category: 'GOVERNANCE' },
            declaration: declared
                ? {
                      framework: 'ISO_27001', controlId: id, applicability: 'APPLICABLE',
                      justification: 'In scope.', implementation: 'IMPLEMENTED', evidenceSource: 'VECTISPIRE',
                      externalEvidence: null, owner: 'n.faure', decidedBy: 'c.moreau',
                      decidedAt: '2026-01-01T00:00:00Z', reviewedAt: '2026-01-01T00:00:00Z', reviewDueAt: null
                  }
                : null,
            measured: 'NON_COMPLIANT',
            divergence,
            reviewOverdue: false
        };
    }

    const STATEMENT = asSchema('SoaStatement', {
            framework: 'ISO_27001',
            total: 4,
            declared: 3,
            findings: 2,
            reviewsOverdue: 0,
            complete: false,
            lines: [
                line('ISO-A.5.15', 'CONSISTENT', true),
                line('ISO-A.8.9', 'UNDECLARED', false),
                line('ISO-A.8.28', 'OVERSTATED', true),
                line('ISO-A.8.8', 'CONTRADICTED', true)
            ]
    });

    /** Two frameworks: the question is asked at the scale of the management system. */
    const OVERDUE = [
        {
            framework: 'ISO_27001', controlId: 'ISO-A.8.8', applicability: 'APPLICABLE',
            justification: null, implementation: 'IMPLEMENTED', evidenceSource: 'VECTISPIRE',
            externalEvidence: null, owner: 'c.moreau', decidedBy: 'ciso',
            decidedAt: '2025-01-10T09:00:00Z', reviewedAt: null, reviewDueAt: '2026-02-01T00:00:00Z'
        },
        {
            framework: 'NIS_2', controlId: 'NIS2-ART21-2-E', applicability: 'APPLICABLE',
            justification: null, implementation: 'PLANNED', evidenceSource: 'EXTERNAL',
            externalEvidence: 'PSSI §4', owner: null, decidedBy: 'ciso',
            decidedAt: '2025-03-01T09:00:00Z', reviewedAt: null, reviewDueAt: '2026-06-01T00:00:00Z'
        }
    ];

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Soa],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Soa);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/compliance/soa').flush([STATEMENT]);
        http.expectOne((call) => call.url === '/api/v1/compliance/soa/reviews/overdue').flush(OVERDUE);
        fixture.detectChanges();
    }, 20_000);

    it('opens on the divergences, most severe to least', () => {
        expect(fixture.componentInstance.lines().map((l) => l.control.id))
            .toEqual(['ISO-A.8.8', 'ISO-A.8.9', 'ISO-A.8.28', 'ISO-A.5.15']);
    });

    it('counts as a finding only what an assessment would write up', () => {
        const component = fixture.componentInstance;
        const [contradicted, undeclared, overstated, consistent] = component.lines();

        expect(component.isFinding(contradicted)).toBe(true);
        expect(component.isFinding(undeclared)).toBe(true);
        // A document ahead of the practice is not the same class of problem as a false claim.
        expect(component.isFinding(overstated)).toBe(false);
        expect(component.isFinding(consistent)).toBe(false);
    });

    it('refuses an exclusion with no justification, before the request', () => {
        const component = fixture.componentInstance;
        component.openDeclare(component.lines()[0]);
        component.applicability = 'EXCLUDED';
        component.justification = '   ';

        expect(component.incomplete()).toBe(true);

        component.submit();
        http.expectNone((call) => call.method === 'PUT');
    });

    it('refuses evidence declared elsewhere that names nowhere', () => {
        const component = fixture.componentInstance;
        component.openDeclare(component.lines()[0]);
        component.applicability = 'APPLICABLE';
        component.evidenceSource = 'EXTERNAL';
        component.externalEvidence = '';

        expect(component.incomplete()).toBe(true);
    });

    it('sends the declaration and reads the document again rather than recomputing the divergence', () => {
        const component = fixture.componentInstance;
        component.openDeclare(component.lines()[0]);
        component.submit();

        const call = http.expectOne('/api/v1/compliance/soa/ISO_27001/ISO-A.8.8');
        expect(call.request.method).toBe('PUT');
        expect(call.request.body.applicability).toBe('APPLICABLE');
        call.flush({});

        // Recomputing the divergence in the browser would make a second implementation of the
        // rule, which would end up no longer saying the same thing as the evidence bundle.
        http.expectOne((request) => request.url === '/api/v1/compliance/soa').flush([STATEMENT]);
    });

    it('opens the overdue-review counter onto the list, across all frameworks', () => {
        // **A number you cannot open is not a record of review, it is a reproach.** Every document
        // displayed "n reviews overdue" and nothing said which, although the route existed.
        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('ISO-A.8.8');
        expect(text).toContain('NIS2-ART21-2-E');
        // The framework is named on every row: the list crosses documents, and a row without its
        // framework attaches to nothing.
        expect(text).toContain('NIS_2');
        expect(text).toContain('c.moreau');
    });

    it('shows no section when no review has lapsed', async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Soa],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        const clean = TestBed.createComponent(Soa);
        const calls = TestBed.inject(HttpTestingController);
        clean.detectChanges();
        calls.expectOne((call) => call.url === '/api/v1/compliance/soa').flush([STATEMENT]);
        calls.expectOne((call) => call.url === '/api/v1/compliance/soa/reviews/overdue').flush([]);
        clean.detectChanges();

        // A panel shown when all is well loses its meaning within days, and then the one that
        // matters becomes invisible too.
        expect(clean.nativeElement.textContent).not.toContain('Reviews overdue');
        expect(clean.componentInstance.overdue()).toEqual([]);
    });

    it('shows the statement even when the list of reviews fails', async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Soa],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        const degraded = TestBed.createComponent(Soa);
        const calls = TestBed.inject(HttpTestingController);
        degraded.detectChanges();
        calls.expectOne((call) => call.url === '/api/v1/compliance/soa').flush([STATEMENT]);
        calls.expectOne((call) => call.url === '/api/v1/compliance/soa/reviews/overdue')
            .error(new ProgressEvent('failed'));
        degraded.detectChanges();

        // The screen's subject is the statement; an unavailable list must not carry it away.
        expect(degraded.componentInstance.lines().length).toBeGreaterThan(0);
        expect(degraded.componentInstance.error()).toBeNull();
    });
});
