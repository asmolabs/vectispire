import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Exceptions } from './exceptions';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The exceptions register, and the review that did not exist.
 *
 * **What is covered here is not the display but the one action whose effect is invisible.**
 * Confirming an exception changes neither its decision, nor its deadline, nor its author: the only
 * thing that moves is the evidence that somebody looked. A screen sending nothing in that case
 * would look exactly the same, and that is precisely the defect this feature fixes on the server.
 *
 * The second case pins the local refusal to extend with no date. The server refuses it too; what
 * is asserted here is that the screen does not let the request go in order to show its error — a
 * disabled button says the same thing without noise.
 */
describe('le registre des exceptions', () => {
    let fixture: ComponentFixture<Exceptions>;
    let http: HttpTestingController;

    const REGISTER = asSchema('Register', {
            entries: [
                {
                    issue_id: 41,
                    identifier: 'CVE-2026-0001',
                    severity: 'high',
                    target_kind: 'REPOSITORY',
                    target_id: 7,
                    target_name: 'paiement-api',
                    decision: 'not_affected',
                    justification: 'vulnerable_code_not_in_execute_path',
                    comment: null,
                    actor: 'c.moreau',
                    origin: 'manual',
                    decided_at: '2026-01-12T09:00:00Z',
                    expires_at: '2026-12-31T00:00:00Z',
                    lapsed: false,
                    last_reviewed_at: null,
                    last_reviewed_by: null
                }
            ],
            granted: 1,
            awaiting_approval: 0,
            lapsed: 0,
            never_reviewed: 1,
            next_cursor: null
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Exceptions],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Exceptions);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        http.expectOne((call) => call.url === '/api/v1/exceptions').flush(REGISTER);
    }, 20_000);

    it('envoie une confirmation, qui ne change rien sauf la preuve', () => {
        const component = fixture.componentInstance;
        component.openReview(REGISTER.entries[0]);
        component.submitReview();

        const call = http.expectOne('/api/v1/exceptions/41/reviews');
        expect(call.request.body.outcome).toBe('CONFIRMED');
        expect(call.request.body.new_expiry).toBeNull();

        // **The row comes back dated**, as the server would return it: the counters are derived
        // from the rows rather than taken from the server, so a data set where the counter moves
        // without the row moving describes nothing real any more.
        call.flush({
            ...REGISTER,
            entries: [{ ...REGISTER.entries[0], last_reviewed_at: '2026-09-14T10:00:00Z', last_reviewed_by: 'n.faure' }],
            never_reviewed: 0
        });

        expect(component.neverReviewed()).toBe(0);
        expect(component.reviewing()).toBeNull();
    });

    it('ne laisse pas partir une prolongation sans date', () => {
        const component = fixture.componentInstance;
        component.openReview(REGISTER.entries[0]);
        component.outcome = 'EXTENDED';

        expect(component.incomplete()).toBe(true);

        component.submitReview();
        http.expectNone('/api/v1/exceptions/41/reviews');
    });

    it('offers more even when the page contained nothing visible', () => {
        // **The client half of the same defect as on the server.** Visibility applies after the
        // read: a whole window can belong to other people only. Hiding the button because the page
        // is empty would make the restricted reader stop just before their own rows — and they are
        // the one person who cannot notice it.
        const component = fixture.componentInstance;
        component.load();
        http.expectOne((call) => call.url === '/api/v1/exceptions').flush({
            entries: [], granted: 0, awaiting_approval: 0, lapsed: 0, never_reviewed: 0,
            next_cursor: '1757836800000:41'
        });

        expect(component.loaded()).toHaveLength(0);
        expect(component.hasMore()).toBe(true);

        component.more();
        const next = http.expectOne((call) => call.url === '/api/v1/exceptions');
        expect(next.request.params.get('cursor')).toBe('1757836800000:41');
        next.flush({ ...REGISTER, next_cursor: null });

        expect(component.loaded()).toHaveLength(1);
        expect(component.hasMore()).toBe(false);
    });

    it('accumulates the pages and recounts over what is loaded', () => {
        const component = fixture.componentInstance;
        expect(component.granted()).toBe(1);

        component.load();
        http.expectOne((call) => call.url === '/api/v1/exceptions')
            .flush({ ...REGISTER, next_cursor: '1757836800000:41' });
        component.more();
        http.expectOne((call) => call.url === '/api/v1/exceptions').flush({
            ...REGISTER,
            entries: [{ ...REGISTER.entries[0], issue_id: 42 }],
            next_cursor: null
        });

        // The counters come from the loaded rows rather than from the server: adding the pages up
        // would give a total that grows as one reads, which is the total of nothing.
        expect(component.loaded()).toHaveLength(2);
        expect(component.granted()).toBe(2);
    });

    it('counts the never-reviewed as a figure apart from the lapsed', () => {
        // Both say "nobody is dealing with it" and they are not the same sentence: a lapsed
        // exception had a deadline that has passed, a never-reviewed one may be perfectly current
        // and simply never have been reopened.
        expect(fixture.componentInstance.lapsed()).toBe(0);
        expect(fixture.componentInstance.neverReviewed()).toBe(1);
    });
});
