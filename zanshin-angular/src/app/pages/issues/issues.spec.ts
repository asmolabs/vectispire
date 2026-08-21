import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Issues } from './issues';

/**
 * The backlog.
 *
 * <p>The one screen with real volume, and therefore the one where paging is not decoration: it
 * asks the server for a window and says which window it is showing. A page that silently
 * displayed the first fifty of two hundred would read as a backlog of fifty.
 */
describe('the issue backlog', () => {
    let fixture: ComponentFixture<Issues>;
    let http: HttpTestingController;

    function issue(id: number, identifier: string): Record<string, unknown> {
        return {
            id,
            repoId: 5,
            containerId: null,
            targetKind: 'repository',
            targetName: 'Arm Libs Spring',
            type: 'vulnerability',
            identifier,
            severity: 'high',
            packageName: 'openssl',
            packageVersion: '3.0.1',
            state: 'open',
            firstSeenAt: '2026-03-03T08:00:00Z',
            lastSeenAt: '2026-08-21T05:03:00Z',
            timesSeen: 1,
            triageStatus: 'under_review',
            isKev: false
        };
    }

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Issues],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Issues);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        // The filters offer target names, so the page fetches both target kinds.
        http.expectOne((call) => call.url === '/api/v1/repositories').flush([]);
        http.expectOne((call) => call.url === '/api/v1/containers').flush([]);
    }, 20_000);

    function firstPage(total: number): void {
        http.expectOne((call) => call.url === '/api/v1/issues')
            .flush({ items: [issue(1, 'CVE-2026-1234')], total, limit: 50, offset: 0 });
        fixture.detectChanges();
    }

    it('says which window of the backlog it is showing', () => {
        firstPage(228);

        // Without this, fifty rows out of two hundred read as a backlog of fifty.
        expect(fixture.componentInstance.pageLabel()).toBe('1–50 of 228');
        expect(fixture.nativeElement.textContent).toContain('1–50 of 228');
    });

    it('asks the server for the next window rather than slicing what it holds', () => {
        firstPage(228);

        fixture.componentInstance.reload(50);
        const next = http.expectOne((call) => call.url === '/api/v1/issues');
        expect(next.request.urlWithParams).toContain('offset=50');
        next.flush({ items: [issue(2, 'CVE-2026-9999')], total: 228, limit: 50, offset: 50 });
        fixture.detectChanges();

        expect(fixture.componentInstance.pageLabel()).toBe('51–100 of 228');
    });

    it('links each row to its detail', () => {
        firstPage(1);

        const link = fixture.nativeElement.querySelector('a[href="/issues/1"]');
        expect(link).not.toBeNull();
        expect(link.textContent).toContain('CVE-2026-1234');
    });

    it('says "no result" rather than showing an empty frame', () => {
        http.expectOne((call) => call.url === '/api/v1/issues')
            .flush({ items: [], total: 0, limit: 50, offset: 0 });
        fixture.detectChanges();

        expect(fixture.componentInstance.pageLabel()).toBe('No result');
    });

    it('stops loading when the request is refused', () => {
        http.expectOne((call) => call.url === '/api/v1/issues')
            .flush(null, { status: 500, statusText: 'Server Error' });
        fixture.detectChanges();

        // A spinner that never stops is how a failed page passes for a slow one.
        expect(fixture.componentInstance.loading()).toBe(false);
    });
});
