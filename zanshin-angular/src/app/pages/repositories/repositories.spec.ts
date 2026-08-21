import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Repositories } from './repositories';

/**
 * The repository list, as cards rather than rows.
 *
 * <p>Converted from a table because these are entities and not measurements: nobody compares the
 * URL of the third against the URL of the seventh, and the alignment a table buys is paid for in
 * horizontal scrolling on a narrow screen. What a smoke test cannot say is whether the card still
 * carries everything the row did — that is what this asserts, field by field.
 */
describe('the repository list', () => {
    let fixture: ComponentFixture<Repositories>;
    let http: HttpTestingController;

    const REPOSITORY = {
        id: 5,
        url: 'ssh://git@bitbucket.example.com/art/arm-libs-spring.git',
        branch: 'master',
        name: null,
        displayName: 'Arm Libs Spring',
        subPath: 'backend',
        scanIntervalMinutes: null,
        scanCron: null,
        openIssues: 38,
        lastScan: {
            id: 34,
            status: 'completed',
            createdAt: '2026-08-21T05:03:00Z',
            error: null
        }
    };

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Repositories],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Repositories);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    function load(repository: Record<string, unknown> = REPOSITORY): void {
        for (const request of http.match(() => true)) {
            request.flush(request.request.url.endsWith('/repositories') ? [repository] : []);
        }
        fixture.detectChanges();
    }

    it('keeps every field the row carried', () => {
        load();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Arm Libs Spring');
        expect(text).toContain('ssh://git@bitbucket.example.com/art/arm-libs-spring.git');
        expect(text).toContain('master');
        expect(text).toContain('38 outstanding');
    });

    it('shows the sub-path, or a monorepo registered twice reads as one target listed twice', () => {
        load();
        expect(fixture.nativeElement.textContent).toContain('backend');
    });

    it("links the outstanding count to that target's backlog", () => {
        load();

        const link = fixture.nativeElement.querySelector('a[href*="/issues"]');
        expect(link).not.toBeNull();
        expect(link.getAttribute('href')).toContain('repository_id=5');
    });

    it('says "nothing outstanding" rather than showing a bare zero', () => {
        load({ ...REPOSITORY, openIssues: 0 });
        expect(fixture.nativeElement.textContent).toContain('nothing outstanding');
    });

    it('says a never-scanned target was never scanned', () => {
        load({ ...REPOSITORY, lastScan: null });
        // An empty cell reads as missing data; "never scanned" is a fact about the target.
        expect(fixture.nativeElement.textContent).toContain('Never scanned');
    });

    it('offers nothing to click when there is nothing to list', () => {
        load();
        http.verify();
    });
});
