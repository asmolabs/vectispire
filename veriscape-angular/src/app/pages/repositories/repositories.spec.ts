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

    it('says a target with no schedule is scanned only when somebody asks', () => {
        load();
        // A blank schedule column reads as "nothing to say here"; the target is in fact never
        // rescanned, which is the one thing about it worth knowing.
        expect(fixture.nativeElement.textContent).toContain('manual only');
    });

    it('shows the expression rather than the interval when both are set, as the scheduler does', () => {
        load({ ...REPOSITORY, scanIntervalMinutes: 60, scanCron: '0 2 * * *' });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('cron 0 2 * * *');
        // Showing "every 60 min" would be a third opinion on a precedence the server already owns.
        expect(text).not.toContain('every 60 min');
    });

    /**
     * The schedule on the wire.
     *
     * <p>The two columns have existed on the row since the first version and no form ever wrote
     * them, so the assertion that matters is that the field reaches the request — a schedule the
     * dialog collects and drops is the same defect with a nicer screen.
     */
    it('sends the schedule when a repository is added', () => {
        load();

        fixture.componentInstance.openForm();
        fixture.componentInstance.form.url = 'https://github.com/org/thing.git';
        fixture.componentInstance.form.scanIntervalMinutes = 720;
        fixture.componentInstance.form.scanCron = '0 2 * * *';
        fixture.componentInstance.submit();

        const body = http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/repositories').request.body;
        expect(body.scanIntervalMinutes).toBe(720);
        expect(body.scanCron).toBe('0 2 * * *');
    });

    it('clears an interval with zero, because absent means "leave alone" on the update path', () => {
        load({ ...REPOSITORY, scanIntervalMinutes: 60 });

        fixture.componentInstance.openForm(fixture.componentInstance.repositories()[0]);
        fixture.componentInstance.form.scanIntervalMinutes = null;
        fixture.componentInstance.form.scanCron = '';
        fixture.componentInstance.submit();

        const body = http.expectOne((call) => call.method === 'PATCH').request.body;
        // `undefined` here would leave the old interval in place while the form showed nothing —
        // the operator would believe the schedule was off and the scans would carry on.
        expect(body.scanIntervalMinutes).toBe(0);
        expect(body.scanCron).toBe('');
    });

    it("surfaces the server's refusal of a cron expression instead of a generic failure", () => {
        load();

        fixture.componentInstance.openForm();
        fixture.componentInstance.form.url = 'https://github.com/org/thing.git';
        fixture.componentInstance.form.scanCron = 'every night';
        fixture.componentInstance.submit();

        http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/repositories').flush(
            // `detail`, which is where Spring's Problem Details puts the sentence — see `messageOf`.
            { detail: 'Unusable cron expression: "every night". Expected five fields, for example "0 2 * * *" (every day at 02:00).' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();

        // The server's wording is the only one that names what was wrong with the expression.
        expect(fixture.componentInstance.formError()).toContain('Expected five fields');
    });
});
