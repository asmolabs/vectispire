import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Containers } from './containers';

/**
 * The container list, as cards rather than rows.
 *
 * <p>Same conversion as the repositories, and the same thing to prove: that the card still
 * carries what the row did. A smoke test only says the screen renders.
 */
describe('the container list', () => {
    let fixture: ComponentFixture<Containers>;
    let http: HttpTestingController;

    const CONTAINER = {
        id: 3,
        imageName: 'nginx',
        reference: 'nginx@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        tag: 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        openIssues: 12,
        lastScan: { id: 18, status: 'completed', createdAt: '2026-08-21T05:03:00Z', error: null }
    };

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Containers],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Containers);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    function load(container: Record<string, unknown> = CONTAINER): void {
        for (const request of http.match(() => true)) {
            request.flush(request.request.url.endsWith('/containers') ? [container] : []);
        }
        fixture.detectChanges();
    }

    it('keeps every field the row carried', () => {
        load();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('nginx');
        expect(text).toContain('12 outstanding');
    });

    it('truncates the reference on screen and keeps it whole on hover', () => {
        load();

        // Sixty characters of hexadecimal would push everything else off a phone, and a digest is
        // read to be compared rather than to be read.
        const shortened = fixture.nativeElement.querySelector('[title*="sha256:"]');
        expect(shortened).not.toBeNull();
        expect(shortened.getAttribute('title')).toContain('1234567890abcdef');
        expect(shortened.textContent.length).toBeLessThan(CONTAINER.reference.length);
    });

    it("links the outstanding count to that image's backlog", () => {
        load();

        const link = fixture.nativeElement.querySelector('a[href*="/issues"]');
        expect(link.getAttribute('href')).toContain('container_id=3');
    });

    it('says "nothing outstanding" rather than showing a bare zero', () => {
        load({ ...CONTAINER, openIssues: 0 });
        expect(fixture.nativeElement.textContent).toContain('nothing outstanding');
    });

    it('says a never-scanned image was never scanned', () => {
        load({ ...CONTAINER, lastScan: null });
        expect(fixture.nativeElement.textContent).toContain('Never scanned');
    });

    it('says an image with no schedule is scanned only when somebody asks', () => {
        load();
        expect(fixture.nativeElement.textContent).toContain('manual only');
    });

    it('shows the expression rather than the interval when both are set, as the scheduler does', () => {
        load({ ...CONTAINER, scanIntervalMinutes: 60, scanCron: '0 3 * * *' });
        expect(fixture.nativeElement.textContent).toContain('cron 0 3 * * *');
    });

    /**
     * The schedule on the wire.
     *
     * <p>Fixable now, on `PATCH /api/v1/containers/{id}`. It was not: create, scan and delete were
     * the whole surface, so a wrong cron field was corrected by deleting the row — and its scan
     * history and its triaged backlog with it.
     */
    it('sends the schedule when an image is added', () => {
        load();

        fixture.componentInstance.openForm();
        fixture.componentInstance.form.imageName = 'team/service';
        fixture.componentInstance.form.scanIntervalMinutes = 1440;
        fixture.componentInstance.form.scanCron = '0 3 * * *';
        fixture.componentInstance.submit();

        const body = http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/containers').request.body;
        expect(body.scanIntervalMinutes).toBe(1440);
        expect(body.scanCron).toBe('0 3 * * *');
    });

    it('prefills the dialog from the row being edited, rather than from an empty form', () => {
        load({ ...CONTAINER, registry: 'ghcr.io', scanIntervalMinutes: 60, scanCron: '0 3 * * *', requiredAgentLabel: 'linux-x64' });

        fixture.componentInstance.openForm(fixture.componentInstance.containers()[0]);

        // On a route whose absent fields mean "leave alone", a box the dialog left empty is a
        // value the operator cannot see and will not think to preserve.
        expect(fixture.componentInstance.form.registry).toBe('ghcr.io');
        expect(fixture.componentInstance.form.requiredAgentLabel).toBe('linux-x64');
        expect(fixture.componentInstance.form.scanCron).toBe('0 3 * * *');
        expect(fixture.componentInstance.form.scanIntervalMinutes).toBe(60);
    });

    it('patches the row rather than adding a second one, so the scan history stays attached', () => {
        load();

        fixture.componentInstance.openForm(fixture.componentInstance.containers()[0]);
        fixture.componentInstance.form.scanCron = '0 3 * * *';
        fixture.componentInstance.submit();

        const call = http.expectOne((request) => request.method === 'PATCH');
        expect(call.request.url).toBe('/api/v1/containers/3');
        expect(call.request.body.scanCron).toBe('0 3 * * *');
    });

    it('clears an interval with zero, because absent means "leave alone" on the update path', () => {
        load({ ...CONTAINER, scanIntervalMinutes: 60 });

        fixture.componentInstance.openForm(fixture.componentInstance.containers()[0]);
        fixture.componentInstance.form.scanIntervalMinutes = null;
        fixture.componentInstance.form.scanCron = '';
        fixture.componentInstance.submit();

        const body = http.expectOne((call) => call.method === 'PATCH').request.body;
        // `undefined` here would leave the old interval in place while the form showed nothing —
        // the operator would believe the rescan was off and the registry would carry on being
        // pulled. The empty cron needs no such trick: the server distinguishes it from absent.
        expect(body.scanIntervalMinutes).toBe(0);
        expect(body.scanCron).toBe('');
    });

    it("surfaces the server's refusal of a cron expression when saving an edit too", () => {
        load();

        fixture.componentInstance.openForm(fixture.componentInstance.containers()[0]);
        fixture.componentInstance.form.scanCron = 'nightly';
        fixture.componentInstance.submit();

        http.expectOne((call) => call.method === 'PATCH').flush(
            // `detail`, which is where Spring's Problem Details puts the sentence — see `messageOf`.
            { detail: 'Unusable cron expression: "nightly". Expected five fields, for example "0 2 * * *" (every day at 02:00).' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();

        expect(fixture.componentInstance.formError()).toContain('Expected five fields');
    });

    it("surfaces the server's refusal of a cron expression instead of a generic failure", () => {
        load();

        fixture.componentInstance.openForm();
        fixture.componentInstance.form.imageName = 'team/service';
        fixture.componentInstance.form.scanCron = 'nightly';
        fixture.componentInstance.submit();

        http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/containers').flush(
            { detail: 'Unusable cron expression: "nightly". Expected five fields, for example "0 2 * * *" (every day at 02:00).' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();

        expect(fixture.componentInstance.formError()).toContain('Expected five fields');
    });
});
