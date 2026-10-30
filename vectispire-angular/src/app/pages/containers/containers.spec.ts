import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Containers } from './containers';
import type { MonitoredContainer, NewContainer } from '@/app/core/api.models';
import { asSchema, asSchemaList } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';

/**
 * The container list, as cards rather than rows.
 *
 * <p>Same conversion as the repositories, and the same thing to prove: that the card still
 * carries what the row did. A smoke test only says the screen renders.
 */
describe('the container list', () => {
    let fixture: ComponentFixture<Containers>;
    let http: HttpTestingController;

    const CONTAINER = asSchema('ContainerSummary', {
        id: 3,
        imageName: 'nginx',
        reference: 'nginx@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        tag: 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        openIssues: 12,
        registry: null,
        scanIntervalMinutes: null,
        scanCron: null,
        requiredAgentLabel: null,
        scanManualOnly: false,
        lastScan: { id: 18, status: 'completed', createdAt: '2026-08-21T05:03:00Z', error: null }
    });

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Containers],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        useEnglish();
        fixture = TestBed.createComponent(Containers);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    function load(container: MonitoredContainer = CONTAINER): void {
        for (const request of http.match(() => true)) {
            request.flush(
                request.request.url.endsWith('/containers') ? asSchemaList('ContainerSummary', [container]) : []
            );
        }
        fixture.detectChanges();
    }

    it('is a form requiring the image, and sends once however often it is submitted', () => {
        load();
        fixture.componentInstance.openForm();
        fixture.detectChanges();
        expect(document.querySelector<HTMLInputElement>('#image')!.required).toBe(true);
        expect(document.querySelector<HTMLInputElement>('#registry')!.required).toBe(false);

        fixture.componentInstance.form.imageName = 'team/service';
        const form = document.querySelector('form')!;
        form.dispatchEvent(new Event('submit'));
        form.dispatchEvent(new Event('submit'));
        expect(http.match((call) => call.method === 'POST' && call.url === '/api/v1/containers').length).toBe(1);
    });

    it('keeps every field the row carried', () => {
        load();

        const text = (fixture.nativeElement as HTMLElement).textContent;
        expect(text).toContain('nginx');
        expect(text).toContain('12 outstanding');
    });

    it('truncates the reference on screen and keeps it whole on hover', () => {
        load();

        // Sixty characters of hexadecimal would push everything else off a phone, and a digest is
        // read to be compared rather than to be read.
        const shortened = (fixture.nativeElement as HTMLElement).querySelector<HTMLElement>('[title*="sha256:"]');
        expect(shortened).not.toBeNull();
        expect(shortened!.getAttribute('title')).toContain('1234567890abcdef');
        expect(shortened!.textContent.length).toBeLessThan(CONTAINER.reference.length);
    });

    it("links the outstanding count to that image's backlog", () => {
        load();

        const link = (fixture.nativeElement as HTMLElement).querySelector('a[href*="/issues"]');
        expect(link?.getAttribute('href')).toContain('container_id=3');
    });

    it("shows the image's project, linking to its place in the solutions tree", () => {
        load({ ...CONTAINER, projectId: 12, projectName: 'Payments / Ledger' });

        const project = (fixture.nativeElement as HTMLElement).querySelector(
            '[data-testid="container-project"]'
        ) as HTMLElement;
        expect(project.textContent).toContain('Project:');
        const link = project.querySelector('a');
        expect(link?.textContent?.trim()).toBe('Payments / Ledger');
        expect(link?.getAttribute('href')).toBe('/solutions#project-12');
    });

    it('says "no project" of an image in none, and links to that group', () => {
        load({ ...CONTAINER, projectId: null, projectName: null });

        const link = (fixture.nativeElement as HTMLElement).querySelector(
            '[data-testid="container-project"] a'
        ) as HTMLElement;
        expect(link.textContent?.trim()).toBe('no project');
        expect(link.getAttribute('href')).toBe('/solutions#unfiled');
    });

    it('says "nothing outstanding" rather than showing a bare zero', () => {
        load({ ...CONTAINER, openIssues: 0 });
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('nothing outstanding');
    });

    it('says a never-scanned image was never scanned', () => {
        load({ ...CONTAINER, lastScan: null });
        const text = (fixture.nativeElement as HTMLElement).textContent;
        expect(text.includes('Never scanned') || text.includes('scans.never_scanned')).toBe(true);
    });

    it('says an image with no schedule of its own runs on the default, and how often', () => {
        load({ ...CONTAINER, schedule: { mode: 'default', intervalMinutes: 10080 } });
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('weekly (default)');
    });

    it('says an image set to manual only is scanned only when somebody asks', () => {
        load({ ...CONTAINER, scanManualOnly: true, schedule: { mode: 'manual', intervalMinutes: null } });
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('manual only');
    });

    it('says a custom interval in hours rather than in minutes', () => {
        load({ ...CONTAINER, scanIntervalMinutes: 360, schedule: { mode: 'interval', intervalMinutes: 360 } });
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('every 6 h');
    });

    it('shows the expression rather than the interval when both are set, as the scheduler does', () => {
        load({
            ...CONTAINER,
            scanIntervalMinutes: 60,
            scanCron: '0 3 * * *',
            schedule: { mode: 'cron', intervalMinutes: null }
        });
        // Read through the English bundle, so the expression itself is asserted: it can only be
        // reached by the branch that prefers the expression over the interval.
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('cron 0 3 * * *');
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

        const body = http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/containers').request
            .body as NewContainer;
        expect(body.scanIntervalMinutes).toBe(1440);
        expect(body.scanCron).toBe('0 3 * * *');
    });

    it('prefills the dialog from the row being edited, rather than from an empty form', () => {
        load({
            ...CONTAINER,
            registry: 'ghcr.io',
            scanIntervalMinutes: 60,
            scanCron: '0 3 * * *',
            requiredAgentLabel: 'linux-x64'
        });

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
        expect((call.request.body as Partial<NewContainer>).scanCron).toBe('0 3 * * *');
    });

    it('clears an interval with zero, because absent means "leave alone" on the update path', () => {
        load({ ...CONTAINER, scanIntervalMinutes: 60 });

        fixture.componentInstance.openForm(fixture.componentInstance.containers()[0]);
        fixture.componentInstance.form.scanIntervalMinutes = null;
        fixture.componentInstance.form.scanCron = '';
        fixture.componentInstance.submit();

        const body = http.expectOne((call) => call.method === 'PATCH').request.body as Partial<NewContainer>;
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
            {
                detail: 'Unusable cron expression: "nightly". Expected five fields, for example "0 2 * * *" (every day at 02:00).'
            },
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
            {
                detail: 'Unusable cron expression: "nightly". Expected five fields, for example "0 2 * * *" (every day at 02:00).'
            },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();

        expect(fixture.componentInstance.formError()).toContain('Expected five fields');
    });
});

/**
 * The image list while a scan runs, and when it is long: the same defects as the repository list,
 * the overlay raised on every poll tick and no pages.
 */
describe('the container list, refreshed and paged', () => {
    let fixture: ComponentFixture<Containers>;
    let http: HttpTestingController;

    const container = (id: number, status = 'completed') =>
        asSchema('ContainerSummary', {
            id,
            imageName: `image-${id}`,
            reference: `registry.invalid/image-${id}:1.0`,
            tag: '1.0',
            openIssues: 0,
            registry: null,
            scanIntervalMinutes: null,
            scanCron: null,
            requiredAgentLabel: null,
            scanManualOnly: false,
            lastScan: { id: 1000 + id, status, createdAt: '2026-08-21T05:03:00Z', error: null }
        });

    const MANY = Array.from({ length: 45 }, (_, index) => container(index + 1, index === 0 ? 'scanning' : 'completed'));

    beforeEach(async () => {
        vi.useFakeTimers();
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Containers],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
        fixture = TestBed.createComponent(Containers);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        for (const request of http.match(() => true)) {
            request.flush(request.request.url.endsWith('/containers') ? MANY : []);
        }
    });

    afterEach(() => vi.useRealTimers());

    function page(): HTMLElement {
        fixture.detectChanges();
        return fixture.nativeElement as HTMLElement;
    }

    /** The full references on the cards shown (each card's title carries it), in order. */
    function shown(): string[] {
        return [...page().querySelectorAll('[title^="registry.invalid/"]')].map((node) => node.getAttribute('title')!);
    }

    it('raises no overlay on a poll tick, and lets the latest request win', () => {
        vi.advanceTimersByTime(5000);
        const tick = http.expectOne('/api/v1/containers');
        expect(page().querySelector('.p-dataview-loading')).toBeNull();

        fixture.componentInstance.reload();
        expect(tick.cancelled).toBe(true);
        http.expectOne('/api/v1/containers').flush(MANY);
    });

    it('pages by twenty and keeps the page across a refresh', () => {
        expect(shown()).toHaveLength(20);
        page().querySelectorAll<HTMLButtonElement>('.p-paginator-page')[1].click();
        expect(shown()[0]).toBe('registry.invalid/image-21:1.0');

        vi.advanceTimersByTime(5000);
        http.expectOne('/api/v1/containers').flush(MANY);
        expect(shown()[0]).toBe('registry.invalid/image-21:1.0');
    });
});
