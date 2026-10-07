import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { Router, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { Owasp } from './owasp';
import { asSchema, asSchemaList } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { OwaspScopePicker } from '@/app/shared/owasp-scope-picker';

/**
 * The OWASP screen.
 *
 * <p>Written after three defects that the compiler could not see and no test existed to catch:
 * a report rendered as raw Markdown, a failed run shown as an empty page, and a download that
 * bypassed the interceptor and saved zero bytes. All three are template and wiring behaviour —
 * the kind that only a mounted component reveals.
 */
/**
 * `saveDocument` clicks an anchor to hand the blob to the browser, which is the behaviour under
 * test — but what the DOM does with that click is not. jsdom refused the navigation and printed a
 * stack that would have hidden a genuine error in the same output; happy-dom calls
 * `window.open(href, '_self')`, and all that keeps it from navigating the window the component is
 * mounted in is that vitest builds that window outside happy-dom's `Browser` API. Neither is a
 * browser saving a file, so the click stops here.
 */
function silenceAnchorNavigation(): void {
    HTMLAnchorElement.prototype.click = function click() {};
}

describe('the OWASP report screen', () => {
    let fixture: ComponentFixture<Owasp>;
    let http: HttpTestingController;

    beforeEach(async () => {
        silenceAnchorNavigation();
        await TestBed.configureTestingModule({
            imports: [Owasp],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        // The labels come from the bundle: asserting on unresolved keys would prove `t()` was
        // called and nothing about what a reader sees.
        TestBed.inject(I18nService).translations.set({
            owasp: {
                inputs_title: 'What the model was given',
                inputs_help:
                    'The findings digest handed to the model, kept as it stands. The text below is a ' +
                    'commentary and not a measurement: nothing it asserts becomes an issue, reaches a ' +
                    'gate, or moves a square of the grid.'
            }
        });

        fixture = TestBed.createComponent(Owasp);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        // The constructor asks for the repositories it offers in the picker.
        http.expectOne('/api/v1/repositories').flush(
            asSchemaList('RepositorySummary', [
                {
                    id: 5,
                    displayName: 'Arm Libs Spring',
                    url: 'ssh://git@example.com/art/arm.git',
                    branch: 'master',
                    openIssues: 0,
                    scanManualOnly: false
                }
            ])
        );
        fixture.detectChanges();
    });

    function runProducing(report: Record<string, unknown>): void {
        fixture.componentInstance.selected = 5;
        fixture.componentInstance.run();
        http.expectOne({ method: 'POST', url: '/api/v1/repositories/5/owasp-review' }).flush(
            asSchema('Report', report)
        );
        fixture.detectChanges();
    }

    it('renders the report from blocks, never as raw Markdown', () => {
        runProducing({
            id: 1,
            status: 'completed',
            model: 'gemma4:e4b',
            content: '## A03 — Injection\n\nA finding.',
            blocks: [
                { kind: 'CATEGORY', level: 2, marker: null, text: 'A03 — Injection' },
                { kind: 'PARAGRAPH', level: 0, marker: null, text: 'A finding.' }
            ],
            error: null,
            scanId: 34,
            createdAt: '2026-08-21T07:57:53Z'
        });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('A03 — Injection');
        expect(text).toContain('A finding.');
        // The hashes are typography, not content. Printing them is what the block rendering
        // replaced, and it is invisible to the compiler.
        expect(text).not.toContain('## ');
    });

    it('shows a failed run with its reason instead of an empty page', () => {
        runProducing({
            id: 2,
            status: 'failed',
            model: 'ornith-1.5:9b',
            content: null,
            blocks: [],
            error: 'Ollama: request timed out',
            scanId: 34,
            createdAt: '2026-08-21T07:40:01Z'
        });

        // A run that vanished would leave this page identical to one nobody ever asked for.
        expect(fixture.nativeElement.textContent).toContain('Ollama: request timed out');
    });

    it('a review still being written says so, and renders no report', () => {
        // Recorded before the model is asked: somebody opening the screen while another request
        // waits sees it under way, not an empty report with an export button.
        TestBed.inject(I18nService).translations.set({
            owasp: { running_notice: 'Another request is waiting for the model to write this report.' }
        });
        runProducing({
            id: 4,
            status: 'running',
            model: 'gemma4:e4b',
            content: null,
            blocks: [],
            error: null,
            scanId: 34,
            createdAt: '2026-08-21T07:40:01Z'
        });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Another request is waiting for the model');
    });

    it('offers the PDF only for a report that exists', () => {
        runProducing({
            id: 3,
            status: 'failed',
            model: 'm',
            content: null,
            blocks: [],
            error: 'boom',
            scanId: 34,
            createdAt: '2026-08-21T07:40:01Z'
        });
        // A PDF of "the model could not be reached", under an OWASP cover, would look like a
        // report and say nothing — and a file travels away from the screen that explained it.
        expect(fixture.nativeElement.textContent).not.toContain('Export PDF');

        runProducing({
            id: 4,
            status: 'completed',
            model: 'm',
            content: 'x',
            blocks: [{ kind: 'PARAGRAPH', level: 0, marker: null, text: 'x' }],
            error: null,
            scanId: 34,
            createdAt: '2026-08-21T07:57:53Z'
        });
        const text = fixture.nativeElement.textContent;
        expect(text.includes('Export PDF') || text.includes('owasp.export_pdf')).toBe(true);
    });

    it('downloads through HttpClient, because a navigation carries no token', () => {
        runProducing({
            id: 5,
            status: 'completed',
            model: 'm',
            content: 'x',
            blocks: [{ kind: 'PARAGRAPH', level: 0, marker: null, text: 'x' }],
            error: null,
            scanId: 34,
            createdAt: '2026-08-21T07:57:53Z'
        });

        fixture.componentInstance.downloadPdf();

        // The defect this pins: `window.location.href` is not a request the interceptor sees, so
        // the session token never travels, the server answers 401 and the browser writes the
        // empty error body to disk as a zero-byte file.
        const request = http.expectOne('/api/v1/repositories/5/owasp-review/export.pdf');
        expect(request.request.responseType).toBe('blob');
        request.flush(new Blob(['%PDF-1.4'], { type: 'application/pdf' }));
    });

    it('reports a refusal rather than staying silent', () => {
        fixture.componentInstance.selected = 5;
        fixture.componentInstance.run();
        http.expectOne({ method: 'POST', url: '/api/v1/repositories/5/owasp-review' }).flush(
            { detail: 'Model review is switched off.' },
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();

        expect(fixture.componentInstance.running()).toBe(false);
        expect(fixture.componentInstance.error()).not.toBeNull();
    });

    /**
     * **What the model was given, offered beside what it answered.**
     *
     * A report used to carry its prompt, its model and its scan — and not its input. The prompt is
     * a static instruction; the evidence digest is the half that decides what the prose says, and
     * it cannot be recomputed later because the issues it was built from have moved on. Without it
     * a reader can check when a claim was made and by which model, and nothing about what it was
     * made from.
     */
    it('offers the evidence the model was shown, beside what it wrote', () => {
        runProducing({
            id: 3,
            status: 'completed',
            model: 'gemma4:e4b',
            content: '## A03 — Injection\n\nA finding.',
            blocks: [{ kind: 'CATEGORY', level: 2, marker: null, text: 'A03 — Injection' }],
            error: null,
            scanId: 34,
            inputs: '=== DATA ===\nRepository: basalt-libs\nOpen findings: 2',
            createdAt: '2026-09-17T09:00:00Z'
        });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Repository: basalt-libs');
        // Said where a reader sees it, not only in the code: the prose is a commentary, and nothing
        // it asserts becomes a finding or reaches a gate.
        expect(text).toContain('nothing it asserts becomes an issue');
    });

    it('says nothing about an input a report was stored without', () => {
        // Reports written before the column existed have none. An empty block would invite the
        // reader to conclude the model was shown nothing, which is a different claim.
        runProducing({
            id: 4,
            status: 'completed',
            model: 'gemma4:e4b',
            content: '## A03\n\nA finding.',
            blocks: [{ kind: 'CATEGORY', level: 2, marker: null, text: 'A03' }],
            error: null,
            scanId: 34,
            inputs: null,
            createdAt: '2026-09-17T09:00:00Z'
        });

        expect(fixture.nativeElement.textContent as string).not.toContain('What the model was given');
    });
});

@Component({ selector: 'zs-nowhere', template: '' })
class Nowhere {}

/**
 * The current grid's scope, through a real router and the DOM: the scope lives in the URL, the grid
 * is asked for it, and everything that leaves the grid — a count, the other view — carries it.
 */
describe('the current OWASP grid, over a project or a solution', () => {
    let harness: RouterTestingHarness;
    let http: HttpTestingController;
    const page = () => harness.routeNativeElement as HTMLElement;

    const TREE = {
        solutions: [{ id: 3, name: 'Payments', projects: [{ id: 12, name: 'Gateway' }] }],
        unfiled: { repositoryCount: 0, containerCount: 0, repositories: [] }
    };

    function grid(scope: Record<string, unknown> | null) {
        return asSchema('DeclaredGrid', {
            lines: [
                { id: 'A01', title: 'Broken Access Control', state: 'NOT_COVERED', findings: 0, because: 'x' },
                { id: 'A06', title: 'Vulnerable Components', state: 'FINDINGS', findings: 4, because: 'y' }
            ],
            covered: 9,
            withFindings: 1,
            unmeasured: 0,
            scope
        });
    }

    const GATEWAY = { kind: 'project', id: 12, name: 'Payments / Gateway', partial: false, targetCount: 3 };

    beforeEach(async () => {
        TestBed.configureTestingModule({
            providers: [
                provideHttpClient(withXhr()),
                provideHttpClientTesting(),
                provideRouter([
                    { path: 'owasp', component: Owasp },
                    { path: 'issues', component: Nowhere }
                ])
            ]
        });
        useEnglish();
        http = TestBed.inject(HttpTestingController);
        harness = await RouterTestingHarness.create();
    }, 20_000);

    /**
     * Answers whatever the page asked; returns the parameters of each grid request, in order. The
     * grid answers `answer`, or fails with it when it is an `Error`.
     */
    async function settle(answer: unknown): Promise<URLSearchParams[]> {
        // A scope picked is a navigation, and the grid asks only once it has rendered the new scope.
        await harness.fixture.whenStable();
        harness.detectChanges();
        const asked: URLSearchParams[] = [];
        for (const request of http.match(() => true)) {
            const url = request.request.url;
            if (url === '/api/v1/owasp/coverage') {
                asked.push(new URLSearchParams(request.request.params.toString()));
                if (answer instanceof Error) {
                    request.flush({ detail: answer.message }, { status: 404, statusText: 'Not Found' });
                } else {
                    request.flush(answer as object);
                }
            } else if (url === '/api/v1/solutions') {
                request.flush(TREE);
            } else {
                request.flush([]);
            }
        }
        await harness.fixture.whenStable();
        harness.detectChanges();
        return asked;
    }

    async function open(url: string, answer: unknown): Promise<URLSearchParams> {
        await harness.navigateByUrl(url);
        const asked = await settle(answer);
        expect(asked).toHaveLength(1);
        return asked[0];
    }

    function picker(): OwaspScopePicker {
        return harness.fixture.debugElement.query(By.directive(OwaspScopePicker)).componentInstance as OwaspScopePicker;
    }

    it('asks the estate with no parameter at all when the URL names no scope', async () => {
        const params = await open('/owasp', grid(null));
        expect([...params.keys()]).toEqual([]);
        expect(page().querySelector('[data-testid="grid-scope"]')).toBeNull();
        expect(picker().value()).toBe('estate');
    });

    it('asks the scope the URL names, and shows whose grid it is', async () => {
        const params = await open('/owasp?project_id=12', grid(GATEWAY));
        expect(params.get('project_id')).toBe('12');
        expect(params.has('solution_id')).toBe(false);
        // The picker reads the URL too: a link opened, or a page reloaded, shows the scope it asks.
        expect(picker().value()).toBe('project:12');
        expect(
            picker()
                .options()
                .map((option) => option.label)
        ).toContain('Project: Payments / Gateway');
        const scope = page().querySelector('[data-testid="grid-scope"]')!.textContent;
        expect(scope).toContain('Payments / Gateway');
        expect(scope).not.toContain('you see');
    });

    it('puts a scope picked into the URL, and asks the grid again for it', async () => {
        await open('/owasp', grid(null));
        picker().picked('solution:3');
        const asked = await settle(grid({ ...GATEWAY, kind: 'solution', id: 3, name: 'Payments' }));
        expect(TestBed.inject(Router).url).toBe('/owasp?solution_id=3');
        expect(asked).toHaveLength(1);
        expect(asked[0].get('solution_id')).toBe('3');

        // And back to the estate: the parameter leaves the URL and the request.
        picker().picked('estate');
        const again = await settle(grid(null));
        expect(TestBed.inject(Router).url).toBe('/owasp');
        expect([...again[0].keys()]).toEqual([]);
    });

    it('opens a count on the backlog it counts, in the same scope', async () => {
        await open('/owasp?project_id=12', grid(GATEWAY));
        const links = page().querySelectorAll<HTMLAnchorElement>('[data-testid="grid-open"]');
        // A count only where something was counted: "not covered" opens nothing.
        expect(links).toHaveLength(1);
        const target = new URL(links[0].href);
        expect(target.pathname).toBe('/issues');
        expect(Object.fromEntries(target.searchParams)).toEqual({
            owasp_category: 'A06',
            unsettled: 'true',
            project_id: '12'
        });
        expect(links[0].getAttribute('aria-label')).toBe('4 open issues in A06');
    });

    it('opens a count over the estate with no scope in the link', async () => {
        await open('/owasp', grid(null));
        const target = new URL(page().querySelector<HTMLAnchorElement>('[data-testid="grid-open"]')!.href);
        expect(Object.fromEntries(target.searchParams)).toEqual({ owasp_category: 'A06', unsettled: 'true' });
    });

    it('says when the reader sees only part of the scope, and how much', async () => {
        await open(
            '/owasp?solution_id=3',
            grid({ ...GATEWAY, kind: 'solution', id: 3, partial: true, targetCount: 2 })
        );
        expect(page().querySelector('[data-testid="grid-scope"]')!.textContent).toContain(
            'you see 2 of its targets; every figure covers those'
        );
    });

    it('keeps the scope when switching to the weekly view', async () => {
        await open('/owasp?project_id=12', grid(GATEWAY));
        const weekly = new URL(page().querySelector<HTMLAnchorElement>('[data-testid="view-weekly"]')!.href);
        expect(Object.fromEntries(weekly.searchParams)).toEqual({ view: 'weekly', project_id: '12' });
    });

    it('says a scope it can no longer read, and goes back to the estate on request', async () => {
        await open('/owasp?project_id=99', new Error('Project not found.'));
        const error = page().querySelector('[data-testid="grid-scope-error"]')!;
        expect(error.textContent).toContain('Project not found.');

        error.querySelector<HTMLButtonElement>('button')!.click();
        const asked = await settle(grid(null));
        expect(TestBed.inject(Router).url).toBe('/owasp');
        expect([...asked[0].keys()]).toEqual([]);
        expect(page().querySelector('[data-testid="grid-scope-error"]')).toBeNull();
    });
});
