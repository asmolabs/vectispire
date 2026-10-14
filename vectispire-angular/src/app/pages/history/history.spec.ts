import { provideHttpClient, withXhr } from '@angular/common/http';
import { useEnglish } from '@/app/core/testing/english';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { History } from './history';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The detection-and-triage trail.
 *
 * <p>The screen this suite covers shipped returning 500 on PostgreSQL while six server tests were
 * green on SQLite. Nothing here would have caught that — a portability defect belongs to the
 * integration campaign — but everything else about the page was equally untested: what it does
 * with an empty history, whether an untriaged issue says so, and whether its exports carry a
 * credential.
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

describe('the history screen', () => {
    let fixture: ComponentFixture<History>;
    let http: HttpTestingController;

    const REPOSITORY = asSchema('Repository', {
        id: 5,
        name: 'Arm Libs Spring',
        url: 'ssh://git@example.com/art/arm.git',
        branch: 'master',
        version: '1.17.6',
        projectType: 'maven',
        scanCount: 3,
        lastScanAt: '2026-08-21T05:03:00Z',
        openIssues: 38,
        decisions: 0
    });

    function dossier(decisions: unknown[]): Record<string, unknown> {
        return {
            repository: { ...REPOSITORY, decisions: decisions.length },
            generatedAt: '2026-08-21T09:00:00Z',
            scans: [
                {
                    id: 34,
                    status: 'completed',
                    branch: 'master',
                    version: '1.17.6',
                    projectType: 'maven',
                    createdAt: '2026-08-21T05:03:00Z',
                    durationMs: 130000,
                    findingsCount: 25,
                    newIssuesCount: 0,
                    resolvedIssuesCount: 0,
                    error: null,
                    issues: [
                        {
                            id: 1,
                            type: 'vulnerability',
                            identifier: 'CVE-2026-1234',
                            severity: 'high',
                            packageName: 'openssl',
                            packageVersion: '3.0.1',
                            filePath: null,
                            state: 'open',
                            triageStatus: 'under_review',
                            firstSeenAt: '2026-03-03T08:00:00Z',
                            resolvedAt: null,
                            decisions
                        }
                    ]
                }
            ]
        };
    }

    beforeEach(async () => {
        silenceAnchorNavigation();
        await TestBed.configureTestingModule({
            imports: [History],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();

        useEnglish();
        fixture = TestBed.createComponent(History);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    function load(decisions: unknown[] = []): void {
        http.expectOne('/api/v1/history/repositories').flush([REPOSITORY]);
        fixture.detectChanges();
        // The page opens the most recently scanned target by itself: an empty right-hand side is
        // a click everybody has to make.
        http.expectOne('/api/v1/history/repositories/5').flush(dossier(decisions));
        fixture.detectChanges();
    }

    it('opens the first target rather than waiting for a click', () => {
        load();
        expect(fixture.componentInstance.selectedId()).toBe(5);
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('Arm Libs Spring');
    });

    // Red here, orange on the dashboard: the same high finding changed colour between two screens.
    it('paints a high finding in the colour every screen gives it', () => {
        load();
        const tag = (fixture.nativeElement as HTMLElement).querySelector('tbody p-tag .p-tag, tbody .p-tag');
        expect(tag?.textContent).toContain('High');
        expect(tag?.classList.contains('p-tag-warn')).toBe(true);
    });

    // The dossier opened by itself answered after the one the reader clicked, and replaced it: the
    // card, and the exports that follow it, then described a target nobody had chosen.
    it("shows the dossier clicked last when the previous one's answer comes last", () => {
        const OTHER = { ...REPOSITORY, id: 6, name: 'Billing Gateway' };
        http.expectOne('/api/v1/history/repositories').flush([REPOSITORY, OTHER]);
        fixture.detectChanges();
        const slow = http.expectOne('/api/v1/history/repositories/5');

        const openButtons = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('tbody button'));
        (openButtons[1] as HTMLButtonElement).click();
        fixture.detectChanges();
        http.expectOne('/api/v1/history/repositories/6').flush({ ...dossier([]), repository: OTHER });
        // A request still open would deliver the old dossier now; a cancelled one cannot.
        if (!slow.cancelled) slow.flush(dossier([]));
        fixture.detectChanges();

        const cards = (fixture.nativeElement as HTMLElement).querySelectorAll('p-card');
        const card = cards[cards.length - 1].textContent;
        expect(card).toContain('Billing Gateway');
        expect(card).not.toContain('Arm Libs Spring');
        expect(fixture.componentInstance.selectedId()).toBe(6);
    });

    // A scan's count is of issues, one per fingerprint; its occurrences are another figure, shown on
    // the scan's own page. Called "findings" here, it disagreed with the list that page opens on.
    it("names a scan's count as issues", () => {
        load();
        const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
        expect(text).toContain('25 issues');
        expect(text).toContain('0 new');
        expect(text).not.toContain('25 findings');
    });

    it('says an untriaged backlog is untriaged, rather than showing a zero', () => {
        load();
        // A counter at zero cannot distinguish "nothing was triaged" from "the decisions predate
        // the recording of this history", and those say very different things about the process.
        const text = (fixture.nativeElement as HTMLElement).textContent;
        expect(
            text.includes('No triage decision has been recorded') || text.includes('history.no_decisions_recorded')
        ).toBe(true);
    });

    it('shows a decision with its author and both ends of the transition', () => {
        load([
            {
                fromStatus: 'under_review',
                toStatus: 'not_affected',
                justification: 'vulnerable_code_not_present',
                comment: 'Not compiled in.',
                actor: 'alice',
                origin: 'manual',
                occurredAt: '2026-03-07T14:30:00Z',
                expiresAt: null,
                scanId: 34,
                version: '1.17.6',
                previousResolvedAt: null
            }
        ]);

        const text = (fixture.nativeElement as HTMLElement).textContent;
        expect(text.toLowerCase()).toContain('under review');
        expect(text.toLowerCase()).toContain('not affected');
        expect(text).toContain('alice');
        expect(text).toContain('Not compiled in.');
    });

    it('names a lapse as a lapse instead of crediting a person', () => {
        load([
            {
                fromStatus: 'not_affected',
                toStatus: 'under_review',
                justification: null,
                comment: null,
                actor: null,
                origin: 'expiry',
                occurredAt: '2026-06-07T14:30:00Z',
                expiresAt: null,
                scanId: 34,
                version: '1.17.6',
                previousResolvedAt: null
            }
        ]);

        const text = (fixture.nativeElement as HTMLElement).textContent;
        expect(text.includes('expired automatically') || text.includes('history.expired_auto')).toBe(true);
    });

    it('names a reopening as a scan finding the issue again, with the resolution it ended — not as a lapse', () => {
        load([
            {
                fromStatus: 'fixed',
                toStatus: 'under_review',
                justification: null,
                comment: null,
                actor: null,
                origin: 'reopen',
                occurredAt: '2026-06-07T14:30:00Z',
                expiresAt: null,
                scanId: 35,
                version: '1.17.7',
                previousResolvedAt: '2026-05-02T09:00:00Z'
            }
        ]);

        const text = (fixture.nativeElement as HTMLElement).textContent;
        expect(text.includes('resolved since 02/05/2026') || text.includes('history.reopened_since')).toBe(true);
        expect(text.includes('expired automatically') || text.includes('history.expired_auto')).toBe(false);
    });

    it('exports through HttpClient, because a navigation carries no token', () => {
        load();

        fixture.componentInstance.download('csv');
        const csv = http.expectOne('/api/v1/history/repositories/5/export.csv');
        expect(csv.request.responseType).toBe('blob');
        csv.flush(new Blob(['a,b'], { type: 'text/csv' }));

        fixture.componentInstance.download('pdf');
        const pdf = http.expectOne('/api/v1/history/repositories/5/export.pdf');
        expect(pdf.request.responseType).toBe('blob');
        pdf.flush(new Blob(['%PDF-1.4'], { type: 'application/pdf' }));
    });

    it('shows a failed list in the server’s words, not the generic sentence', () => {
        http.expectOne('/api/v1/history/repositories').flush(
            { title: 'Internal Server Error', status: 500, detail: 'History index is being rebuilt.' },
            { status: 500, statusText: 'Internal Server Error' }
        );
        fixture.detectChanges();

        expect((fixture.nativeElement as HTMLElement).textContent).toContain('History index is being rebuilt.');
    });

    it('shows a failed dossier in the server’s words', () => {
        http.expectOne('/api/v1/history/repositories').flush([REPOSITORY]);
        http.expectOne('/api/v1/history/repositories/5').flush(
            { title: 'Not Found', status: 404, detail: 'Repository 5 is no longer monitored.' },
            { status: 404, statusText: 'Not Found' }
        );
        fixture.detectChanges();

        expect((fixture.nativeElement as HTMLElement).textContent).toContain('Repository 5 is no longer monitored.');
    });
});
