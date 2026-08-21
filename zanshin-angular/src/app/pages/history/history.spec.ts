import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { History } from './history';

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
 * jsdom refuses a real navigation and prints a stack for it. `saveDocument` clicks an anchor to
 * hand the blob to the browser, which is the behaviour under test — the noise is the environment
 * saying it is not a browser, and left in it would hide a genuine error in the same output.
 */
function silenceAnchorNavigation(): void {
    HTMLAnchorElement.prototype.click = function click() {};
}

describe('the history screen', () => {
    let fixture: ComponentFixture<History>;
    let http: HttpTestingController;

    const REPOSITORY = {
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
    };

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
            providers: [provideHttpClient(), provideHttpClientTesting()]
        }).compileComponents();

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
        expect(fixture.nativeElement.textContent).toContain('Arm Libs Spring');
    });

    it('says an untriaged backlog is untriaged, rather than showing a zero', () => {
        load();
        // A counter at zero cannot distinguish "nothing was triaged" from "the decisions predate
        // the recording of this history", and those say very different things about the process.
        expect(fixture.nativeElement.textContent).toContain('No triage decision has been recorded');
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
                version: '1.17.6'
            }
        ]);

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Under review');
        expect(text).toContain('Not affected');
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
                version: '1.17.6'
            }
        ]);

        expect(fixture.nativeElement.textContent).toContain('expired automatically');
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
});
