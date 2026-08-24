import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { IssueDetailPage } from './issue-detail';

/**
 * One issue's detail.
 *
 * <p>The page exists for the two things a backlog row cannot carry — where the issue was seen,
 * and what was decided about it. Both are the answer to a question the row provokes: "is this
 * still in the release we shipped" and "why is this dismissed".
 */
describe('the issue detail', () => {
    let fixture: ComponentFixture<IssueDetailPage>;
    let http: HttpTestingController;

    const ISSUE = {
        id: 7,
        repoId: 5,
        containerId: null,
        targetKind: 'repository',
        targetName: 'Arm Libs Spring',
        type: 'vulnerability',
        identifier: 'CVE-2026-1234',
        severity: 'high',
        packageName: 'openssl',
        packageVersion: '3.0.1',
        purl: null,
        filePath: null,
        line: null,
        cvssScore: 9.1,
        epssScore: null,
        isKev: false,
        fixState: 'fixed',
        fixVersions: '3.0.14',
        link: null,
        description: 'A flaw in the parser.',
        state: 'open',
        firstSeenAt: '2026-03-03T08:00:00Z',
        lastSeenAt: '2026-08-21T05:03:00Z',
        timesSeen: 4,
        triageStatus: 'under_review',
        triageJustification: null,
        triageComment: null,
        triagedBy: null,
        triagedAt: null,
        isDirectDependency: true,
        sightings: [
            {
                scanId: 34,
                status: 'completed',
                branch: 'master',
                version: '1.17.6',
                scannedAt: '2026-08-21T05:03:00Z',
                severity: 'high'
            }
        ],
        decisions: []
    };

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [IssueDetailPage],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(IssueDetailPage);
        fixture.componentRef.setInput('id', '7');
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    async function load(issue: Record<string, unknown> = ISSUE): Promise<void> {
        // The request is queued on a microtask so the required input is set before it fires.
        await Promise.resolve();
        http.expectOne('/api/v1/issues/7').flush(issue);
        fixture.detectChanges();
    }

    it('shows the version each scan read, which is what dates the sighting', async () => {
        await load();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('CVE-2026-1234');
        expect(text).toContain('1.17.6');
        expect(text).toContain('openssl');
    });

    it('says an issue nobody triaged was never decided upon', async () => {
        await load();

        const text = fixture.nativeElement.textContent;
        expect(text.includes('No decision has been recorded') || text.includes('history.no_decision_recorded')).toBe(true);
    });

    it('shows a decision with both ends of the transition', async () => {
        await load({
            ...ISSUE,
            triageStatus: 'not_affected',
            decisions: [
                {
                    fromStatus: 'under_review',
                    toStatus: 'not_affected',
                    justification: 'vulnerable_code_not_present',
                    comment: 'Demonstration application.',
                    actor: 'alice',
                    origin: 'manual',
                    occurredAt: '2026-03-07T14:30:00Z',
                    expiresAt: null,
                    scanId: 34,
                    version: null
                }
            ]
        });

        const text = fixture.nativeElement.textContent as string;
        expect(text.toLowerCase()).toContain('under review');
        expect(text.toLowerCase()).toContain('not affected');
        expect(text).toContain('Demonstration application.');
    });

    it('says "none published" rather than leaving the fix blank', async () => {
        await load({ ...ISSUE, fixVersions: null });

        // The case that needs a human decision is exactly the one an empty cell hides.
        const text = fixture.nativeElement.textContent;
        expect(text.includes('none published') || text.includes('issues.fix_none_published')).toBe(true);
    });

    it('reports a load failure instead of rendering half a page', async () => {
        await Promise.resolve();
        http.expectOne('/api/v1/issues/7').flush(null, { status: 404, statusText: 'Not Found' });
        fixture.detectChanges();

        expect(fixture.componentInstance.issue()).toBeNull();
        expect(fixture.nativeElement.textContent).toContain('could not be loaded');
    });
});
