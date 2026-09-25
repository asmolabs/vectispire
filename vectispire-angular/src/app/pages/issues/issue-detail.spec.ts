import { provideHttpClient, withXhr } from '@angular/common/http';
import { useEnglish } from '@/app/core/testing/english';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { IssueDetailPage } from './issue-detail';
import { SessionStore } from '@/app/core/session.store';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { asSchema } from '@/app/core/testing/contract';

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

    const ISSUE = asSchema('IssueDetail', {
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
        ticketRef: null,
        ticketUrl: null,
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
    });

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [IssueDetailPage],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        // An account that can act: the attach form is offered only to those, and an auditor who saw
        // it would be refused by the server.
        TestBed.inject(SessionStore).open('a-token', {
            username: 'c.moreau',
            displayName: null,
            role: 'USER',
            mustChangePassword: false,
            mfaEnabled: false
        });
        TestBed.inject(I18nService).translations.set({
            common: { save: 'Save', cancel: 'Cancel' },
            issues: {
                ticket: 'Ticket',
                ticket_none: 'No ticket attached.',
                ticket_attach: 'Attach a ticket',
                ticket_change: 'Change the reference',
                ticket_reference: 'Reference',
                ticket_reference_help: '—',
                ticket_url: 'Link',
                ticket_synced: 'Closing this ticket can close this finding.',
                ticket_attach_failed: 'The ticket could not be attached.'
            }
        });

        useEnglish();
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
        // With the shipped bundle loaded the reader's words can be asserted, rather than either an
        // old sentence or the bare key.
        expect(text).toContain('no decision recorded');
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

    it('says no ticket tracks this finding, rather than leaving the box empty', async () => {
        await load();

        // "No ticket" and "the card showed nothing" look alike on screen and do not mean the same
        // thing; it is the sentence that makes somebody click "attach".
        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('No ticket attached.');
        expect(text).toContain('Attach a ticket');
    });

    it('attaches the reference onto the field the webhook looks up', async () => {
        await load();

        const page = fixture.componentInstance;
        page.editTicket();
        page.ticketReference = '  SEC-1234  ';
        page.ticketUrl = 'https://tracker.invalid/SEC-1234';
        page.saveTicket();

        const call = http.expectOne('/api/v1/issues/7/ticket');
        expect(call.request.method).toBe('PUT');
        // Trimmed here rather than on the server: a reference surrounded by spaces would be found
        // by no webhook.
        expect(call.request.body).toEqual({ reference: 'SEC-1234', url: 'https://tracker.invalid/SEC-1234' });
        call.flush({ ...ISSUE, ticketRef: 'SEC-1234', ticketUrl: 'https://tracker.invalid/SEC-1234' });
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('SEC-1234');
        expect(text).toContain('Closing this ticket can close this finding.');
        expect(page.editingTicket()).toBe(false);
    });

    it('sends a null URL rather than an empty one, an internal tracker may have none', async () => {
        await load();

        const page = fixture.componentInstance;
        page.editTicket();
        page.ticketReference = '#87';
        page.saveTicket();

        const call = http.expectOne('/api/v1/issues/7/ticket');
        expect(call.request.body).toEqual({ reference: '#87', url: null });
        call.flush({ ...ISSUE, ticketRef: '#87', ticketUrl: null });
    });

    it('sends nothing for an empty reference, instead of having the move refused', async () => {
        await load();

        const page = fixture.componentInstance;
        page.editTicket();
        page.ticketReference = '   ';
        page.saveTicket();

        // The server refuses, and rightly: a field emptied by mistake would make the finding
        // invisible to the webhook and reopen the door to a second ticket from the sweep.
        http.expectNone('/api/v1/issues/7/ticket');
    });

    it('garde le formulaire ouvert et dit pourquoi quand le serveur refuse', async () => {
        await load();

        const page = fixture.componentInstance;
        page.editTicket();
        page.ticketReference = 'SEC-1234';
        page.saveTicket();
        http.expectOne('/api/v1/issues/7/ticket').flush(
            { message: 'Issue not found.' },
            { status: 404, statusText: 'Not Found' }
        );
        fixture.detectChanges();

        expect(page.editingTicket()).toBe(true);
        expect(page.ticketError()).toContain('Issue not found.');
    });

    it('does not offer the attachment to an account that can change nothing', async () => {
        TestBed.inject(SessionStore).open('a-token', {
            username: 'audit',
            displayName: null,
            role: 'AUDITOR',
            mustChangePassword: false,
            mfaEnabled: false
        });
        await load();

        // Offering a door the server closes is worse than offering nothing: the auditor clicks,
        // gets a refusal, and learns to distrust the screen.
        expect(fixture.componentInstance.canAttach()).toBe(false);
        expect(fixture.nativeElement.textContent).not.toContain('Attach a ticket');
    });

    it('reports a load failure instead of rendering half a page', async () => {
        await Promise.resolve();
        http.expectOne('/api/v1/issues/7').flush(null, { status: 404, statusText: 'Not Found' });
        fixture.detectChanges();

        expect(fixture.componentInstance.issue()).toBeNull();
        expect(fixture.nativeElement.textContent).toContain('could not be loaded');
    });
});
