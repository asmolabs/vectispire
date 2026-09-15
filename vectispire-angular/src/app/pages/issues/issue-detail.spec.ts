import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { IssueDetailPage } from './issue-detail';
import { SessionStore } from '@/app/core/session.store';
import { I18nService } from '@/app/core/i18n/i18n.service';

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
    };

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [IssueDetailPage],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        // Un compte qui peut agir : le formulaire de rattachement n'est offert qu'à ceux-là,
        // et un auditeur qui le verrait se ferait refuser par le serveur.
        TestBed.inject(SessionStore).open('a-token', {
            username: 'c.moreau', displayName: null, role: 'USER', mustChangePassword: false
        });
        TestBed.inject(I18nService).translations.set({
            common: { save: 'Save', cancel: 'Cancel' },
            issues: {
                ticket: 'Ticket', ticket_none: 'No ticket attached.', ticket_attach: 'Attach a ticket',
                ticket_change: 'Change the reference', ticket_reference: 'Reference',
                ticket_reference_help: '—', ticket_url: 'Link', ticket_synced: 'Closing this ticket can close this finding.',
                ticket_attach_failed: 'The ticket could not be attached.'
            }
        });

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


    it("dit qu'aucun ticket ne suit ce constat, plutôt que de laisser la case vide", async () => {
        await load();

        // « Aucun ticket » et « la carte n'a rien affiché » se ressemblent à l'écran et ne
        // veulent pas dire la même chose ; c'est la phrase qui fait cliquer sur « rattacher ».
        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('No ticket attached.');
        expect(text).toContain('Attach a ticket');
    });

    it('rattache la référence sur le champ que le webhook cherche', async () => {
        await load();

        const page = fixture.componentInstance;
        page.editTicket();
        page.ticketReference = '  SEC-1234  ';
        page.ticketUrl = 'https://tracker.invalid/SEC-1234';
        page.saveTicket();

        const call = http.expectOne('/api/v1/issues/7/ticket');
        expect(call.request.method).toBe('PUT');
        // Rognée ici plutôt que sur le serveur : une référence entourée d'espaces ne serait
        // retrouvée par aucun webhook.
        expect(call.request.body).toEqual({ reference: 'SEC-1234', url: 'https://tracker.invalid/SEC-1234' });
        call.flush({ ...ISSUE, ticketRef: 'SEC-1234', ticketUrl: 'https://tracker.invalid/SEC-1234' });
        fixture.detectChanges();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('SEC-1234');
        expect(text).toContain('Closing this ticket can close this finding.');
        expect(page.editingTicket()).toBe(false);
    });

    it('envoie une URL nulle plutôt que vide, un traqueur interne pouvant ne pas en avoir', async () => {
        await load();

        const page = fixture.componentInstance;
        page.editTicket();
        page.ticketReference = '#87';
        page.saveTicket();

        const call = http.expectOne('/api/v1/issues/7/ticket');
        expect(call.request.body).toEqual({ reference: '#87', url: null });
        call.flush({ ...ISSUE, ticketRef: '#87', ticketUrl: null });
    });

    it("n'envoie rien sur une référence vide, au lieu de faire refuser le geste", async () => {
        await load();

        const page = fixture.componentInstance;
        page.editTicket();
        page.ticketReference = '   ';
        page.saveTicket();

        // Le serveur refuse, et il a raison : un champ vidé par mégarde rendrait le constat
        // invisible au webhook et rouvrirait la porte à un second ticket de la balayeuse.
        http.expectNone('/api/v1/issues/7/ticket');
    });

    it('garde le formulaire ouvert et dit pourquoi quand le serveur refuse', async () => {
        await load();

        const page = fixture.componentInstance;
        page.editTicket();
        page.ticketReference = 'SEC-1234';
        page.saveTicket();
        http.expectOne('/api/v1/issues/7/ticket')
            .flush({ message: 'Issue not found.' }, { status: 404, statusText: 'Not Found' });
        fixture.detectChanges();

        expect(page.editingTicket()).toBe(true);
        expect(page.ticketError()).toContain('Issue not found.');
    });

    it("n'offre pas le rattachement à un compte qui ne peut rien changer", async () => {
        TestBed.inject(SessionStore).open('a-token', {
            username: 'audit', displayName: null, role: 'AUDITOR', mustChangePassword: false
        });
        await load();

        // Offrir une porte que le serveur ferme est pire que ne rien offrir : l'auditeur clique,
        // reçoit un refus, et apprend à se méfier de l'écran.
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
