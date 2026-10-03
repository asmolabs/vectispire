import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting, TestRequest } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type {
    ChecklistOfferedVersion,
    ChecklistProjectContext,
    ChecklistRevisionSummary,
    ChecklistView
} from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import {
    CARRIED_LINE,
    CHECKLIST,
    conflict,
    CONTEXT,
    DRAFT_REVISION,
    EMPTY_CONTEXT,
    LINE_HISTORY,
    OFFERED,
    OPEN_LINE,
    PROJECT_ID,
    READY_CHECKLIST,
    READY_LINE,
    SIGNED_CHECKLIST,
    SIGNED_REVISION,
    SUBMITTED_CHECKLIST
} from '@/app/core/testing/checklists.fixtures';
import { useEnglish } from '@/app/core/testing/english';
import english from '../../../../public/i18n/en.json';
import french from '../../../../public/i18n/fr.json';
import {
    ANSWER_KEYS,
    CONFLICT_KEYS,
    CONFLICT_TYPES,
    EVIDENCE_KIND_KEYS,
    groupsOf,
    incompleteLinesOf,
    PROBLEM_KEYS,
    ProjectChecklist,
    signOffBlockOf,
    STATUS_KEYS
} from './project-checklist';

/**
 * A project's security checklist (decision 0032 §4, §5, §8), through the DOM.
 *
 * What it must get right is who is offered what — the auditor and the platform governor read, the
 * roles that cause effects write, approvers sign off and, under four-eyes, not an author — that
 * every write names the edition on screen and adopts the one it gets back, and that each refusal
 * the server names by its problem type reaches the person as a sentence they can act on.
 */
describe('the project checklist screen', () => {
    let fixture: ComponentFixture<ProjectChecklist>;
    let http: HttpTestingController;

    const BASE = `/api/v1/projects/${PROJECT_ID}/checklists`;

    // A request left open fails its own case; the reset in `finally` keeps it from failing every case
    // after it, which would bury the one that matters under forty that do not.
    afterEach(() => {
        try {
            http?.verify();
        } finally {
            TestBed.resetTestingModule();
        }
    });

    interface Start {
        revisions?: ChecklistRevisionSummary[];
        view?: ChecklistView;
        context?: ChecklistProjectContext;
        offered?: ChecklistOfferedVersion[];
    }

    /** The context the server answers beside the revisions: the newest one's number and edition. */
    const contextOf = (revisions: ChecklistRevisionSummary[]): ChecklistProjectContext =>
        revisions.length === 0
            ? EMPTY_CONTEXT
            : { ...CONTEXT, latestRevision: revisions[0].revision, latestEdition: revisions[0].edition };

    async function start(role: string, username = 'someone', given: Start = {}): Promise<void> {
        const view = given.view ?? CHECKLIST;
        const revisions = given.revisions ?? [view.checklist, SIGNED_REVISION];
        const context = given.context ?? contextOf(revisions);
        await TestBed.configureTestingModule({
            imports: [ProjectChecklist],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        TestBed.inject(SessionStore).open('token', {
            username,
            displayName: null,
            role,
            mustChangePassword: false,
            mfaEnabled: false
        });
        useEnglish();
        fixture = TestBed.createComponent(ProjectChecklist);
        fixture.componentRef.setInput('projectId', String(PROJECT_ID));
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne({ method: 'GET', url: `${BASE}/context` }).flush(context);
        http.expectOne({ method: 'GET', url: BASE }).flush(revisions);
        // The versions a checklist may be opened on or moved to are read for those who write only.
        for (const offered of http.match({ method: 'GET', url: `${BASE}/offered` }))
            offered.flush(given.offered ?? OFFERED);
        if (context.latestRevision !== null) {
            http.expectOne({ method: 'GET', url: `${BASE}/${revisions[0]?.revision ?? context.latestRevision}` }).flush(
                view
            );
        }
        fixture.detectChanges();
    }

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string) => dom().querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';

    /** The `<button>` a `p-button` renders, found by the host's id or by its accessible name. */
    function button(idOrName: string): HTMLButtonElement {
        const host = dom().querySelector(`[id="${idOrName}"]`);
        const found =
            host?.tagName === 'BUTTON'
                ? host
                : (host?.querySelector('button') ??
                  Array.from(dom().querySelectorAll('button')).find(
                      (candidate) =>
                          candidate.getAttribute('aria-label') === idOrName ||
                          candidate.textContent?.trim() === idOrName
                  ));
        if (!found) throw new Error(`no button ${idOrName}`);
        return found as HTMLButtonElement;
    }

    const has = (selector: string) => dom().querySelector(selector) !== null;

    function type(selector: string, value: string): void {
        const input = dom().querySelector(selector) as HTMLInputElement | HTMLTextAreaElement;
        input.value = value;
        input.dispatchEvent(new Event('input'));
        fixture.detectChanges();
    }

    function choose(selector: string, value: string): void {
        const select = dom().querySelector(selector) as HTMLSelectElement;
        const index = Array.from(select.options).findIndex((option) => option.textContent?.trim() === value);
        if (index < 0) throw new Error(`no option ${value} in ${selector}`);
        select.selectedIndex = index;
        select.dispatchEvent(new Event('change'));
        fixture.detectChanges();
    }

    function click(idOrName: string): void {
        button(idOrName).click();
        fixture.detectChanges();
    }

    function tick(selector: string): void {
        (dom().querySelector(selector) as HTMLInputElement).click();
        fixture.detectChanges();
    }

    /** A write's view, one edition on: what every later write must name. */
    const after = (view: ChecklistView, edition: number): ChecklistView => ({
        ...view,
        checklist: { ...view.checklist, edition }
    });

    function post(url: string): TestRequest {
        const request = http.expectOne({ method: 'POST', url });
        return request;
    }

    function refuse(
        request: TestRequest,
        type: string,
        detail = 'An English sentence the screen must not show.',
        members: Record<string, unknown> = {}
    ): void {
        request.flush(
            { type, title: 'Conflict', status: 409, detail, ...members },
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();
    }

    // ------------------------------------------------------------------ roles

    it.each([
        ['AUDITOR', 'reads everything and writes nothing'],
        ['SUPERUSER', 'governs the platform and fills no checklist']
    ])('shows the %s — who %s — every line and no write control', async (role) => {
        await start(role);

        expect(text('[data-testid="line-1"] [data-testid="control"]')).toBe(
            'Service accounts hold no interactive login'
        );
        expect(text('[data-testid="read-only-role"]')).toBe('You read this checklist; your role does not change it.');
        expect(has('[data-testid="acts"]')).toBe(false);
        expect(has('[id="answer-101"]')).toBe(false);
        expect(has('[id="add-evidence-101"]')).toBe(false);
        expect(has('[id="confirm-102"]')).toBe(false);
        expect(dom().querySelector('[data-testid="proof-900"]')?.textContent).not.toContain('Withdraw');
        // The history is read by whoever reads the checklist.
        expect(has('[id="history-101"]')).toBe(true);
        http.expectNone(`${BASE}/offered`);
    });

    it('offers the roles that cause effects the line acts and the revision acts', async () => {
        await start('USER');

        expect(has('[data-testid="read-only-role"]')).toBe(false);
        expect(button('Answer line 3').textContent).toContain('Answer');
        expect(button('Answer line 1').textContent).toContain('Change the answer');
        expect(has('[id="add-evidence-103"]')).toBe(true);
        expect(has('#submit-checklist')).toBe(true);
        expect(has('[data-testid="move"]')).toBe(true);
    });

    it('says a project it cannot show does not exist or is not visible, without telling which', async () => {
        await TestBed.configureTestingModule({
            imports: [ProjectChecklist],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        TestBed.inject(SessionStore).open('token', {
            username: 'erin',
            displayName: null,
            role: 'USER',
            mustChangePassword: false,
            mfaEnabled: false
        });
        useEnglish();
        fixture = TestBed.createComponent(ProjectChecklist);
        fixture.componentRef.setInput('projectId', String(PROJECT_ID));
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne(`${BASE}/context`).flush(
            { type: 'about:blank', title: 'Not Found', status: 404, detail: 'Project not found.' },
            { status: 404, statusText: 'Not Found' }
        );
        // Read beside the context, and dropped with it: one refusal is the answer.
        expect(http.match(BASE).map((request) => request.cancelled)).toEqual([true]);
        fixture.detectChanges();

        expect(text('[data-testid="not-found"]')).toBe(
            "This project does not exist or is not visible to you. A project's checklist is shown only to those who see the whole project."
        );
        expect(has('[data-testid="no-checklist"]')).toBe(false);
    });

    // ------------------------------------------------------------------ opening

    it('offers a writer the published versions when there is no checklist, and opens one naming no edition', async () => {
        await start('USER', 'carol', { revisions: [] });

        expect(text('[data-testid="no-checklist"]')).toContain('This project has no security checklist yet.');
        expect(button('open-checklist').disabled).toBe(true);
        choose('#open-version', 'Release checklist — version 1 (2025 edition)');
        click('open-checklist');

        const request = post(BASE);
        expect(request.request.body).toEqual({ template: 'release', version: 1 });
        request.flush(CHECKLIST, { status: 201, statusText: 'Created' });
        http.expectOne({ method: 'GET', url: BASE }).flush([DRAFT_REVISION]);
        fixture.detectChanges();

        expect(text('[data-testid="notice"]')).toBe('The checklist is open: revision 2.');
        expect(text('[data-testid="shown-revision"]')).toBe('Revision 2');
    });

    it('tells a reader there is no checklist yet, and offers nothing to open', async () => {
        await start('AUDITOR', 'audrey', { revisions: [] });

        expect(text('[data-testid="no-checklist"]')).toContain('Somebody with write access opens one');
        expect(has('#open-version')).toBe(false);
    });

    it.each(['USER', 'AUDITOR'])(
        'names the project from its context before any checklist exists, to %s',
        async (role) => {
            await start(role, 'someone', { revisions: [] });

            expect(has('[data-testid="no-checklist"]')).toBe(true);
            expect(text('h1')).toBe('Security checklist — Gateway');
        }
    );

    it('names the project as its context does, over the name a checklist header carries', async () => {
        await start('USER', 'someone', { context: { ...CONTEXT, projectName: 'Gateway API' } });

        expect(text('[data-testid="project-name"]')).toBe('— Gateway API');
    });

    it('shows no checklist when its context saw none, and opens naming the edition that context read', async () => {
        // A checklist opened between the two reads: the list has it, the context did not. The page
        // offers to open one as the context says, and the server — named no edition — refuses it.
        await start('USER', 'carol', { revisions: [DRAFT_REVISION], context: EMPTY_CONTEXT });

        expect(has('[data-testid="no-checklist"]')).toBe(true);
        choose('#open-version', 'Release checklist — version 1 (2025 edition)');
        click('open-checklist');
        const request = post(BASE);
        expect(request.request.body).toEqual({ template: 'release', version: 1 });
        refuse(request, 'urn:vectispire:problem:checklist-changed');
        expect(text('[data-testid="refusal-message"]')).toContain('The checklist changed since you read it.');
    });

    // ------------------------------------------------------------------ the header and the lines

    it('states the header: template, version, revision, status, author, and the four-eyes rule in force', async () => {
        await start('USER');

        expect(text('[data-testid="header"]')).toContain('Release checklist');
        expect(text('[data-testid="version"]')).toBe('version 1 (2025 edition)');
        expect(text('[data-testid="status"]')).toBe('Draft');
        expect(text('[data-testid="header"]')).toContain('opened from revision 1');
        expect(text('[data-testid="four-eyes"]')).toBe(
            'On: whoever signs it off must have written none of this revision.'
        );
        expect(text('[data-testid="authors"]')).toBe('carol, dave');
    });

    it('groups the lines by domain then objective, and shows each line problems plainly', async () => {
        await start('USER');

        expect(text('[data-testid="domain-0"] h3')).toBe('Access');
        expect(text('[data-testid="domain-1"] h3')).toBe('Supply chain');
        expect(text('[data-testid="domain-1"] h4')).toBe('Known vulnerabilities');
        expect(text('[data-testid="line-1"] [data-testid="problems"]')).toBe('Ready');
        expect(text('[data-testid="line-3"] [data-testid="problems"]')).toBe('Not answered yet');
        expect(text('[data-testid="line-3"]')).toContain('Zero critical');
        expect(text('[data-testid="line-1"]')).toContain('Platform team');
        expect(text('[data-testid="line-2"]')).toContain('A yes needs a link or a file as evidence');
        expect(text('[data-testid="line-2"]')).toContain('a proof holds 12 months');
    });

    it('makes a carried line awaiting confirmation stand out, and confirms it naming the edition', async () => {
        await start('USER');

        expect(text('[data-testid="awaiting-2"]')).toContain('Carried, awaiting confirmation');
        expect(text('[data-testid="line-2"] [data-testid="answer"]')).toContain('carried by dave');
        expect(has('[data-testid="awaiting-1"]')).toBe(false);
        click('Confirm the answer to line 2');

        const request = post(`${BASE}/2/items/102/confirmation`);
        expect(request.request.body).toEqual({ edition: 5 });
        request.flush(after(READY_CHECKLIST, 6), { status: 201, statusText: 'Created' });
        fixture.detectChanges();
        expect(has('[data-testid="awaiting-2"]')).toBe(false);
    });

    // ------------------------------------------------------------------ answering

    it('answers yes without a comment, adopts the view it gets back, and names its edition next', async () => {
        await start('USER');

        click('Answer line 3');
        tick('#answer-103-yes');
        click('save-answer-103');
        const first = post(`${BASE}/2/items/103/answers`);
        expect(first.request.body).toEqual({ value: 'yes', edition: 5 });
        first.flush(after(CHECKLIST, 6), { status: 201, statusText: 'Created' });
        fixture.detectChanges();
        expect(has('[data-testid="answer-form-3"]')).toBe(false);

        // The edition moved on with the write: the next one names 6, not the 5 first read.
        click('Answer line 1');
        tick('#answer-101-yes');
        click('save-answer-101');
        const second = post(`${BASE}/2/items/101/answers`);
        expect(second.request.body).toEqual({ value: 'yes', edition: 6 });
        second.flush(after(CHECKLIST, 7), { status: 201, statusText: 'Created' });
    });

    it('refuses a no without its comment before sending it, and sends it with one', async () => {
        await start('USER');

        click('Answer line 3');
        tick('#answer-103-no');
        click('save-answer-103');
        expect(text('[data-testid="answer-error"]')).toBe('A no or not applicable answer needs a comment saying why.');
        http.expectNone({ method: 'POST', url: `${BASE}/2/items/103/answers` });

        type('#comment-103', 'Two criticals, fix planned.');
        click('save-answer-103');
        const request = post(`${BASE}/2/items/103/answers`);
        expect(request.request.body).toEqual({ value: 'no', comment: 'Two criticals, fix planned.', edition: 5 });
        request.flush(CHECKLIST, { status: 201, statusText: 'Created' });
    });

    it('refuses an answer chosen from nothing', async () => {
        await start('USER');

        click('Answer line 3');
        click('save-answer-103');
        expect(text('[data-testid="answer-error"]')).toBe('Choose an answer.');
        http.expectNone({ method: 'POST', url: `${BASE}/2/items/103/answers` });
    });

    it('offers not applicable only on a version whose importer mapped a word to it, beside the template word', async () => {
        await start('USER');
        click('Answer line 3');
        expect(text('label[for="answer-103-not_applicable"]')).toBe('Not applicable (N/A)');
        expect(text('label[for="answer-103-yes"]')).toBe('Yes (Oui)');
        fixture.destroy();
        http.verify();
        TestBed.resetTestingModule();

        await start('USER', 'someone', {
            view: {
                ...CHECKLIST,
                offersNotApplicable: false,
                answerWords: { yes: 'Oui', no: 'Non', notApplicable: null }
            }
        });
        click('Answer line 3');
        expect(has('#answer-103-not_applicable')).toBe(false);
        expect(has('#answer-103-no')).toBe(true);
    });

    // ------------------------------------------------------------------ evidence

    it('attaches a link with the day the work was done and the edition', async () => {
        await start('USER');

        click('Add evidence to line 2');
        type('#evidence-link-102', 'ftp://files.example.invalid/rotation');
        type('#evidence-day-102', '2026-09-01');
        click('save-evidence-102');
        expect(text('[data-testid="evidence-error"]')).toBe('A link proof is an https: or http: address.');
        http.expectNone({ method: 'POST', url: `${BASE}/2/items/102/evidence/links` });

        type('#evidence-link-102', 'https://wiki.example.invalid/rotation-2026');
        click('save-evidence-102');
        const request = post(`${BASE}/2/items/102/evidence/links`);
        expect(request.request.body).toEqual({
            link: 'https://wiki.example.invalid/rotation-2026',
            performedOn: '2026-09-01',
            edition: 5
        });
        request.flush(CHECKLIST, { status: 201, statusText: 'Created' });
    });

    it('refuses a proof dated in the future before sending it', async () => {
        await start('USER');

        click('Add evidence to line 2');
        type('#evidence-link-102', 'https://wiki.example.invalid/rotation');
        type('#evidence-day-102', '2999-01-01');
        click('save-evidence-102');
        expect(text('[data-testid="evidence-error"]')).toBe(
            'State the day the work was done: a day, and not in the future.'
        );
        http.expectNone({ method: 'POST', url: `${BASE}/2/items/102/evidence/links` });
    });

    function pick(selector: string, file: File): void {
        const input = dom().querySelector(selector) as HTMLInputElement;
        Object.defineProperty(input, 'files', { value: [file], configurable: true });
        input.dispatchEvent(new Event('change'));
        fixture.detectChanges();
    }

    it('attaches a file as the raw body, with its name, day and edition in the query', async () => {
        await start('USER');

        click('Add evidence to line 1');
        tick('#evidence-kind-101-file');
        const report = new File([new Uint8Array([0x25, 0x50, 0x44, 0x46])], 'pentest-2026.pdf', {
            type: 'application/pdf'
        });
        pick('#evidence-file-101', report);
        type('#evidence-day-101', '2026-09-02');
        click('save-evidence-101');

        const request = http.expectOne((call) => call.url === `${BASE}/2/items/101/evidence/files`);
        expect(request.request.body).toBe(report);
        expect(request.request.headers.get('Content-Type')).toBe('application/pdf');
        expect(request.request.params.get('name')).toBe('pentest-2026.pdf');
        expect(request.request.params.get('performedOn')).toBe('2026-09-02');
        expect(request.request.params.get('edition')).toBe('5');
        request.flush(CHECKLIST, { status: 201, statusText: 'Created' });
    });

    it('refuses a file past twenty-five megabytes before sending it, in the words the server uses', async () => {
        await start('USER');

        click('Add evidence to line 1');
        tick('#evidence-kind-101-file');
        pick('#evidence-file-101', new File([new Uint8Array(25 * 1024 * 1024 + 1)], 'huge.pdf'));

        expect(text('[data-testid="evidence-error"]')).toBe(
            'The request body is larger than the 26214400 bytes this route accepts.'
        );
        expect(button('save-evidence-101').disabled).toBe(true);
        http.expectNone((call) => call.method === 'POST');
    });

    it('withdraws a proof naming the edition, and shows a withdrawn one as withdrawn', async () => {
        await start('USER');

        click('Withdraw the evidence https://wiki.example.invalid/rotation');
        const request = post(`${BASE}/2/evidence/900/withdrawal`);
        expect(request.request.body).toEqual({ edition: 5 });
        const withdrawn = {
            ...CHECKLIST.lines[1].evidence[0],
            withdrawnBy: 'dave',
            withdrawnAt: '2026-09-22T09:00:00Z',
            inDate: false
        };
        request.flush({
            ...after(CHECKLIST, 6),
            lines: [CHECKLIST.lines[0], { ...CHECKLIST.lines[1], evidence: [withdrawn] }, CHECKLIST.lines[2]]
        });
        fixture.detectChanges();

        expect(text('[data-testid="proof-900"] [data-testid="withdrawn"]')).toContain('withdrawn by dave');
        expect(text('[data-testid="proof-900"]')).not.toContain('Withdraw ');
    });

    it('downloads a file proof through the client, under its own name, and never opens it in the page', async () => {
        await start('AUDITOR');

        const saved: string[] = [];
        const original = HTMLAnchorElement.prototype.click;
        HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
            saved.push(this.download);
        };
        try {
            click('Download pentest-report.pdf');
            const request = http.expectOne({ method: 'GET', url: `${BASE}/2/evidence/901/file` });
            expect(request.request.responseType).toBe('blob');
            request.flush(new Blob(['%PDF']), {
                headers: { 'Content-Disposition': 'attachment; filename="other.bin"' }
            });
        } finally {
            HTMLAnchorElement.prototype.click = original;
        }
        expect(saved).toEqual(['pentest-report.pdf']);
    });

    // ------------------------------------------------------------------ the document

    /** The names the page gave the anchors it clicked while `act` ran — the files it saved. */
    function savedBy(act: () => void): string[] {
        const saved: string[] = [];
        const original = HTMLAnchorElement.prototype.click;
        HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
            saved.push(this.download);
        };
        try {
            act();
        } finally {
            HTMLAnchorElement.prototype.click = original;
        }
        return saved;
    }

    /** The `<button>` inside a host found by its test id. */
    function inside(testId: string): HTMLButtonElement {
        const found = dom().querySelector(`[data-testid="${testId}"] button`);
        if (!found) throw new Error(`no button in ${testId}`);
        return found as HTMLButtonElement;
    }

    it("calls a draft's document an unsigned rendering, and offers no verification for it", async () => {
        await start('AUDITOR');

        expect(button('download-document').textContent?.trim()).toBe('Download an unsigned rendering');
        expect(text('[data-testid="document-hint"]')).toContain('Draft — not signed off');
        expect(has('[data-testid="verification"]')).toBe(false);
        expect(text('[data-testid="document"]')).not.toContain('cosign');
    });

    it("calls a submitted revision's document unsigned too: only a sign-off is signed", async () => {
        await start('CISO', 'carol', {
            view: SUBMITTED_CHECKLIST,
            revisions: [SUBMITTED_CHECKLIST.checklist, SIGNED_REVISION]
        });

        expect(button('download-document').textContent?.trim()).toBe('Download an unsigned rendering');
        expect(has('[data-testid="verification"]')).toBe(false);
    });

    it("labels each listed revision's download by its own status", async () => {
        await start('AUDITOR');

        expect(inside('download-document-1').getAttribute('aria-label')).toBe(
            'Download the signed package of revision 1'
        );
        expect(inside('download-document-2').getAttribute('aria-label')).toBe(
            'Download an unsigned rendering of revision 2'
        );
    });

    it("downloads the shown revision's document through the client, as a blob, under the server's name", async () => {
        await start('AUDITOR');

        const saved = savedBy(() => {
            click('download-document');
            const request = http.expectOne({ method: 'GET', url: `${BASE}/2/document` });
            expect(request.request.responseType).toBe('blob');
            request.flush(new Blob(['PK']), {
                headers: { 'Content-Disposition': 'attachment; filename="checklist-project-7-revision-2.zip"' }
            });
        });
        expect(saved).toEqual(['checklist-project-7-revision-2.zip']);
    });

    it("downloads a listed revision's document by its own number, not the one shown", async () => {
        await start('AUDITOR');

        const saved = savedBy(() => {
            inside('download-document-1').click();
            fixture.detectChanges();
            http.expectOne({ method: 'GET', url: `${BASE}/1/document` }).flush(new Blob(['PK']));
        });
        // No header read: the name the server gives, built on this side.
        expect(saved).toEqual(['checklist-project-7-revision-1.zip']);
    });

    it("calls a signed-off revision's document a signed package, and shows the guide's verification commands", async () => {
        await start('AUDITOR', 'someone', {
            view: SIGNED_CHECKLIST,
            revisions: [SIGNED_CHECKLIST.checklist, SIGNED_REVISION]
        });

        expect(button('download-document').textContent?.trim()).toBe('Download the signed package');
        const commands = (dom().querySelector('[data-testid="verification-commands"]')?.textContent ?? '').split('\n');
        expect(commands).toEqual([
            `curl -fsS -o vectispire-signing-key.pub "${window.location.origin}/api/v1/crypto/public-key.pub"`,
            'unzip checklist-project-7-revision-2.zip',
            'cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true --signature checklist.xlsx.sig checklist.xlsx',
            'cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true --signature checklist.json.sig checklist.json'
        ]);
        const key = dom().querySelector('[data-testid="public-key-link"]') as HTMLAnchorElement;
        expect(key.getAttribute('href')).toBe('/api/v1/crypto/public-key.pub');
        expect(key.getAttribute('download')).toBe('vectispire-signing-key.pub');
    });

    it('copies the verification commands whole', async () => {
        await start('AUDITOR', 'someone', {
            view: SIGNED_CHECKLIST,
            revisions: [SIGNED_CHECKLIST.checklist, SIGNED_REVISION]
        });
        const writeText = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined);
        try {
            click('Copy the verification commands');
            expect(writeText).toHaveBeenCalledWith(
                dom().querySelector('[data-testid="verification-commands"]')!.textContent
            );
            await Promise.resolve();
            fixture.detectChanges();
            expect(button('Verification commands copied')).toBeTruthy();
        } finally {
            writeText.mockRestore();
        }
    });

    it('answers a refused document as an absence, with a reload, and nothing saved', async () => {
        await start('AUDITOR');

        const saved = savedBy(() => {
            click('download-document');
            http.expectOne({ method: 'GET', url: `${BASE}/2/document` }).flush(new Blob(['{}']), {
                status: 404,
                statusText: 'Not Found'
            });
        });
        fixture.detectChanges();
        expect(saved).toEqual([]);
        expect(text('[data-testid="refusal-message"]')).toBe(
            'The document of revision 2 was not found: the project is no longer visible to you as a whole, or the revision does not exist. Reload the checklist.'
        );
        expect(has('#reload-checklist')).toBe(true);
    });

    it('says a failed download failed, in its own words', async () => {
        await start('AUDITOR');

        click('download-document');
        http.expectOne({ method: 'GET', url: `${BASE}/2/document` }).flush(new Blob(['{}']), {
            status: 500,
            statusText: 'Server Error'
        });
        fixture.detectChanges();
        expect(text('[data-testid="error"]')).toContain('Could not download the document.');
        expect(has('[data-testid="refusal"]')).toBe(false);
    });

    // ------------------------------------------------------------------ history

    it('reads a line history on demand: every answer with who and when, withdrawn proofs included', async () => {
        await start('AUDITOR');

        click('History of line 2');
        http.expectOne({ method: 'GET', url: `${BASE}/2/items/102/history` }).flush(LINE_HISTORY);
        fixture.detectChanges();

        const history = text('[data-testid="history-2"]');
        expect(history).toContain('Answers, oldest first');
        expect(history).toMatch(/No — erin, .*Not yet automated\..*Yes — dave/);
        expect(history).toContain('withdrawn by dave');

        click('History of line 2');
        expect(has('[data-testid="history-2"]')).toBe(false);
    });

    // ------------------------------------------------------------------ automatic answers (0032, 2026-09-29)

    /**
     * Line 3 answered no by Vectispire from a failing measurement, line 1 by a person whose username
     * happens to be "Vectispire", and line 2 carrying no kind at all — a row from before the amendment.
     * Only the kind makes an answer automatic.
     */
    const AUTOMATIC: ChecklistView = {
        ...CHECKLIST,
        lines: [
            { ...READY_LINE, answer: { ...READY_LINE.answer!, answeredBy: 'Vectispire' } },
            { ...CARRIED_LINE, answer: { ...CARRIED_LINE.answer!, answeredByKind: undefined } },
            {
                ...OPEN_LINE,
                problems: [],
                answer: {
                    ...READY_LINE.answer!,
                    id: 703,
                    itemId: 103,
                    value: 'no',
                    comment: 'Measured by Vectispire (secrets): 2 open secrets on 1 repository.',
                    answeredBy: 'Vectispire',
                    answeredByKind: 'system',
                    measurementId: 42
                }
            }
        ]
    };

    it("marks an answer Vectispire wrote by its kind, never by its author's name, and counts them", async () => {
        await start('USER', 'someone', { view: AUTOMATIC });

        expect(has('[data-testid="line-3"] [data-testid="answer-automatic"]')).toBe(true);
        expect(text('[data-testid="line-3"] [data-testid="answer-automatic"]')).toBe(
            'Automatic — measured by Vectispire'
        );
        expect(text('[data-testid="line-3"] [data-testid="answer-author"]')).toMatch(/^· answered by Vectispire, /);
        expect(text('[data-testid="line-3"] [data-testid="answer-comment"]')).toBe(
            'Comment: Measured by Vectispire (secrets): 2 open secrets on 1 repository.'
        );
        // A person called Vectispire is a person; an answer with no kind is a person's.
        expect(has('[data-testid="line-1"] [data-testid="answer-automatic"]')).toBe(false);
        expect(has('[data-testid="line-2"] [data-testid="answer-automatic"]')).toBe(false);
        expect(text('[data-testid="automatic-count"]')).toBe('1 automatic answer');
        // Still a line people answer.
        expect(button('Answer line 3').textContent).toContain('Change the answer');
    });

    it('says no automatic answers are there by saying nothing', async () => {
        await start('USER');

        expect(has('[data-testid="automatic-count"]')).toBe(false);
        expect(has('[data-testid="answer-automatic"]')).toBe(false);
    });

    it('tells whoever answers an automatic line that the answer becomes theirs, and only there', async () => {
        await start('USER', 'someone', { view: AUTOMATIC });

        click('Answer line 1');
        expect(has('[data-testid="takeover-hint"]')).toBe(false);
        click('Answer line 3');
        expect(text('[data-testid="answer-form-3"] [data-testid="takeover-hint"]')).toBe(
            'Answering replaces the automatic answer: the line becomes yours.'
        );
        tick('#answer-103-yes');
        click('save-answer-103');
        const request = post(`${BASE}/2/items/103/answers`);
        expect(request.request.body).toMatchObject({ value: 'yes', edition: 5 });
        request.flush(after(CHECKLIST, 6), { status: 201, statusText: 'Created' });
    });

    it("labels Vectispire's rows in a line history, and says a withdrawal withdrew", async () => {
        await start('AUDITOR', 'someone', { view: AUTOMATIC });

        const system = { ...LINE_HISTORY.answers[1], answeredBy: 'Vectispire', answeredByKind: 'system' as const };
        click('History of line 2');
        http.expectOne({ method: 'GET', url: `${BASE}/2/items/102/history` }).flush({
            ...LINE_HISTORY,
            answers: [
                { ...system, id: 620, answeredAt: '2026-09-21T08:00:00Z' },
                {
                    ...system,
                    id: 621,
                    withdrawn: true,
                    comment: 'Withdrawn by Vectispire: the measurement this answer rested on has no data any more.',
                    answeredAt: '2026-09-22T08:00:00Z'
                },
                { ...LINE_HISTORY.answers[1], id: 622, answeredBy: 'Vectispire', answeredAt: '2026-09-23T08:00:00Z' }
            ]
        });
        fixture.detectChanges();

        expect(text('[data-testid="history-row-620"]')).toMatch(/^Yes · automatic — Vectispire, /);
        expect(text('[data-testid="history-row-621"]')).toMatch(
            /^Automatic answer withdrawn \(no more data\) — Vectispire, .*has no data any more\.$/
        );
        expect(has('[data-testid="history-row-621"] [data-testid="history-automatic"]')).toBe(false);
        // The person named Vectispire answered as a person.
        expect(text('[data-testid="history-row-622"]')).toMatch(/^Yes — Vectispire, /);
    });

    // ------------------------------------------------------------------ submitting

    it('greys out the submission while lines need attention, and names them', async () => {
        await start('USER');

        expect(button('submit-checklist').disabled).toBe(true);
        expect(text('[data-testid="submit-blocked"]')).toBe('Not ready to submit: lines 2, 3 still need attention.');
    });

    it('submits a ready draft naming the edition, and shows it submitted', async () => {
        await start('USER', 'carol', { view: READY_CHECKLIST });

        expect(button('submit-checklist').disabled).toBe(false);
        expect(has('[data-testid="submit-blocked"]')).toBe(false);
        click('submit-checklist');
        const request = post(`${BASE}/2/submission`);
        expect(request.request.body).toEqual({ edition: 5 });
        request.flush(SUBMITTED_CHECKLIST);
        fixture.detectChanges();

        expect(text('[data-testid="notice"]')).toBe('Revision 2 submitted for sign-off.');
        expect(text('[data-testid="status"]')).toBe('Submitted');
        expect(text('[data-testid="revision-2"]')).toContain('Submitted');
        expect(has('[id="answer-101"]')).toBe(false);
    });

    // ------------------------------------------------------------------ each refusal, by its type

    const SENTENCES: [string, string, boolean][] = [
        [
            'checklist-changed',
            'The checklist changed since you read it. Reload it, look at what changed, then try again.',
            true
        ],
        [
            'checklist-line-changed',
            'Somebody else wrote on this line since you read it. Reload the checklist to see their answer or evidence.',
            true
        ],
        [
            'checklist-not-draft',
            'This revision is no longer a draft: it was submitted, signed off or set aside meanwhile. Reload it.',
            true
        ],
        ['checklist-not-submitted', 'This revision is no longer waiting for a sign-off. Reload it.', true],
        ['checklist-not-signed-off', 'Only a signed-off revision is reopened. Reload the checklist.', true],
        [
            'checklist-not-latest',
            'A newer revision of this checklist exists: act on that one. Reload the checklist.',
            true
        ],
        [
            'checklist-four-eyes',
            'Four-eyes approval: you wrote part of this revision, so a second person must sign it off. Written by: carol, dave.',
            false
        ],
        [
            'checklist-version-not-published',
            'That version is no longer published. Reload to see the versions offered.',
            true
        ],
        [
            'checklist-same-version',
            'The checklist is already on that version. After a sign-off, reopen the signed revision to start again on it.',
            true
        ],
        [
            'checklist-nothing-to-confirm',
            'This line no longer has a carried answer awaiting confirmation. Reload the checklist.',
            true
        ],
        ['checklist-evidence-withdrawn', 'That evidence was already withdrawn. Reload the checklist.', true],
        ['checklist-incomplete', 'Not every line is ready any more. Reload the checklist to see which.', true]
    ];

    it.each(SENTENCES)('explains a 409 %s in one sentence of its own', async (token, sentence, reload) => {
        await start('USER', 'carol', { view: READY_CHECKLIST });

        click('submit-checklist');
        refuse(post(`${BASE}/2/submission`), `urn:vectispire:problem:${token}`);

        expect(text('[data-testid="refusal-message"]')).toBe(sentence);
        expect(has('#reload-checklist')).toBe(reload);
    });

    it('names the lines an incomplete refusal is about when the screen shows them', async () => {
        await start('USER');

        // The button is greyed out on this draft; the sign-off meets the same refusal when a proof
        // lapsed since the submission. Called directly to read the sentence built from the lines shown.
        fixture.componentInstance.submit();
        refuse(post(`${BASE}/2/submission`), 'urn:vectispire:problem:checklist-incomplete');
        fixture.detectChanges();

        expect(text('[data-testid="refusal"]')).toContain('Not every line is ready: lines 2, 3 still need attention.');
    });

    const tags = (testId: string) =>
        Array.from(dom().querySelectorAll(`[data-testid="${testId}"] p-tag`)).map((tag) => tag.textContent?.trim());

    /** The `lines` a `checklist-incomplete` names: line 2's proof lapsed, line 3 lost its answer and comment. */
    const INCOMPLETE = conflict('checklist-incomplete', 'line 2 evidence expired; line 3 unanswered', {
        lines: [
            { itemId: 103, position: 3, problems: ['unanswered', 'comment_required'] },
            { itemId: 102, position: 2, problems: ['evidence_expired'] }
        ]
    });

    it('highlights the lines an incomplete refusal names, with their problems in words, over what the view shows', async () => {
        // Every line reads ready on screen: the refusal's lines are the only place the server's say so.
        await start('USER', 'carol', { view: READY_CHECKLIST });

        click('submit-checklist');
        post(`${BASE}/2/submission`).flush(INCOMPLETE, { status: 409, statusText: 'Conflict' });
        fixture.detectChanges();

        expect(text('[data-testid="refusal-message"]')).toBe(
            'Not every line is ready: lines 2, 3 still need attention.'
        );
        expect(text('[data-testid="incomplete-2"] span')).toBe('Refused for this line:');
        expect(tags('incomplete-2')).toEqual(['Evidence out of date']);
        expect(tags('incomplete-3')).toEqual(['Not answered yet', 'Comment required']);
        expect(has('[data-testid="incomplete-1"]')).toBe(false);
        expect(dom().textContent).not.toContain('line 2 evidence expired');
        expect((dom().querySelector('[data-testid="line-2"]') as HTMLElement).style.borderColor).toBe(
            'var(--p-red-500)'
        );

        // Read again, the checklist says for itself where it stands: the refusal's marks go.
        click('reload-checklist');
        http.expectOne({ method: 'GET', url: `${BASE}/context` }).flush(CONTEXT);
        http.expectOne({ method: 'GET', url: BASE }).flush([DRAFT_REVISION, SIGNED_REVISION]);
        http.expectOne({ method: 'GET', url: `${BASE}/offered` }).flush(OFFERED);
        http.expectOne({ method: 'GET', url: `${BASE}/2` }).flush(CHECKLIST);
        fixture.detectChanges();
        expect(has('[data-testid="incomplete-2"]')).toBe(false);
        expect(has('[data-testid="incomplete-3"]')).toBe(false);
    });

    it('highlights the lines a sign-off is refused for once a proof lapsed since the submission', async () => {
        await start('SECURITY_CHAMPION', 'bob', { view: SUBMITTED_CHECKLIST });

        click('sign-off-checklist');
        post(`${BASE}/2/sign-off`).flush(
            conflict('checklist-incomplete', 'line 2 evidence expired', {
                lines: [{ itemId: 102, position: 2, problems: ['evidence_expired'] }]
            }),
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();

        expect(text('[data-testid="refusal-message"]')).toBe('Not every line is ready: line 2 still needs attention.');
        expect(tags('incomplete-2')).toEqual(['Evidence out of date']);
    });

    it('shows a line refusal on the line itself, and reloads the checklist when asked', async () => {
        await start('USER');

        click('Answer line 3');
        tick('#answer-103-yes');
        click('save-answer-103');
        refuse(post(`${BASE}/2/items/103/answers`), 'urn:vectispire:problem:checklist-line-changed');

        expect(text('[data-testid="line-3"] [data-testid="refusal"]')).toContain(
            'Somebody else wrote on this line since you read it.'
        );
        click('reload-checklist');
        http.expectOne({ method: 'GET', url: `${BASE}/context` }).flush({ ...CONTEXT, latestEdition: 7 });
        http.expectOne({ method: 'GET', url: BASE }).flush([DRAFT_REVISION, SIGNED_REVISION]);
        http.expectOne({ method: 'GET', url: `${BASE}/offered` }).flush(OFFERED);
        http.expectOne({ method: 'GET', url: `${BASE}/2` }).flush(after(CHECKLIST, 7));
        fixture.detectChanges();
        expect(has('[data-testid="refusal"]')).toBe(false);
    });

    it("falls back to the server's own sentence for a refusal it names no cause for", async () => {
        await start('USER', 'carol', { view: READY_CHECKLIST });

        click('submit-checklist');
        post(`${BASE}/2/submission`).flush(
            { type: 'about:blank', title: 'Bad Request', status: 400, detail: 'State the edition you read.' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();

        expect(text('[data-testid="refusal-message"]')).toBe('State the edition you read.');
        expect(has('#reload-checklist')).toBe(false);
    });

    // ------------------------------------------------------------------ signing off

    it('greys out the sign-off for an author under four-eyes, and says a second person must give it', async () => {
        await start('CISO', 'Carol', { view: SUBMITTED_CHECKLIST });

        expect(button('sign-off-checklist').disabled).toBe(true);
        expect(text('[data-testid="sign-off-blocked"]')).toBe(
            'Four-eyes approval is on and you wrote part of this revision: a second person must sign it off.'
        );
    });

    it('greys out the sign-off for a role that approves nothing, and says who does', async () => {
        await start('USER', 'erin', { view: SUBMITTED_CHECKLIST });

        expect(button('sign-off-checklist').disabled).toBe(true);
        expect(text('[data-testid="sign-off-blocked"]')).toBe(
            'Signing off is an approval: an administrator, a CISO or a security champion gives it.'
        );
    });

    it('lets an approver who wrote none of it sign off, naming the edition', async () => {
        await start('SECURITY_CHAMPION', 'bob', { view: SUBMITTED_CHECKLIST });

        expect(has('[data-testid="sign-off-blocked"]')).toBe(false);
        click('sign-off-checklist');
        const request = post(`${BASE}/2/sign-off`);
        expect(request.request.body).toEqual({ edition: 8 });
        request.flush(SIGNED_CHECKLIST);
        fixture.detectChanges();

        expect(text('[data-testid="notice"]')).toBe('Revision 2 signed off.');
        expect(text('[data-testid="signed-off"]')).toContain('bob');
        expect(text('[data-testid="four-eyes"]')).toBe('Applied: whoever signed it off wrote none of it.');
    });

    it('lets an author sign off when four-eyes is off', async () => {
        await start('ADMIN', 'carol', { view: { ...SUBMITTED_CHECKLIST, fourEyesRequired: false } });

        expect(button('sign-off-checklist').disabled).toBe(false);
    });

    it('returns a submitted revision with its reason, and refuses one without', async () => {
        await start('USER', 'erin', { view: SUBMITTED_CHECKLIST });

        click('return-checklist');
        click('confirm-return');
        expect(text('[data-testid="return-error"]')).toBe(
            'Say why the checklist is returned: its authors read the reason.'
        );
        http.expectNone({ method: 'POST', url: `${BASE}/2/return` });

        type('#return-reason', 'Line 3 needs its evidence.');
        click('confirm-return');
        const request = post(`${BASE}/2/return`);
        expect(request.request.body).toEqual({ reason: 'Line 3 needs its evidence.', edition: 8 });
        request.flush(READY_CHECKLIST);
        fixture.detectChanges();
        expect(text('[data-testid="notice"]')).toBe('Revision 2 returned to its authors, a draft again.');
    });

    // ------------------------------------------------------------------ reopening, moving, earlier revisions

    it('reopens a signed-off revision as the next one, naming its edition', async () => {
        await start('USER', 'erin', { view: SIGNED_CHECKLIST });

        expect(has('#submit-checklist')).toBe(false);
        click('reopen-checklist');
        const request = post(`${BASE}/2/reopen`);
        expect(request.request.body).toEqual({ edition: 9 });
        const reopened = {
            ...READY_CHECKLIST,
            checklist: { ...DRAFT_REVISION, revision: 3, edition: 1, supersedesRevision: 2 }
        };
        request.flush(reopened, { status: 201, statusText: 'Created' });
        http.expectOne({ method: 'GET', url: BASE }).flush([reopened.checklist, SIGNED_CHECKLIST.checklist]);
        fixture.detectChanges();

        expect(text('[data-testid="notice"]')).toBe('Revision 3 opened from the signed-off revision.');
        expect(text('[data-testid="shown-revision"]')).toBe('Revision 3');
    });

    it('moves the checklist to another published version, naming the newest revision edition', async () => {
        await start('USER');

        const options = Array.from((dom().querySelector('#move-version') as HTMLSelectElement).options).map((option) =>
            option.textContent?.trim()
        );
        // The version it is on is not offered: moving onto it is refused.
        expect(options).toEqual(['—', 'Release checklist — version 2 (2026 edition)']);
        choose('#move-version', 'Release checklist — version 2 (2026 edition)');
        click('move-checklist');

        const request = post(BASE);
        expect(request.request.body).toEqual({ template: 'release', version: 2, edition: 5 });
        const moved = { ...CHECKLIST, checklist: { ...DRAFT_REVISION, revision: 3, edition: 1, versionOrdinal: 2 } };
        request.flush(moved, { status: 201, statusText: 'Created' });
        http.expectOne({ method: 'GET', url: BASE }).flush([moved.checklist]);
        fixture.detectChanges();
        expect(text('[data-testid="notice"]')).toBe('Revision 3 opened on version 2.');
    });

    /** The `cells` member of a `checklist-version-unrenderable` refusal: a shared master and an array formula. */
    const UNRENDERABLE = {
        cells: [
            { cell: 'G7', kind: 'shared', range: 'G7:G9' },
            { cell: 'B3', kind: 'array', range: 'B3:C3' }
        ]
    };
    const UNRENDERABLE_SENTENCE =
        'No sign-off could fill in the workbook of the version you chose, so nothing was opened or moved: cells Vectispire writes into hold a formula other cells depend on — G7 (the master of a formula shared across G7:G9), B3 (an array formula over B3:C3). The version was published before Vectispire checked for this, and a published version never changes. Ask whoever manages the checklist templates to publish a corrected version, then open or move the checklist onto that one; a checklist already on this version can still be moved away from it.';

    it('names the cells of a version no sign-off could fill in when the checklist is moved to it, and moves nothing', async () => {
        await start('USER');

        choose('#move-version', 'Release checklist — version 2 (2026 edition)');
        click('move-checklist');
        refuse(post(BASE), 'urn:vectispire:problem:checklist-version-unrenderable', undefined, UNRENDERABLE);

        expect(text('[data-testid="refusal-message"]')).toBe(UNRENDERABLE_SENTENCE);
        // A published version's workbook never changes: reloading would show the same refusal again.
        expect(has('#reload-checklist')).toBe(false);
        expect(text('[data-testid="shown-revision"]')).toBe('Revision 2');
        http.expectNone({ method: 'GET', url: BASE });
    });

    it('names the cells when the first checklist is opened on such a version', async () => {
        await start('USER', 'carol', { revisions: [] });

        choose('#open-version', 'Release checklist — version 1 (2025 edition)');
        click('open-checklist');
        refuse(post(BASE), 'urn:vectispire:problem:checklist-version-unrenderable', undefined, UNRENDERABLE);

        expect(text('[data-testid="refusal-message"]')).toBe(UNRENDERABLE_SENTENCE);
        expect(has('[data-testid="no-checklist"]')).toBe(true);
    });

    it("shows such a refusal naming no cell in the server's own words", async () => {
        await start('USER');

        choose('#move-version', 'Release checklist — version 2 (2026 edition)');
        click('move-checklist');
        refuse(
            post(BASE),
            'urn:vectispire:problem:checklist-version-unrenderable',
            'Version 2 of "release" cannot be signed off.'
        );

        expect(text('[data-testid="refusal-message"]')).toBe('Version 2 of "release" cannot be signed off.');
    });

    /** The second version as 0.10.0 published it: no sign-off could fill it in, and the list says so. */
    const OFFERED_UNRENDERABLE: ChecklistOfferedVersion[] = [
        OFFERED[0],
        { ...OFFERED[1], unrenderable: { detail: 'Version 2 of "release" cannot be signed off.', ...UNRENDERABLE } }
    ] as ChecklistOfferedVersion[];

    it('offers a version no sign-off could fill in disabled, saying why and naming its cells', async () => {
        await start('USER', 'someone', { offered: OFFERED_UNRENDERABLE });

        const moving = Array.from(dom().querySelectorAll<HTMLOptionElement>('#move-version option'));
        const version2 = moving.find((one) => one.textContent?.includes('version 2'));
        expect(version2?.disabled).toBe(true);
        expect(version2?.textContent?.trim()).toBe(
            'Release checklist — version 2 (2026 edition) — cannot be signed off'
        );
        expect(text('[data-testid="move-unrenderable"]')).toBe(
            'Release checklist — version 2 (2026 edition) cannot be chosen: no sign-off could fill its workbook in, since cells Vectispire writes into hold a formula other cells depend on — G7 (the master of a formula shared across G7:G9), B3 (an array formula over B3:C3). It was published before Vectispire checked for this, and a published version never changes: ask whoever manages the checklist templates to publish a corrected version.'
        );
    });

    it('offers the first checklist the versions a sign-off can fill in, and the other one disabled', async () => {
        await start('USER', 'carol', { revisions: [], offered: OFFERED_UNRENDERABLE });

        const opening = Array.from(dom().querySelectorAll<HTMLOptionElement>('#open-version option'));
        expect(opening.map((one) => one.disabled)).toEqual([false, false, true]);
        expect(dom().querySelectorAll('[data-testid="open-unrenderable"]')).toHaveLength(1);
    });

    it("says why in the server's words when the version is refused for another reason than a formula", async () => {
        const other = [
            OFFERED[0],
            { ...OFFERED[1], unrenderable: { detail: 'The sheet "Checklist" is missing.', cells: [] } }
        ] as ChecklistOfferedVersion[];
        await start('USER', 'carol', { revisions: [], offered: other });

        expect(text('[data-testid="open-unrenderable"]')).toBe(
            'Release checklist — version 2 (2026 edition) cannot be chosen: no sign-off could fill its workbook in. The sheet "Checklist" is missing.'
        );
    });

    it('offers every version alike when none is unrenderable', async () => {
        await start('USER', 'carol', { revisions: [] });

        const opening = Array.from(dom().querySelectorAll<HTMLOptionElement>('#open-version option'));
        expect(opening.some((one) => one.disabled)).toBe(false);
        expect(has('[data-testid="open-unrenderable"]')).toBe(false);
    });

    it('lists the earlier revisions and reads one, read-only', async () => {
        await start('USER');

        expect(text('[data-testid="revision-1"]')).toContain('Signed off');
        click('Read revision 1');
        http.expectOne({ method: 'GET', url: `${BASE}/1` }).flush({ ...SIGNED_CHECKLIST, checklist: SIGNED_REVISION });
        fixture.detectChanges();

        expect(text('[data-testid="shown-revision"]')).toBe('Revision 1');
        expect(text('[data-testid="read-only-old"]')).toBe(
            'An earlier revision, shown as it stands: it is never changed again.'
        );
        expect(has('[data-testid="acts"]')).toBe(false);
        expect(has('[id="answer-101"]')).toBe(false);
    });
});

describe('the project checklist, by its rules', () => {
    it('groups by domain then objective in the order of the positions', () => {
        const groups = groupsOf([...CHECKLIST.lines].reverse());
        expect(groups.map((group) => group.domain)).toEqual(['Access', 'Supply chain']);
        expect(groups[0].objectives[0].lines.map((line) => line.position)).toEqual([1, 2]);
    });

    it('blocks the sign-off for a non-approver, and for an author under four-eyes only, compared without case', () => {
        expect(signOffBlockOf(SUBMITTED_CHECKLIST, false, 'bob')).toBe('not_approver');
        expect(signOffBlockOf(SUBMITTED_CHECKLIST, true, ' CAROL ')).toBe('four_eyes');
        expect(signOffBlockOf(SUBMITTED_CHECKLIST, true, 'bob')).toBeNull();
        expect(signOffBlockOf({ ...SUBMITTED_CHECKLIST, fourEyesRequired: false }, true, 'carol')).toBeNull();
    });

    it('reads the lines an incomplete refusal names, and nothing from one that names none it can read', () => {
        expect(incompleteLinesOf({ error: conflict('checklist-incomplete', 'x', { lines: [] }) })).toBeNull();
        expect(incompleteLinesOf({ error: conflict('checklist-incomplete') })).toBeNull();
        expect(incompleteLinesOf({ error: 'text' })).toBeNull();
        expect(incompleteLinesOf(null)).toBeNull();
        expect(
            incompleteLinesOf({
                error: conflict('checklist-incomplete', 'x', {
                    lines: [
                        { itemId: '102', position: 2, problems: ['unanswered'] },
                        { itemId: 103, position: 3, problems: 'unanswered' },
                        { itemId: 104, position: 4, problems: [4] },
                        { itemId: 101, position: 1, problems: ['comment_required'] }
                    ]
                })
            })
        ).toEqual([{ itemId: 101, position: 1, problems: ['comment_required'] }]);
    });

    it('knows every cause the server names, and no other', () => {
        // `ChecklistConflict.Cause`, token for token — a cause added there and not here falls back to
        // the English detail, which is survivable; a token misspelt here never matches, which is not.
        expect(Object.keys(CONFLICT_TYPES).sort()).toEqual(
            [
                'changed',
                'line-changed',
                'not-draft',
                'not-submitted',
                'not-signed-off',
                'not-latest',
                'incomplete',
                'four-eyes',
                'version-not-published',
                'same-version',
                'version-unrenderable',
                'nothing-to-confirm',
                'evidence-withdrawn',
                'measurement-contradicted',
                'measurement-changed'
            ]
                .map((token) => `urn:vectispire:problem:checklist-${token}`)
                .sort()
        );
    });

    it('has every mapped key in both bundles — the i18n check cannot see them', () => {
        const lookup = (bundle: unknown, key: string) =>
            key
                .split('.')
                .reduce<unknown>((node, part) => (node as Record<string, unknown> | undefined)?.[part], bundle);
        // A message counting its lines is a pair, `_one` and `_other`, asked for by its stem.
        const kind = (bundle: unknown, key: string) =>
            typeof lookup(bundle, key) === 'string' ||
            (typeof lookup(bundle, `${key}_one`) === 'string' && typeof lookup(bundle, `${key}_other`) === 'string')
                ? 'string'
                : 'missing';
        const keys = [
            ...Object.values(STATUS_KEYS),
            ...Object.values(ANSWER_KEYS),
            ...Object.values(PROBLEM_KEYS),
            ...Object.values(EVIDENCE_KIND_KEYS),
            ...Object.values(CONFLICT_KEYS)
        ];
        for (const key of keys) {
            expect(kind(english, key), `${key} in en.json`).toBe('string');
            expect(kind(french, key), `${key} in fr.json`).toBe('string');
        }
    });
});
