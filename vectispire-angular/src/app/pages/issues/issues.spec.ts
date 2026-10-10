import { provideHttpClient, withXhr } from '@angular/common/http';
import { useEnglish } from '@/app/core/testing/english';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router, convertToParamMap, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from '../../core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
import { Issues } from './issues';
import { asSchema, asSchemaList } from '@/app/core/testing/contract';
import { threeWeeks } from '@/app/core/testing/owasp-weekly.fixtures';
import { openLink, openedLink, reopenedLink, resolvedLink } from '@/app/shared/owasp-weekly';

/**
 * The backlog.
 *
 * <p>The one screen with real volume, and therefore the one where paging is not decoration: it
 * asks the server for a window and says which window it is showing. A page that silently
 * displayed the first fifty of two hundred would read as a backlog of fifty.
 */
describe('the issue backlog', () => {
    let fixture: ComponentFixture<Issues>;
    let http: HttpTestingController;

    function issue(id: number, identifier: string): Record<string, unknown> {
        return asSchema('BacklogEntry', {
            id,
            repoId: 5,
            containerId: null,
            targetKind: 'repository',
            targetName: 'Arm Libs Spring',
            type: 'vulnerability',
            identifier,
            severity: 'high',
            packageName: 'openssl',
            packageVersion: '3.0.1',
            state: 'open',
            firstSeenAt: '2026-03-03T08:00:00Z',
            lastSeenAt: '2026-08-21T05:03:00Z',
            timesSeen: 1,
            triageStatus: 'under_review',
            isKev: false
        });
    }

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Issues],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        useEnglish();
        fixture = TestBed.createComponent(Issues);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        // The filters offer target names, so the page fetches both target kinds.
        http.expectOne((call) => call.url === '/api/v1/repositories').flush([]);
        http.expectOne((call) => call.url === '/api/v1/containers').flush([]);

        // And the model's availability, which decides whether the explain button exists. A model is
        // configured by default in these runs: its absence has a case of its own.
        http.expectOne((call) => call.url === '/api/v1/ai-advisor/status').flush({
            enabled: true,
            selectedModel: 'llama3',
            availableModels: ['llama3']
        });
    }, 20_000);

    function firstPage(total: number): void {
        http.expectOne((call) => call.url === '/api/v1/issues').flush({
            items: [issue(1, 'CVE-2026-1234')],
            total,
            limit: 50,
            offset: 0
        });
        fixture.detectChanges();
    }

    it('says which window of the backlog it is showing', () => {
        firstPage(228);

        // Without this, fifty rows out of two hundred read as a backlog of fifty.
        expect(fixture.componentInstance.pageLabel()).toBe('1–50 of 228');
        expect(fixture.nativeElement.textContent).toContain('1–50 of 228');
    });

    /**
     * **Provenance is read on the row** (decision 0017): an auditor scanning the backlog must tell
     * "analysed by Vectispire" from "declared by a CI" without opening each issue, and filter by it.
     */
    it('offers the plugin and imported types in the filter, and names where each row came from', () => {
        const values = fixture.componentInstance.types().map((option) => option.value);
        expect(values).toContain('plugin');
        expect(values).toContain('imported');

        http.expectOne((call) => call.url === '/api/v1/issues').flush({
            items: [
                {
                    ...issue(1, 'acme.no-internal-http'),
                    type: 'plugin',
                    tool: 'plugin:acme-lint',
                    toolName: 'acme-lint',
                    toolVersion: '1.4.0'
                },
                {
                    ...issue(2, 'java:S2076'),
                    type: 'imported',
                    tool: 'import:payments-ci/sonarqube',
                    toolName: 'SonarQube',
                    toolVersion: '10.6',
                    importSource: 'payments-ci'
                }
            ].map((row) => asSchema('BacklogEntry', row)),
            total: 2,
            limit: 50,
            offset: 0
        });
        fixture.detectChanges();

        const rows = Array.from(
            (fixture.nativeElement as HTMLElement).querySelectorAll('[data-testid="issue-provenance"]')
        ).map((cell) => cell.textContent?.trim());
        expect(rows).toEqual(['analysed by Vectispire · acme-lint', 'declared by payments-ci · SonarQube']);
        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Plugin (analysed by Vectispire)');
        expect(text).toContain('Imported (declared by CI)');
    });

    it('sends the chosen type to the server', () => {
        firstPage(1);
        fixture.componentInstance.type = 'imported';
        fixture.componentInstance.reload(0);
        const request = http.expectOne((call) => call.url === '/api/v1/issues');
        expect(request.request.params.get('type')).toBe('imported');
        request.flush({ items: [], total: 0, limit: 50, offset: 0 });
    });

    it('asks the server for the next window rather than slicing what it holds', () => {
        firstPage(228);

        fixture.componentInstance.reload(50);
        const next = http.expectOne((call) => call.url === '/api/v1/issues');
        expect(next.request.urlWithParams).toContain('offset=50');
        next.flush({ items: [issue(2, 'CVE-2026-9999')], total: 228, limit: 50, offset: 50 });
        fixture.detectChanges();

        expect(fixture.componentInstance.pageLabel()).toBe('51–100 of 228');
    });

    it('links each row to its detail', () => {
        firstPage(1);

        const link = fixture.nativeElement.querySelector('a[href="/issues/1"]');
        expect(link).not.toBeNull();
        expect(link.textContent).toContain('CVE-2026-1234');
    });

    it('says "no result" rather than showing an empty frame', () => {
        http.expectOne((call) => call.url === '/api/v1/issues').flush({ items: [], total: 0, limit: 50, offset: 0 });
        fixture.detectChanges();

        expect(fixture.componentInstance.pageLabel()).toBe('No result');
    });

    it('stops loading when the request is refused', () => {
        http.expectOne((call) => call.url === '/api/v1/issues').flush(null, {
            status: 500,
            statusText: 'Server Error'
        });
        fixture.detectChanges();

        // A spinner that never stops is how a failed page passes for a slow one.
        expect(fixture.componentInstance.loading()).toBe(false);
    });

    /**
     * The four filters the API has always accepted and this screen offered no way to set.
     *
     * What is asserted is the parameter, not the field: a control bound to a property nobody
     * puts in the request is a switch that moves and does nothing, which is the defect these
     * four were already an instance of.
     */
    it('sends each switch to the server as the parameter the API reads', () => {
        firstPage(1);

        const component = fixture.componentInstance;
        component.onlyKev = true;
        component.overdue = true;
        component.unsettled = true;
        component.onlyDirect = true;
        component.triageFilter = 'affected';
        component.reload(0);

        const url = http.expectOne((call) => call.url === '/api/v1/issues').request.urlWithParams;
        expect(url).toContain('is_kev=true');
        expect(url).toContain('overdue=true');
        expect(url).toContain('unsettled=true');
        expect(url).toContain('only_direct=true');
        expect(url).toContain('triage_status=affected');
    });

    it('reloads with is_kev when the switch on screen is thrown', async () => {
        firstPage(1);

        // Through the DOM and not through the field: a control wired to nothing looks identical
        // from the component's side, and that is precisely the state this screen was in.
        fixture.nativeElement.querySelector('#filter-kev').click();
        await fixture.whenStable();
        fixture.detectChanges();

        expect(fixture.componentInstance.onlyKev).toBe(true);
        expect(http.expectOne((call) => call.url === '/api/v1/issues').request.urlWithParams).toContain('is_kev=true');
    });

    it('leaves the three switches out of the request while they are off', () => {
        // `only_direct=false` says nothing the server does not already assume, and a URL full of
        // false filters is a URL nobody can read back to see what was actually asked for.
        const url = http.expectOne((call) => call.url === '/api/v1/issues').request.urlWithParams;
        expect(url).not.toContain('is_kev');
        expect(url).not.toContain('overdue');
        expect(url).not.toContain('unsettled');
        expect(url).not.toContain('only_direct');
        expect(url).not.toContain('triage_status');
    });

    it('does not offer the advisor when no model is configured', async () => {
        // **An absent option must be absent, not present and refusing.** The button was offered to
        // everybody; with no model it opened a dialog onto an unreachable service.
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Issues],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        useEnglish();
        const offline = TestBed.createComponent(Issues);
        const calls = TestBed.inject(HttpTestingController);
        offline.detectChanges();
        calls.expectOne((call) => call.url === '/api/v1/repositories').flush([]);
        calls.expectOne((call) => call.url === '/api/v1/containers').flush([]);
        calls
            .expectOne((call) => call.url === '/api/v1/ai-advisor/status')
            .flush({ enabled: false, selectedModel: null, availableModels: [] });
        calls
            .expectOne((call) => call.url === '/api/v1/issues')
            .flush({ items: [issue(1, 'CVE-2026-1234')], total: 1, limit: 50, offset: 0 });
        offline.detectChanges();

        expect(offline.componentInstance.aiEnabled()).toBe(false);
    });

    it('hides the advisor too when availability itself does not answer', async () => {
        // A read failure is not an access: promising a button one does not know will work is
        // exactly what this guard prevents.
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Issues],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        useEnglish();
        const broken = TestBed.createComponent(Issues);
        const calls = TestBed.inject(HttpTestingController);
        broken.detectChanges();
        calls.expectOne((call) => call.url === '/api/v1/repositories').flush([]);
        calls.expectOne((call) => call.url === '/api/v1/containers').flush([]);
        calls.expectOne((call) => call.url === '/api/v1/ai-advisor/status').error(new ProgressEvent('failed'));
        calls.expectOne((call) => call.url === '/api/v1/issues').flush({ items: [], total: 0, limit: 50, offset: 0 });
        broken.detectChanges();

        expect(broken.componentInstance.aiEnabled()).toBe(false);
    });

    it('says the model did not answer, instead of opening an empty dialog', () => {
        firstPage(1);

        const page = fixture.componentInstance;
        page.openAiAdvisor({ id: 1 } as never);
        const explain = http.expectOne((call) => call.url === '/api/v1/ai-advisor/explain/issue/1');
        expect(explain.request.params.get('language')).toBe('en');
        explain.error(new ProgressEvent('failed'));
        fixture.detectChanges();

        // **The error was set in a signal the template did not use**: the dialog opened, the
        // spinner stopped, and nothing was left. The message moreover promised a "local fallback
        // generation" that this code never wrote.
        expect(page.aiAdviceError()).toBeTruthy();
        expect(page.aiAdviceError()).not.toContain('secours');
        expect(page.aiAdviceLoading()).toBe(false);
    });
});

/**
 * The same decision on many issues.
 *
 * One CVE appears in forty repositories, and "not reachable in our configuration" is one judgement
 * about one context, not forty. What is asserted here is the two things that make the feature safe
 * rather than convenient: that the ids the user ticked are the ids the request carries, and that a
 * refusal is reported as a refusal of the whole batch — the server writes nothing when one id is
 * invisible, and a message that leaves a partial write plausible makes the reader stop instead of
 * retrying.
 */
describe('triaging a selection', () => {
    let fixture: ComponentFixture<Issues>;
    let http: HttpTestingController;

    function row(id: number): Record<string, unknown> {
        return asSchema('BacklogEntry', {
            id,
            targetKind: 'repository',
            type: 'vulnerability',
            identifier: `CVE-2026-${id}`,
            severity: 'high',
            state: 'open',
            firstSeenAt: '2026-03-03T08:00:00Z',
            lastSeenAt: '2026-08-21T05:03:00Z',
            timesSeen: 1,
            triageStatus: 'under_review',
            isKev: false
        });
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Issues],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        useEnglish();
        fixture = TestBed.createComponent(Issues);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        for (const request of http.match(() => true)) {
            request.flush(
                request.request.url.endsWith('/issues')
                    ? { items: [row(11), row(22), row(33)], total: 3, limit: 50, offset: 0 }
                    : []
            );
        }
        fixture.detectChanges();
    }, 20_000);

    it('sends the ticked issues as `ids`, once', () => {
        const component = fixture.componentInstance;
        component.selected.set([component.issues()[0], component.issues()[2]]);
        component.openBulkTriage();
        component.triageStatus = 'not_affected';
        component.triageJustification = 'vulnerable_code_not_in_execute_path';
        component.submitTriage();

        const call = http.expectOne('/api/v1/issues/triage');
        expect(call.request.method).toBe('POST');
        // The ids, and not a request per row: forty requests would be forty audit entries and
        // thirty-nine chances of a half-applied decision.
        expect(call.request.body.ids).toEqual([11, 33]);
        expect(call.request.body.status).toBe('not_affected');
        expect(call.request.body.justification).toBe('vulnerable_code_not_in_execute_path');
    });

    it('reloads and drops the selection once the batch is written', () => {
        const component = fixture.componentInstance;
        component.selected.set([component.issues()[0]]);
        component.openBulkTriage();
        component.submitTriage();
        // The route answers with the written issues, not with backlog rows: `targetKind` is the
        // backlog's word and an `IssueView` does not carry it.
        http.expectOne('/api/v1/issues/triage').flush(
            asSchemaList('IssueView', [
                {
                    id: 11,
                    type: 'vulnerability',
                    severity: 'high',
                    state: 'open',
                    triageStatus: 'not_affected',
                    isKev: false,
                    timesSeen: 1
                }
            ])
        );

        // A selection outliving its rows is a decision about issues nobody is looking at any more.
        expect(component.selected()).toEqual([]);
        http.expectOne((call) => call.url === '/api/v1/issues').flush({ items: [], total: 0, limit: 50, offset: 0 });
    });

    it('drops the selection when the filters change under it', () => {
        const component = fixture.componentInstance;
        component.selected.set([component.issues()[0], component.issues()[1]]);
        component.severity = 'critical';
        component.reload(0);

        expect(component.selected()).toEqual([]);
        http.expectOne((call) => call.url === '/api/v1/issues').flush({ items: [], total: 0, limit: 50, offset: 0 });
    });

    it('says the whole batch was refused when one issue is not visible', () => {
        const component = fixture.componentInstance;
        component.selected.set([component.issues()[0], component.issues()[1]]);
        component.openBulkTriage();
        component.submitTriage();
        // The server's own sentence for this case, which says nothing about the other rows.
        http.expectOne('/api/v1/issues/triage').flush(
            { detail: 'Issue not found.' },
            { status: 404, statusText: 'Not Found' }
        );
        fixture.detectChanges();

        const message = component.triageError();
        expect(message).toContain('None of the 2 selected issues were triaged');
        expect(message).toContain('refused as a whole');
        // And nothing was reloaded, so the ticks are still there to select again from.
        http.expectNone((call) => call.url === '/api/v1/issues');
    });

    it("still shows the server's explanation when the refusal is not a visibility one", () => {
        const component = fixture.componentInstance;
        component.selected.set([component.issues()[0]]);
        component.openBulkTriage();
        component.submitTriage();
        http.expectOne('/api/v1/issues/triage').flush(
            { detail: 'Too many issues at once: 900, the limit is 500.' },
            { status: 400, statusText: 'Bad Request' }
        );

        // The sentence the server took care to write, kept — with the batch's fate stated first.
        expect(component.triageError()).toContain('Too many issues at once');
        expect(component.triageError()).toContain('The selected issue was not triaged');
    });

    /**
     * Through the DOM, because a checkbox column bound to nothing looks identical from the
     * component's side — and "select all, decide once" is the whole flow this feature exists for.
     */
    it('ticks the page from the header checkbox and sends what it ticked', async () => {
        const header = fixture.nativeElement.querySelector('p-tableheadercheckbox input[type="checkbox"]');
        expect(header).not.toBeNull();
        header.click();
        await fixture.whenStable();
        fixture.detectChanges();

        expect(fixture.componentInstance.selected().map((issue) => issue.id)).toEqual([11, 22, 33]);

        fixture.componentInstance.openBulkTriage();
        fixture.componentInstance.submitTriage();
        expect(http.expectOne('/api/v1/issues/triage').request.body.ids).toEqual([11, 22, 33]);
    });

    it('offers the action only once something is ticked, and says what it will do', () => {
        const component = fixture.componentInstance;
        const session = TestBed.inject(SessionStore);
        const as = (role: string) =>
            session.user.set({ id: 1, username: 'x', role, mustChangePassword: false } as never);

        // **A test dictionary, because the label now goes through i18n.** It was hard-coded, in
        // French, in a bilingual application — three times. What this case tests is unchanged: that
        // the button's promise changes with the role. Whether the translation really exists is
        // `check-i18n-keys.mjs`'s job.
        TestBed.inject(I18nService).translations.set({
            issues: { triage_action: 'Trier', triage_request: 'Envoyer pour approbation' }
        });

        as('CISO');
        expect(fixture.nativeElement.textContent).not.toContain('(2)');

        component.selected.set([component.issues()[0], component.issues()[1]]);
        fixture.detectChanges();

        // The count is on the button because "Save" looks the same for one row and for forty.
        expect(fixture.nativeElement.textContent).toContain('Trier (2)');

        // **The label is the promise.** An account without approval rights can triage, but its
        // decision goes into a queue: the screen announced "Triage" to it as to the others, and it
        // found out afterwards on seeing the tag turn to "Pending approval".
        as('USER');
        fixture.detectChanges();
        expect(fixture.nativeElement.textContent).toContain('Envoyer pour approbation (2)');
        expect(fixture.nativeElement.textContent).not.toContain('Trier (2)');

        // An auditor observes and does not decide: the control is absent, not greyed out.
        //
        // **Asserted on the key and not on the sentence.** The label was hard-coded in French in an
        // otherwise English template; it now goes through the bundles, and an assertion on the
        // translated text would say which language the suite loaded rather than what the screen
        // shows.
        as('AUDITOR');
        fixture.detectChanges();
        expect(fixture.nativeElement.textContent).not.toContain('(2)');
        expect(fixture.nativeElement.textContent).toContain('issues.reads_only');
    });
});

/**
 * The dashboard's links, and the controls they have to light up.
 *
 * The filter applied while every control on screen read "all" — that was the state this screen
 * shipped in, and the reason it was wrong is not that the list was unfiltered but that the screen
 * contradicted the URL that opened it: a short backlog with no filter showing reads as a backlog
 * that lost most of its rows.
 */
describe('the backlog opened from a dashboard link', () => {
    async function open(queryParams: Record<string, string>): Promise<ComponentFixture<Issues>> {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({
            imports: [Issues],
            providers: [
                provideHttpClient(withXhr()),
                provideHttpClientTesting(),
                provideRouter([]),
                {
                    provide: ActivatedRoute,
                    useValue: {
                        snapshot: { queryParamMap: convertToParamMap(queryParams) },
                        queryParamMap: of(convertToParamMap(queryParams))
                    }
                }
            ]
        });

        useEnglish();
        const fixture = TestBed.createComponent(Issues);
        const http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        for (const request of http.match(() => true)) {
            request.flush(request.request.url.endsWith('/issues') ? { items: [], total: 0, limit: 50, offset: 0 } : []);
        }
        fixture.detectChanges();
        // `ngModel` writes the initial value into the control on a microtask, so a switch asserted
        // synchronously reads as off however right the field is — and that would pass a screen
        // whose controls never light up.
        await fixture.whenStable();
        fixture.detectChanges();
        return fixture;
    }

    it('applies is_kev and shows the control as active', async () => {
        const fixture = await open({ is_kev: 'true' });

        expect(fixture.componentInstance.onlyKev).toBe(true);
        const control = fixture.nativeElement.querySelector('#filter-kev');
        expect(control).not.toBeNull();
        expect(control.checked).toBe(true);

        // And it is still the filter the server was asked for, not only the box that is ticked.
        const http = TestBed.inject(HttpTestingController);
        fixture.componentInstance.reload(0);
        expect(http.expectOne((call) => call.url === '/api/v1/issues').request.urlWithParams).toContain('is_kev=true');
    });

    it('does the same for the deadline figure', async () => {
        const fixture = await open({ overdue: 'true' });

        expect(fixture.componentInstance.overdue).toBe(true);
        expect(fixture.nativeElement.querySelector('#filter-overdue').checked).toBe(true);
    });

    it('and for the per-severity figures, which leave settled triage out', async () => {
        // The dashboard links here with `unsettled=true`. Unread, "3 critical" opens a list of
        // five — the figure looks wrong, and it is the list that is.
        const fixture = await open({ severity: 'critical', state: 'open', unsettled: 'true' });

        expect(fixture.componentInstance.unsettled).toBe(true);
        expect(fixture.nativeElement.querySelector('#filter-unsettled').checked).toBe(true);
    });

    it('shows nothing as active when the link carries no filter', async () => {
        // The other half of the same contract: a control lit up without a filter behind it would
        // be the same contradiction the other way round.
        const fixture = await open({});

        expect(fixture.componentInstance.onlyKev).toBe(false);
        expect(fixture.nativeElement.querySelector('#filter-kev').checked).toBe(false);
    });
});

/**
 * The scope a link from the solutions tree applies (`project_id`, `solution_id`), through a real
 * router, because what is being tested is the URL: the page read a snapshot of it, so a second link
 * into the open page changed the address and left the list as it was.
 */
describe('the backlog narrowed to a project or a solution', () => {
    let harness: RouterTestingHarness;
    let http: HttpTestingController;

    const TREE = asSchema('SolutionTree', {
        solutions: [
            {
                id: 1,
                name: 'Payments',
                description: null,
                createdAt: '2026-09-01T00:00:00Z',
                partial: false,
                repositoryCount: 1,
                containerCount: 0,
                openIssues: { critical: 0, high: 1, medium: 0, low: 0, negligible: 0, unknown: 0, total: 1 },
                projects: [
                    {
                        id: 12,
                        solutionId: 1,
                        name: 'Ledger',
                        description: null,
                        createdAt: '2026-09-01T00:00:00Z',
                        partial: false,
                        checklistsVisible: true,
                        repositoryCount: 1,
                        containerCount: 0,
                        openIssues: { critical: 0, high: 1, medium: 0, low: 0, negligible: 0, unknown: 0, total: 1 },
                        repositories: [{ id: 10, name: 'ledger-core' }]
                    }
                ]
            }
        ],
        unfiled: {
            repositoryCount: 0,
            containerCount: 0,
            openIssues: { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0, total: 0 },
            repositories: []
        }
    });

    const EMPTY_PAGE = { items: [], total: 0, limit: 50, offset: 0 };
    const page = () => harness.routeNativeElement as HTMLElement;
    const button = (name: string) =>
        [...page().querySelectorAll('button')].find((candidate) => candidate.getAttribute('aria-label') === name);

    /** Answers everything the page asks for on arrival, and returns the backlog request's parameters. */
    async function open(url: string): Promise<URLSearchParams> {
        await harness.navigateByUrl(url);
        let issues: URLSearchParams | null = null;
        for (const request of http.match(() => true)) {
            const path = request.request.url;
            if (path === '/api/v1/issues') {
                issues = new URLSearchParams(request.request.urlWithParams.split('?')[1] ?? '');
                request.flush(EMPTY_PAGE);
            } else if (path === '/api/v1/solutions') request.flush(TREE);
            else if (path === '/api/v1/ai-advisor/status') request.flush({ enabled: false });
            else request.flush([]);
        }
        await harness.fixture.whenStable();
        harness.detectChanges();
        expect(issues).not.toBeNull();
        return issues!;
    }

    /** The one backlog request a URL change should cause. */
    async function nextRequest(): Promise<URLSearchParams> {
        await harness.fixture.whenStable();
        const request = http.expectOne((call) => call.url === '/api/v1/issues');
        request.flush(EMPTY_PAGE);
        await harness.fixture.whenStable();
        harness.detectChanges();
        return new URLSearchParams(request.request.urlWithParams.split('?')[1] ?? '');
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({
            providers: [
                provideHttpClient(withXhr()),
                provideHttpClientTesting(),
                provideRouter([{ path: 'issues', component: Issues }])
            ]
        });
        useEnglish();
        http = TestBed.inject(HttpTestingController);
        harness = await RouterTestingHarness.create();
    }, 20_000);

    it('sends the project with the rest of the link, and names it in a chip that can be taken off', async () => {
        const params = await open('/issues?project_id=12&severity=high&unsettled=true');

        expect(params.get('project_id')).toBe('12');
        expect(params.get('severity')).toBe('high');
        expect(params.get('unsettled')).toBe('true');
        expect(params.has('solution_id')).toBe(false);

        expect(page().querySelector('[data-testid="scope-project"]')?.textContent).toContain(
            'Project: Payments / Ledger'
        );
        expect(button('Remove the project filter Payments / Ledger')).toBeDefined();
        expect(page().querySelector('[data-testid="scope-solution"]')).toBeNull();
    });

    it('sends a solution, and both when the link carries both, each with its chip', async () => {
        const params = await open('/issues?solution_id=1&project_id=12');

        expect(params.get('solution_id')).toBe('1');
        expect(params.get('project_id')).toBe('12');
        expect(page().querySelector('[data-testid="scope-solution"]')?.textContent).toContain('Solution: Payments');
        expect(button('Remove the solution filter Payments')).toBeDefined();
        expect(page().querySelector('[data-testid="scope-project"]')).not.toBeNull();
    });

    it('takes the project off the URL and the request, and leaves the rest of the link alone', async () => {
        await open('/issues?project_id=12&severity=high&unsettled=true');

        button('Remove the project filter Payments / Ledger')!.click();
        const params = await nextRequest();

        expect(params.has('project_id')).toBe(false);
        expect(params.get('severity')).toBe('high');
        expect(params.get('unsettled')).toBe('true');
        const url = TestBed.inject(Router).url;
        expect(url).not.toContain('project_id');
        expect(url).toContain('severity=high');
        expect(page().querySelector('[data-testid="scope-project"]')).toBeNull();
    });

    it('follows a second link into the open page instead of keeping the first one', async () => {
        await open('/issues?project_id=12&severity=high&unsettled=true');
        const before = harness.routeDebugElement!.componentInstance as Issues;

        await harness.navigateByUrl('/issues?solution_id=1');
        const params = await nextRequest();

        // The same component, reused by the router: only the subscription can have seen the change.
        expect(harness.routeDebugElement!.componentInstance).toBe(before);
        expect(params.get('solution_id')).toBe('1');
        expect(params.has('project_id')).toBe(false);
        // A filter the new link does not carry is off, on screen and in the request — not left
        // over from the link before it.
        expect(params.has('severity')).toBe(false);
        expect(params.has('unsettled')).toBe(false);
        expect(before.severity).toBeNull();
        expect(before.unsettled).toBe(false);
        expect(page().querySelector('[data-testid="scope-project"]')).toBeNull();
        expect(page().querySelector('[data-testid="scope-solution"]')).not.toBeNull();
    });

    it('writes a control into the URL, keeping the scope it was opened with', async () => {
        await open('/issues?project_id=12');
        const component = harness.routeDebugElement!.componentInstance as Issues;

        component.severity = 'critical';
        component.onlyKev = true;
        component.filtersChanged();
        const params = await nextRequest();

        expect(params.get('project_id')).toBe('12');
        expect(params.get('severity')).toBe('critical');
        const url = TestBed.inject(Router).url;
        expect(url).toContain('project_id=12');
        expect(url).toContain('severity=critical');
        expect(url).toContain('is_kev=true');
        // A default stays out of the address, so a plain visit reads `/issues`.
        expect(url).not.toContain('state=');
    });

    it('shows a project it cannot name as the number the link carried, over the ordinary empty list', async () => {
        const params = await open('/issues?project_id=99');

        // The server answers a hidden project and a missing one alike, with an empty page; the
        // screen must not tell them apart either.
        expect(params.get('project_id')).toBe('99');
        expect(page().querySelector('[data-testid="scope-project"]')?.textContent).toContain('Project: #99');
        expect(page().textContent).toContain('No issue matches these filters');
    });

    it('does not read the tree when the link carries no scope', async () => {
        await harness.navigateByUrl('/issues');
        expect(http.match((call) => call.url === '/api/v1/solutions')).toEqual([]);
        for (const request of http.match(() => true))
            request.flush(request.request.url.endsWith('/issues') ? EMPTY_PAGE : []);
    });
});

/**
 * The weekly OWASP view's drill-down, read back from the URL its figures build. **The link is taken
 * from the view's own rules** (`openLink`, `openedLink`), not retyped here: a spec that wrote the
 * parameters by hand would pass while the two screens disagreed on the week's last day.
 */
describe('the backlog opened from a weekly OWASP figure', () => {
    let harness: RouterTestingHarness;
    let http: HttpTestingController;
    const page = () => harness.routeNativeElement as HTMLElement;

    function issueRow(id: number) {
        return asSchema('BacklogEntry', {
            id,
            repoId: 5,
            containerId: null,
            targetKind: 'repository',
            targetName: 'Arm Libs Spring',
            type: 'vulnerability',
            identifier: `CVE-2026-${id}`,
            severity: 'high',
            packageName: 'openssl',
            packageVersion: '3.0.1',
            state: id % 2 === 0 ? 'resolved' : 'open',
            firstSeenAt: '2026-09-03T08:00:00Z',
            lastSeenAt: '2026-09-21T05:03:00Z',
            timesSeen: 1,
            triageStatus: 'under_review',
            isKev: false
        });
    }

    async function open(url: string, total: number): Promise<URLSearchParams> {
        await harness.navigateByUrl(url);
        let issues: URLSearchParams | null = null;
        for (const request of http.match(() => true)) {
            const path = request.request.url;
            if (path === '/api/v1/issues') {
                issues = new URLSearchParams(request.request.urlWithParams.split('?')[1] ?? '');
                request.flush({
                    items: Array.from({ length: total }, (_, index) => issueRow(index + 1)),
                    total,
                    limit: 50,
                    offset: 0
                });
            } else if (path === '/api/v1/ai-advisor/status') request.flush({ enabled: false });
            else if (path === '/api/v1/solutions')
                request.flush({ solutions: [], unfiled: { repositoryCount: 0, containerCount: 0, repositories: [] } });
            else request.flush([]);
        }
        await harness.fixture.whenStable();
        harness.detectChanges();
        expect(issues).not.toBeNull();
        return issues!;
    }

    const url = (params: Record<string, string>) => `/issues?${new URLSearchParams(params).toString()}`;

    beforeEach(async () => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({
            providers: [
                provideHttpClient(withXhr()),
                provideHttpClientTesting(),
                provideRouter([{ path: 'issues', component: Issues }])
            ]
        });
        useEnglish();
        http = TestBed.inject(HttpTestingController);
        harness = await RouterTestingHarness.create();
    }, 20_000);

    it('asks exactly what an open count counts, every state, and says so in a banner with the count', async () => {
        const week = threeWeeks().weeks[1];
        const line = week.categories.find((candidate) => candidate.category === 'A06')!;
        const params = await open(url(openLink(week, 'A06', { kind: 'project', id: 12 })), line.open);

        expect(params.get('owasp_category')).toBe('A06');
        expect(params.get('open_at')).toBe('2026-09-27');
        expect(params.get('unsettled')).toBe('true');
        expect(params.get('project_id')).toBe('12');
        // Every state: "open on that Sunday" is mostly resolved since, and `open` would hide them.
        expect(params.get('state')).toBe('all');

        const banner = page().querySelector('[data-testid="weekly-banner"]')!;
        expect(banner.querySelector('[data-testid="weekly-banner-text"]')?.textContent).toContain(
            'Issues A06 open on 2026-09-27 — from the weekly OWASP view'
        );
        // The count the banner shows is the server's total for that filter — the figure clicked.
        expect(banner.textContent).toContain(`1–${line.open} of ${line.open}`);
        expect(banner.textContent).toContain('not settled by triage as it stands today');
        // The state control says "all", not "open": the control agrees with the request.
        expect((harness.routeDebugElement!.componentInstance as Issues).state).toBe('all');
        // The way back names the week and the scope, and nothing the link could have smuggled in.
        const back = new URL(banner.querySelector<HTMLAnchorElement>('[data-testid="weekly-back"]')!.href);
        expect(back.pathname).toBe('/owasp');
        expect(Object.fromEntries(back.searchParams)).toEqual({ view: 'weekly', week: '2026-09-21', project_id: '12' });
    });

    it('reads a flow range, and keeps a state the link names', async () => {
        const week = threeWeeks().weeks[2];
        const params = await open(`${url(openedLink(week, 'A06', null))}&state=open`, 3);
        expect(params.get('first_seen_from')).toBe('2026-09-28');
        expect(params.get('first_seen_to')).toBe('2026-10-04');
        expect(params.get('state')).toBe('open');
        expect(page().querySelector('[data-testid="weekly-banner-text"]')?.textContent).toContain(
            'Issues A06 first seen from 2026-09-28 to 2026-10-04'
        );
    });

    it('keeps the drill-down when another control moves', async () => {
        const week = threeWeeks().weeks[1];
        await open(url(openLink(week, 'A06', null)), 4);
        const component = harness.routeDebugElement!.componentInstance as Issues;
        component.severity = 'critical';
        component.filtersChanged();
        await harness.fixture.whenStable();
        const request = http.expectOne((call) => call.url === '/api/v1/issues');
        const params = new URLSearchParams(request.request.urlWithParams.split('?')[1] ?? '');
        request.flush({ items: [], total: 0, limit: 50, offset: 0 });
        expect(params.get('open_at')).toBe('2026-09-27');
        expect(params.get('owasp_category')).toBe('A06');
        expect(params.get('severity')).toBe('critical');
        const address = TestBed.inject(Router).url;
        expect(address).toContain('open_at=2026-09-27');
        expect(address).toContain('owasp_category=A06');
        // The default for a date is every state: it stays out of the address, as `open` does without one.
        expect(address).not.toContain('state=');
    });

    it('takes the drill-down off in one click, back to the open backlog, leaving the scope', async () => {
        const week = threeWeeks().weeks[1];
        await open(url(resolvedLink(week, 'A06', { kind: 'solution', id: 1 })), 5);
        page().querySelector<HTMLButtonElement>('[data-testid="weekly-clear"] button')!.click();
        await harness.fixture.whenStable();
        const request = http.expectOne((call) => call.url === '/api/v1/issues');
        const params = new URLSearchParams(request.request.urlWithParams.split('?')[1] ?? '');
        request.flush({ items: [], total: 0, limit: 50, offset: 0 });
        await harness.fixture.whenStable();
        harness.detectChanges();

        for (const key of ['owasp_category', 'resolved_from', 'resolved_to']) expect(params.has(key)).toBe(false);
        expect(params.get('state')).toBe('open');
        expect(params.get('solution_id')).toBe('1');
        expect(TestBed.inject(Router).url).toBe('/issues?solution_id=1');
        expect(page().querySelector('[data-testid="weekly-banner"]')).toBeNull();
    });

    it('asks a total for every category at once, and says so in words rather than as a code', async () => {
        const week = threeWeeks().weeks[2];
        const params = await open(url(resolvedLink(week, null, { kind: 'project', id: 12 })), week.resolved);
        expect(params.get('owasp_category')).toBe('any');
        expect(params.get('resolved_from')).toBe('2026-09-28');
        expect(params.get('resolved_to')).toBe('2026-10-04');
        const text = page().querySelector('[data-testid="weekly-banner-text"]')?.textContent;
        expect(text).toContain('Issues of any OWASP category resolved from 2026-09-28 to 2026-10-04');
        expect(text).not.toContain('any resolved');
    });

    it('goes back to the week a reopened range starts in, even with no end', async () => {
        await open('/issues?reopened_from=2026-09-30', 1);
        const back = page().querySelector<HTMLAnchorElement>('[data-testid="weekly-back"]')!;
        expect(new URL(back.href).searchParams.get('week')).toBe('2026-09-28');
    });

    it('names a lone any filter as the Top 10, not as a category called any', async () => {
        await open('/issues?owasp_category=any', 2);
        expect(page().querySelector('[data-testid="weekly-banner-text"]')?.textContent).toContain(
            'Issues placed in an OWASP Top 10:2021 category'
        );
    });

    /**
     * A category with no date is the current grid's link, and the grid is where it goes back to: the
     * banner used to say "from the weekly OWASP view" and offer a way back to a view never opened.
     */
    it('names the current grid as the origin of a dateless category, and goes back to it in its scope', async () => {
        const params = await open('/issues?owasp_category=A06&unsettled=true&project_id=12', 4);
        expect(params.get('owasp_category')).toBe('A06');
        expect(params.get('unsettled')).toBe('true');
        expect(params.get('project_id')).toBe('12');
        expect(params.get('state')).toBe('open');
        const banner = page().querySelector('[data-testid="weekly-banner"]')!;
        expect(banner.querySelector('[data-testid="weekly-banner-text"]')?.textContent).toContain(
            'Issues placed in A06 — from the OWASP grid'
        );
        const back = banner.querySelector<HTMLAnchorElement>('[data-testid="weekly-back"]')!;
        expect(back.textContent?.trim()).toBe('Back to the OWASP grid');
        const address = new URL(back.href);
        expect(address.pathname).toBe('/owasp');
        expect(Object.fromEntries(address.searchParams)).toEqual({ project_id: '12' });
    });

    it('asks a reopened bar its recorded reopenings over every state, and its way back is the week', async () => {
        const week = threeWeeks().weeks[2];
        const params = await open(url(reopenedLink(week, 'A06', null)!), 2);
        expect(params.get('reopened_from')).toBe('2026-09-28');
        expect(params.get('reopened_to')).toBe('2026-10-04');
        expect(params.get('owasp_category')).toBe('A06');
        expect(params.get('state')).toBe('all');
        const banner = page().querySelector('[data-testid="weekly-banner"]')!;
        expect(banner.querySelector('[data-testid="weekly-banner-text"]')?.textContent).toContain(
            'Issues A06 reopened from 2026-09-28 to 2026-10-04'
        );
        const back = new URL(banner.querySelector<HTMLAnchorElement>('[data-testid="weekly-back"]')!.href);
        expect(back.searchParams.get('week')).toBe('2026-09-28');
        expect(TestBed.inject(Router).url).toContain('reopened_to=2026-10-04');

        page().querySelector<HTMLButtonElement>('[data-testid="weekly-clear"] button')!.click();
        await harness.fixture.whenStable();
        const request = http.expectOne((call) => call.url === '/api/v1/issues');
        const cleared = new URLSearchParams(request.request.urlWithParams.split('?')[1] ?? '');
        request.flush({ items: [], total: 0, limit: 50, offset: 0 });
        for (const key of ['reopened_from', 'reopened_to', 'owasp_category']) expect(cleared.has(key)).toBe(false);
    });

    it('shows no banner, and asks no date, on an ordinary visit or a garbled one', async () => {
        const params = await open('/issues?open_at=2026-13-40&owasp_category=A11', 0);
        expect(params.has('open_at')).toBe(false);
        expect(params.has('owasp_category')).toBe(false);
        expect(params.get('state')).toBe('open');
        expect(page().querySelector('[data-testid="weekly-banner"]')).toBeNull();
    });
});

/**
 * A risk accepted (`will_not_fix`, decision 0041).
 *
 * It is the one decision that has to carry a review date and must not carry a VEX justification:
 * each of the five says the product is *not* exposed, and this one says it is. The server refuses
 * both mistakes; what is asserted here is that the dialog cannot make them — a justification left
 * from a `not_affected` chosen a moment earlier would otherwise ride along hidden and be refused.
 */
describe('accepting a risk', () => {
    let fixture: ComponentFixture<Issues>;
    let http: HttpTestingController;

    const ROW = asSchema('BacklogEntry', {
        id: 7,
        targetKind: 'repository',
        type: 'vulnerability',
        identifier: 'CVE-2026-7',
        severity: 'high',
        state: 'open',
        firstSeenAt: '2026-03-03T08:00:00Z',
        lastSeenAt: '2026-08-21T05:03:00Z',
        timesSeen: 1,
        triageStatus: 'under_review',
        isKev: false
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Issues],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        useEnglish();
        TestBed.inject(SessionStore).user.set({
            id: 1,
            username: 'x',
            role: 'CISO',
            mustChangePassword: false
        } as never);
        fixture = TestBed.createComponent(Issues);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        for (const request of http.match(() => true)) {
            request.flush(
                request.request.url.endsWith('/issues') ? { items: [ROW], total: 1, limit: 50, offset: 0 } : []
            );
        }
        fixture.detectChanges();
    }, 20_000);

    it('offers it in the one list, in words, and never in the colour of good news', () => {
        const component = fixture.componentInstance;
        const option = component.triageOptions().find((one) => one.value === 'will_not_fix');
        expect(option?.label).toBe('Will not fix — risk accepted');
        expect(component.triageLabel('will_not_fix')).toBe('Will not fix — risk accepted');
        // Settled for the gate, still exposed: amber, not the green of `fixed`.
        expect(component.triageColour('will_not_fix')).toBe('warn');
    });

    it('cannot be submitted without a review delay the server accepts', () => {
        const component = fixture.componentInstance;
        component.openTriage(component.issues()[0]);
        component.chooseTriageStatus('will_not_fix');

        for (const days of [null, 0, 3651, 1.5]) {
            component.triageExpiresInDays = days;
            expect(component.canSubmitTriage()).toBe(false);
        }
        component.submitTriage();
        http.expectNone('/api/v1/issues/7/triage');

        component.triageExpiresInDays = 90;
        expect(component.canSubmitTriage()).toBe(true);
    });

    it('clears a justification chosen before, and never sends one', () => {
        const component = fixture.componentInstance;
        component.openTriage(component.issues()[0]);
        component.chooseTriageStatus('not_affected');
        component.triageJustification = 'inline_mitigations_already_exist';

        component.chooseTriageStatus('will_not_fix');
        expect(component.triageJustification).toBeNull();

        // Even a value written behind the field's back stays home.
        component.triageJustification = 'inline_mitigations_already_exist';
        component.triageExpiresInDays = 90;
        component.submitTriage();

        const body = http.expectOne('/api/v1/issues/7/triage').request.body;
        expect(body.status).toBe('will_not_fix');
        expect(body.justification).toBeNull();
        expect(body.expires_in_days).toBe(90);
    });

    it('shows no justification field, and says the delay is required, in the dialog', async () => {
        const component = fixture.componentInstance;
        component.openTriage(component.issues()[0]);
        component.chooseTriageStatus('will_not_fix');
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();

        const delay = document.body.querySelector<HTMLInputElement>('#triage-expires');
        expect(delay).not.toBeNull();
        expect(delay!.required).toBe(true);
        expect(document.body.querySelector('#triage-justification')).toBeNull();
        expect(document.body.querySelector('#triage-expires-hint')?.textContent).toContain(
            'Accepting a risk needs a review date'
        );
    });

    it('keeps the justification and an optional delay for an argument that the product is not exposed', async () => {
        const component = fixture.componentInstance;
        component.openTriage(component.issues()[0]);
        component.chooseTriageStatus('not_affected');
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();

        expect(document.body.querySelector('#triage-justification')).not.toBeNull();
        expect(document.body.querySelector<HTMLInputElement>('#triage-expires')!.required).toBe(false);
        expect(document.body.querySelector('#triage-expires-hint')?.textContent).toContain('Leave empty');
    });
});
