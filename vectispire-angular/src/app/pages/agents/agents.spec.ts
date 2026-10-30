import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Type } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Agents } from './agents';
import { AgentsPage } from './agents-page';
import { ConcurrencyDialog } from './concurrency-dialog';
import { DeclareAgentDialog } from './declare-agent-dialog';
import { ResetSealingDialog } from './reset-sealing-dialog';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import { SessionStore } from '@/app/core/session.store';
import type { UnservedCredentialedScans } from '@/app/core/api.models';
import { sessionUser } from '@/app/core/testing/session.fixtures';

/** A part of the screen, as the shell mounted it. */
function partOf<T>(fixture: ComponentFixture<Agents>, type: Type<T>): T {
    return fixture.debugElement.query(By.directive(type)).componentInstance as T;
}

const pageOf = (fixture: ComponentFixture<Agents>): AgentsPage => fixture.debugElement.injector.get(AgentsPage);

/**
 * How many scans an agent runs at once, as the agents screen shows and changes it.
 *
 * <p>The control plane refuses a limit outside 1..16 with a 400; the screen repeats the bound so
 * the input does not offer what will be refused, and still shows the server's words when it is.
 */
describe('the agents screen, on concurrent scans', () => {
    let fixture: ComponentFixture<Agents>;
    let page: AgentsPage;
    let http: HttpTestingController;

    const AGENT = asSchema('AgentSummary', {
        id: '00000000-0000-0000-0000-0000000000aa',
        name: 'runner-dmz-01',
        kind: 'remote',
        enabled: true,
        credentialsMode: 'local',
        sealsCredentials: false,
        signsResults: false,
        maxConcurrent: 4,
        online: true,
        runningScans: 2,
        description: null,
        labels: null,
        hostname: 'runner-dmz-01',
        platform: 'linux/amd64',
        version: '0.9.0',
        contractVersion: '1',
        lastSeenAt: '2026-09-26T05:00:00Z'
    });

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Agents],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        useEnglish();
        fixture = TestBed.createComponent(Agents);
        page = pageOf(fixture);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        load();
    });

    function load(): void {
        for (const request of http.match(() => true)) {
            const url = request.request.url;
            if (url.endsWith('/admin/agents')) {
                request.flush([AGENT]);
            } else if (url.endsWith('/activity')) {
                // An empty queue: no polling timer, nothing else to flush.
                request.flush(null, { status: 500, statusText: 'unavailable' });
            } else {
                request.flush([]);
            }
        }
        fixture.detectChanges();
    }

    /**
     * The two queue tags, read as a reader reads them. They were `count + ' en cours'` and
     * `count + ' en attente'`: French words glued to a number, shown as such on the English screen.
     */
    it("counts the running and the waiting scans in the reader's language", () => {
        const running = asSchema('RunningScanItem', {
            scanId: 7,
            targetType: 'repository' as const,
            targetId: 3,
            targetName: 'billing-api',
            branch: 'main',
            agentName: 'runner-dmz-01',
            claimedAt: '2026-09-26T05:00:00Z',
            agentId: AGENT.id,
            requiredLabel: null,
            durationSeconds: 40
        });
        const pending = asSchema('PendingScanItem', {
            scanId: 8,
            targetType: 'repository' as const,
            targetId: 4,
            targetName: 'ledger',
            branch: 'main',
            queuedAt: '2026-09-26T05:01:00Z',
            requiredLabel: null,
            isRoutable: true,
            positionInQueue: 1,
            waitDurationSeconds: 12
        });
        page.activity.set(
            asSchema('AgentActivitySummary', {
                runningScans: [running, { ...running, scanId: 9 }],
                pendingScans: [pending, { ...pending, scanId: 10 }, { ...pending, scanId: 11 }],
                stats: {
                    avgScanDurationSeconds: 40,
                    busyAgents: 1,
                    idleAgents: 0,
                    onlineAgents: 1,
                    pendingScansCount: 3,
                    runningScansCount: 2,
                    scansCompleted24h: 5,
                    totalAgents: 1
                }
            })
        );
        const tags = () =>
            [...(fixture.nativeElement as HTMLElement).querySelectorAll('p-tag')]
                .map((tag) => tag.textContent.trim())
                .filter((text) => /^\d+ /.test(text));

        fixture.detectChanges();
        expect(tags()).toEqual(expect.arrayContaining(['2 running', '3 waiting']));
        expect(tags().join(' ')).not.toMatch(/en cours|en attente/);

        useFrench();
        fixture.detectChanges();
        expect(tags()).toEqual(expect.arrayContaining(['2 en cours', '3 en attente']));
    });

    it('shows each agent as running out of allowed', () => {
        const cell = (fixture.nativeElement as HTMLElement).querySelector(
            'td[title*="allowed at once"]'
        ) as HTMLElement;
        expect(cell.textContent?.replace(/\s+/g, ' ').trim()).toBe('2 / 4');
    });

    it('sends the new limit, and only that, to the agent it was opened for', () => {
        page.openConcurrency(AGENT);
        expect(page.concurrencyValue()).toBe(4);

        page.concurrencyValue.set(8);
        partOf(fixture, ConcurrencyDialog).saveConcurrency();

        const patch = http.expectOne(`/api/v1/admin/agents/${AGENT.id}`);
        expect(patch.request.method).toBe('PATCH');
        // Nothing else: `enabled` and `labels` left out mean "as they were" to the server.
        expect(patch.request.body).toEqual({ max_concurrent: 8 });
    });

    it('refuses a limit outside 1..16 without asking the server', () => {
        page.openConcurrency(AGENT);

        for (const outside of [0, 17, 2.5, null]) {
            page.concurrencyValue.set(outside);
            partOf(fixture, ConcurrencyDialog).saveConcurrency();
            expect(page.concurrencyError()).toContain('between 1 and 16');
        }
        http.expectNone(`/api/v1/admin/agents/${AGENT.id}`);
    });

    it("shows the server's refusal when there is one", () => {
        page.openConcurrency(AGENT);
        page.concurrencyValue.set(16);
        partOf(fixture, ConcurrencyDialog).saveConcurrency();

        http.expectOne(`/api/v1/admin/agents/${AGENT.id}`).flush(
            { detail: 'max_concurrent must be between 1 and 16, not 16.' },
            { status: 400, statusText: 'Bad Request' }
        );
        expect(page.concurrencyError()).toContain('max_concurrent must be between 1 and 16');
        expect(page.concurrencyVisible()).toBe(true);
    });

    it('refuses to declare an agent with a limit outside the bound', () => {
        page.openForm();
        page.formName.set('edge');
        page.formMaxConcurrent.set(0);
        partOf(fixture, DeclareAgentDialog).save();

        expect(page.formError()).toContain('between 1 and 16');
        http.expectNone((request) => request.method === 'POST');
    });
});

/**
 * Forgetting an agent's sealing key (ADR 0031), as an administrator reaches it from the row.
 *
 * <p>Tested through the DOM: whether the button is there is the behaviour, and a component that
 * holds the right method with no button to call it is the defect a component test cannot see.
 */
describe('the agents screen, on forgetting a sealing key', () => {
    let fixture: ComponentFixture<Agents>;
    let http: HttpTestingController;

    const SEALING = asSchema('AgentSummary', {
        id: '00000000-0000-0000-0000-0000000000bb',
        name: 'runner-dmz-02',
        kind: 'remote',
        enabled: true,
        credentialsMode: 'delegated',
        sealsCredentials: true,
        signsResults: true,
        maxConcurrent: 1,
        online: true,
        runningScans: 0,
        description: null,
        labels: null,
        hostname: 'runner-dmz-02',
        platform: 'linux/amd64',
        version: '0.9.0',
        contractVersion: '1',
        lastSeenAt: '2026-09-26T05:00:00Z'
    });

    async function open(role: string, agent: typeof SEALING): Promise<void> {
        await TestBed.configureTestingModule({
            imports: [Agents],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        useEnglish();
        TestBed.inject(SessionStore).user.set(sessionUser(role));
        fixture = TestBed.createComponent(Agents);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        flushLoad([agent]);
    }

    function flushLoad(agents: (typeof SEALING)[]): void {
        for (const request of http.match((r) => r.method === 'GET')) {
            const url = request.request.url;
            if (url.endsWith('/admin/agents')) {
                request.flush(agents);
            } else if (url.endsWith('/activity')) {
                request.flush(null, { status: 500, statusText: 'unavailable' });
            } else {
                request.flush([]);
            }
        }
        fixture.detectChanges();
    }

    function button(testId: string): HTMLButtonElement | null {
        return (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>(
            `[data-testid="${testId}"] button`
        );
    }

    // The dialog may be rendered outside the component's element, so it is looked for in the page.
    function dialogButton(testId: string): HTMLButtonElement {
        const found = document.querySelector<HTMLButtonElement>(`[data-testid="${testId}"] button`);
        expect(found, `${testId} in the confirmation dialog`).not.toBeNull();
        return found as HTMLButtonElement;
    }

    it('is offered to an administrator on an agent that holds a sealing key, with a name', async () => {
        await open('ADMIN', SEALING);
        expect(button('reset-sealing-key')?.getAttribute('aria-label')).toBe('Forget the sealing key of runner-dmz-02');
    });

    it('is not offered to anyone but an administrator', async () => {
        await open('CISO', SEALING);
        expect(button('reset-sealing-key')).toBeNull();
    });

    it('is not offered when there is no key to forget', async () => {
        await open('ADMIN', { ...SEALING, sealsCredentials: false });
        expect(button('reset-sealing-key')).toBeNull();
    });

    it('asks first, then forgets the key of that agent and shows the row without it', async () => {
        await open('ADMIN', SEALING);
        button('reset-sealing-key')?.click();
        fixture.detectChanges();
        http.expectNone((r) => r.method === 'DELETE');

        dialogButton('reset-sealing-confirm').click();
        const reset = http.expectOne(`/api/v1/admin/agents/${SEALING.id}/sealing-key`);
        expect(reset.request.method).toBe('DELETE');
        reset.flush(null, { status: 204, statusText: 'No Content' });
        fixture.detectChanges();

        flushLoad([{ ...SEALING, sealsCredentials: false }]);
        expect(button('reset-sealing-key')).toBeNull();
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('credentials withheld');
        expect((fixture.nativeElement as HTMLElement).textContent).toContain(
            'The sealing key of runner-dmz-02 is forgotten'
        );
    });

    it('sends nothing when the confirmation is cancelled', async () => {
        await open('ADMIN', SEALING);
        button('reset-sealing-key')?.click();
        fixture.detectChanges();

        dialogButton('reset-sealing-cancel').click();
        fixture.detectChanges();
        http.expectNone((r) => r.method === 'DELETE');
        expect(pageOf(fixture).resetSealingVisible()).toBe(false);
    });

    it('says the agent is gone when the server no longer knows it', async () => {
        await open('ADMIN', SEALING);
        pageOf(fixture).askResetSealing(SEALING);
        partOf(fixture, ResetSealingDialog).confirmResetSealing();
        http.expectOne(`/api/v1/admin/agents/${SEALING.id}/sealing-key`).flush(
            { detail: 'Agent not found' },
            { status: 404, statusText: 'Not Found' }
        );
        flushLoad([]);
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('This agent no longer exists.');
    });
});

/**
 * The scans that need a credential and that nobody able to be handed it can take, said on the
 * screen where an operator can act on it. The server computes the figure (`CredentialedBacklog`);
 * what is tested here is that the banner says it, names what waits and says what to do.
 */
describe('the agents screen, on credentialed scans nobody can take', () => {
    let fixture: ComponentFixture<Agents>;
    let http: HttpTestingController;

    const NONE: UnservedCredentialedScans = asSchema('UnservedCredentialedScans', {
        scans: 0,
        labels: [],
        keptAgents: []
    });

    async function open(backlog: UnservedCredentialedScans): Promise<void> {
        await TestBed.configureTestingModule({
            imports: [Agents],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        useEnglish();
        fixture = TestBed.createComponent(Agents);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        flushLoad(backlog);
    }

    function flushLoad(backlog: UnservedCredentialedScans): void {
        for (const request of http.match(() => true)) {
            const url = request.request.url;
            if (url.endsWith('/credentialed-backlog')) {
                request.flush(backlog);
            } else if (url.endsWith('/activity')) {
                request.flush(null, { status: 500, statusText: 'unavailable' });
            } else {
                request.flush([]);
            }
        }
        fixture.detectChanges();
    }

    function banner(): string | null {
        const found = (fixture.nativeElement as HTMLElement).querySelector<HTMLElement>(
            '[data-testid="credentialed-backlog"]'
        );
        return found ? (found.textContent ?? '').replace(/\s+/g, ' ').trim() : null;
    }

    it('says nothing when every such scan has an executor', async () => {
        await open(NONE);
        expect(banner()).toBeNull();
    });

    it('names the waiting scans, their labels and the agents to fix, and how', async () => {
        await open({ scans: 3, labels: ['', 'dmz'], keptAgents: ['edge-01', 'edge-02'] });

        const text = banner();
        expect(text).toContain('3 scans');
        // "No label" in words, not an empty slot before the comma.
        expect(text).toContain('label: none, dmz');
        expect(text).toContain('edge-01, edge-02 would take them');
        expect(text).toContain('pin a signing key');
        expect(text).toContain('VECTISPIRE_AGENT_SIGNING_KEY');
    });

    it('says that nobody carries the label when no agent would take them at all', async () => {
        await open({ scans: 1, labels: ['dmz'], keptAgents: [] });

        expect(banner()).toContain('No enabled executor carries that label');
        expect(banner()).not.toContain('would take them');
    });

    it('reads it again on a refresh, from the route the gauge is computed by', async () => {
        await open(NONE);
        pageOf(fixture).reload();
        const request = http.expectOne('/api/v1/admin/agents/credentialed-backlog');
        expect(request.request.method).toBe('GET');
        request.flush(asSchema('UnservedCredentialedScans', { scans: 2, labels: ['dmz'], keptAgents: ['edge-01'] }));
        flushLoad(NONE);
        expect(banner()).toContain('2 scans');
    });
});

/**
 * The fleet's activity and the agent list, when the server fails, say so in its words (RFC 7807
 * `detail`). The activity was read with `error: () => {}`: the running and waiting figures simply
 * vanished, which reads as an idle fleet.
 */
describe('the agents screen when a read fails', () => {
    let fixture: ComponentFixture<Agents>;
    let http: HttpTestingController;

    const failure = { status: 500, statusText: 'Internal Server Error' };
    const problem = (detail: string) => ({ title: 'Internal Server Error', status: 500, detail });
    // An idle fleet as the server sends it: the figures are always there, zero rather than null.
    const IDLE = asSchema('AgentActivitySummary', {
        runningScans: [],
        pendingScans: [],
        stats: {
            avgScanDurationSeconds: 0,
            busyAgents: 0,
            idleAgents: 0,
            onlineAgents: 0,
            pendingScansCount: 0,
            runningScansCount: 0,
            scansCompleted24h: 0,
            totalAgents: 0
        }
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Agents],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
        fixture = TestBed.createComponent(Agents);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    function page(): HTMLElement {
        fixture.detectChanges();
        return fixture.nativeElement as HTMLElement;
    }

    function answer(activity: () => [object, { status: number; statusText: string }?], agents: object = []): void {
        for (const request of http.match(() => true)) {
            const url = request.request.url;
            if (url.endsWith('/activity')) request.flush(...activity());
            else if (url === '/api/v1/admin/agents') request.flush(agents, 'status' in agents ? failure : undefined);
            else if (url.endsWith('/credentialed-backlog'))
                request.flush(asSchema('UnservedCredentialedScans', { scans: 0, labels: [], keptAgents: [] }));
            else request.flush([]);
        }
    }

    it('says the activity could not be read, in the server’s words, and clears it when a refresh answers', () => {
        answer(() => [problem('Activity view is being rebuilt.'), failure]);

        expect(page().querySelector('[data-testid="activity-error"]')?.textContent).toContain(
            'Activity view is being rebuilt.'
        );

        pageOf(fixture).refreshActivity();
        http.expectOne('/api/v1/admin/agents/activity').flush(IDLE);

        expect(page().querySelector('[data-testid="activity-error"]')).toBeNull();
    });

    it('shows the agent list’s failure in the server’s words', () => {
        answer(() => [IDLE], problem('Agent registry locked.'));

        expect(page().textContent).toContain('Agent registry locked.');
    });
});
