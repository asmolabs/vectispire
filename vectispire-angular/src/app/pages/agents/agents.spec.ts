import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Agents } from './agents';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import { SessionStore } from '@/app/core/session.store';

/**
 * How many scans an agent runs at once, as the agents screen shows and changes it.
 *
 * <p>The control plane refuses a limit outside 1..16 with a 400; the screen repeats the bound so
 * the input does not offer what will be refused, and still shows the server's words when it is.
 */
describe('the agents screen, on concurrent scans', () => {
    let fixture: ComponentFixture<Agents>;
    let component: Agents;
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
        component = fixture.componentInstance;
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

    it('shows each agent as running out of allowed', () => {
        const cell = fixture.nativeElement.querySelector('td[title*="allowed at once"]') as HTMLElement;
        expect(cell.textContent?.replace(/\s+/g, ' ').trim()).toBe('2 / 4');
    });

    it('sends the new limit, and only that, to the agent it was opened for', () => {
        component.openConcurrency(AGENT);
        expect(component.concurrencyValue).toBe(4);

        component.concurrencyValue = 8;
        component.saveConcurrency();

        const patch = http.expectOne(`/api/v1/admin/agents/${AGENT.id}`);
        expect(patch.request.method).toBe('PATCH');
        // Nothing else: `enabled` and `labels` left out mean "as they were" to the server.
        expect(patch.request.body).toEqual({ max_concurrent: 8 });
    });

    it('refuses a limit outside 1..16 without asking the server', () => {
        component.openConcurrency(AGENT);

        for (const outside of [0, 17, 2.5]) {
            component.concurrencyValue = outside;
            component.saveConcurrency();
            expect(component.concurrencyError()).toContain('between 1 and 16');
        }
        http.expectNone(`/api/v1/admin/agents/${AGENT.id}`);
    });

    it("shows the server's refusal when there is one", () => {
        component.openConcurrency(AGENT);
        component.concurrencyValue = 16;
        component.saveConcurrency();

        http.expectOne(`/api/v1/admin/agents/${AGENT.id}`).flush(
            { detail: 'max_concurrent must be between 1 and 16, not 16.' },
            { status: 400, statusText: 'Bad Request' }
        );
        expect(component.concurrencyError()).toContain('max_concurrent must be between 1 and 16');
        expect(component.concurrencyVisible()).toBe(true);
    });

    it('refuses to declare an agent with a limit outside the bound', () => {
        component.openForm();
        component.form.name = 'edge';
        component.form.maxConcurrent = 0;
        component.save();

        expect(component.formError()).toContain('between 1 and 16');
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
        TestBed.inject(SessionStore).user.set({ id: 1, username: 'x', role, mustChangePassword: false } as never);
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
        return fixture.nativeElement.querySelector(`[data-testid="${testId}"] button`) as HTMLButtonElement | null;
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
        expect(fixture.nativeElement.textContent).toContain('credentials withheld');
        expect(fixture.nativeElement.textContent).toContain('The sealing key of runner-dmz-02 is forgotten');
    });

    it('sends nothing when the confirmation is cancelled', async () => {
        await open('ADMIN', SEALING);
        button('reset-sealing-key')?.click();
        fixture.detectChanges();

        dialogButton('reset-sealing-cancel').click();
        fixture.detectChanges();
        http.expectNone((r) => r.method === 'DELETE');
        expect(fixture.componentInstance.resetSealingVisible()).toBe(false);
    });

    it('says the agent is gone when the server no longer knows it', async () => {
        await open('ADMIN', SEALING);
        fixture.componentInstance.askResetSealing(SEALING);
        fixture.componentInstance.confirmResetSealing();
        http.expectOne(`/api/v1/admin/agents/${SEALING.id}/sealing-key`).flush(
            { detail: 'Agent not found' },
            { status: 404, statusText: 'Not Found' }
        );
        flushLoad([]);
        expect(fixture.nativeElement.textContent).toContain('This agent no longer exists.');
    });
});
