import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForgeDiscoveryPage, POLL_FIRST_MS } from './forge-discovery';
import { useEnglish } from '@/app/core/testing/english';
import { asSchema } from '@/app/core/testing/contract';
import {
    API,
    CANDIDATE_PAGE,
    COMPLETED_DISCOVERY,
    PREVIEW,
    RESULT,
    CONNECTION,
    CONNECTION_ID,
    RUNNING_DISCOVERY,
    repository
} from '@/app/core/testing/forges.fixtures';

/**
 * A connection's discovery, through the DOM: the run's state and counters while it moves, why it ended short,
 * the comparison's figures and the lists they open — and the polling, which must back off while nothing moves
 * and stop when the page is left.
 */
describe('the discovery page', () => {
    let fixture: ComponentFixture<ForgeDiscoveryPage>;
    let http: HttpTestingController;
    const BASE = `/api/v1/forge-connections/${CONNECTION_ID}`;

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string) => dom().querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
    const has = (selector: string) => dom().querySelector(selector) !== null;
    const click = (selector: string) => {
        const host = dom().querySelector<HTMLElement>(selector)!;
        (host.tagName === 'BUTTON' ? host : host.querySelector('button')!).click();
        fixture.detectChanges();
    };

    function open(connection: object = CONNECTION, history: object[] = [COMPLETED_DISCOVERY]): void {
        fixture = TestBed.createComponent(ForgeDiscoveryPage);
        fixture.componentRef.setInput('connectionId', CONNECTION_ID);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne({ method: 'GET', url: BASE }).flush(asSchema('ForgeConnectionView', connection));
        http.expectOne({ method: 'GET', url: `${BASE}/discoveries` }).flush(history);
        fixture.detectChanges();
    }

    function discovery(changes: object): object {
        return asSchema('ForgeDiscoveryView', { ...COMPLETED_DISCOVERY, ...changes });
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [ForgeDiscoveryPage],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
    }, 20_000);

    afterEach(() => {
        vi.useRealTimers();
    });

    it('shows the last discovery, its counters and the comparison, each figure opening its list', () => {
        open();

        expect(text('[data-testid="connection-title"]')).toBe('Internal GitLab');
        expect(text('[data-testid="discovery-state"]')).toBe('Completed');
        expect(text('[data-testid="namespaces"]')).toBe('4');
        expect(text('[data-testid="repositories"]')).toBe('37');
        expect(text('[data-testid="requests"]')).toBe('41');
        expect(text('[data-testid="count-new"]')).toBe('3 new');
        expect(text('[data-testid="count-changed"]')).toBe('1 changed');
        expect(text('[data-testid="count-gone"]')).toBe('2 gone');

        // The figure "3 new" opens the new repositories, and nothing else.
        click('[data-testid="count-new"]');
        http.expectOne({
            method: 'GET',
            url: `${BASE}/discoveries/12/repositories?change=new&limit=50&offset=0`
        }).flush({
            items: [API],
            limit: 50,
            offset: 0,
            total: 1
        });
        fixture.detectChanges();
        expect(text('[data-testid="changed-row"]')).toContain('acme/backend/payments/api');

        click('[data-testid="count-changed"]');
        http.expectOne(`${BASE}/discoveries/12/repositories?change=changed&limit=50&offset=0`).flush({
            items: [repository('105', 'acme/new-name', { changeSummary: 'renamed or moved from acme/old-name' })],
            limit: 50,
            offset: 0,
            total: 1
        });
        fixture.detectChanges();
        expect(text('[data-testid="changed-row"]')).toContain('renamed or moved from acme/old-name');
    });

    it('says why a partial run stopped, when the limit lifts, and that it counts nothing gone', () => {
        const partial = discovery({
            state: 'partial',
            reason: 'rate_limited',
            rateLimitResetAt: '2026-10-03T09:30:00Z',
            goneCount: null
        });
        open({ ...CONNECTION, lastDiscovery: partial }, [partial]);

        expect(text('[data-testid="discovery-state"]')).toBe('Partial');
        expect(text('[data-testid="reason"]')).toContain('rate limit asked for a longer wait');
        expect(text('[data-testid="reset-at"]')).toMatch(/^The limit lifts at 2026-10-03 \d\d:30/);
        expect(text('[data-testid="reason"]')).toContain('Nothing is marked gone');
        expect(has('[data-testid="count-gone"]')).toBe(false);
        expect(text('[data-testid="gone-not-counted"]')).toContain('only a completed discovery');
        // A partial run listed what it listed whole: it can be chosen from.
        expect(has('[data-testid="to-selection"]')).toBe(true);
    });

    it('says why a run failed, in words, with the server detail below', () => {
        const failed = discovery({
            state: 'failed',
            reason: 'token_rejected',
            detail: 'GitLab answered 401.',
            newCount: null,
            changedCount: null,
            goneCount: null
        });
        open({ ...CONNECTION, lastDiscovery: failed }, [failed]);

        expect(text('[data-testid="discovery-state"]')).toBe('Failed');
        expect(text('[data-testid="reason"]')).toContain('The forge rejected the token');
        expect(text('[data-testid="reason-detail"]')).toBe('GitLab answered 401.');
        expect(has('[data-testid="comparison"]')).toBe(false);
    });

    it('starts a discovery and polls it, backing off while nothing moves, until it ends', () => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
        open({ ...CONNECTION, lastDiscovery: null }, []);
        expect(text('[data-testid="never"]')).toBe('No discovery yet.');

        click('[data-testid="discover"]');
        http.expectOne({ method: 'POST', url: `${BASE}/discoveries` }).flush(RUNNING_DISCOVERY, {
            status: 202,
            statusText: 'Accepted'
        });
        http.expectOne({ method: 'GET', url: `${BASE}/discoveries` }).flush([RUNNING_DISCOVERY]);
        fixture.detectChanges();
        expect(text('[data-testid="discovery-state"]')).toBe('Running');
        expect(text('[data-testid="running"]')).toContain('follows it by itself');

        // Nothing before the first step, then one read.
        vi.advanceTimersByTime(POLL_FIRST_MS - 1);
        http.expectNone(`${BASE}/discoveries/13`);
        vi.advanceTimersByTime(1);
        http.expectOne(`${BASE}/discoveries/13`).flush(RUNNING_DISCOVERY);
        fixture.detectChanges();

        // Nothing moved: the next read waits twice as long.
        vi.advanceTimersByTime(POLL_FIRST_MS);
        http.expectNone(`${BASE}/discoveries/13`);
        vi.advanceTimersByTime(POLL_FIRST_MS);
        http.expectOne(`${BASE}/discoveries/13`).flush({
            ...RUNNING_DISCOVERY,
            repositoriesSeen: 30,
            requestsMade: 20
        });
        fixture.detectChanges();
        expect(text('[data-testid="repositories"]')).toBe('30');

        // A counter moved: back to the first step.
        vi.advanceTimersByTime(POLL_FIRST_MS);
        http.expectOne(`${BASE}/discoveries/13`).flush({ ...COMPLETED_DISCOVERY, id: 13 });
        http.expectOne({ method: 'GET', url: `${BASE}/discoveries` }).flush([{ ...COMPLETED_DISCOVERY, id: 13 }]);
        http.expectOne({ method: 'GET', url: BASE }).flush(CONNECTION);
        fixture.detectChanges();
        expect(text('[data-testid="discovery-state"]')).toBe('Completed');

        // Ended: no read any more.
        vi.advanceTimersByTime(60_000);
        http.expectNone(`${BASE}/discoveries/13`);
        http.verify();
    });

    it('stops polling when the page is left', () => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
        open({ ...CONNECTION, lastDiscovery: RUNNING_DISCOVERY }, [RUNNING_DISCOVERY]);

        fixture.destroy();
        vi.advanceTimersByTime(120_000);
        http.expectNone(`${BASE}/discoveries/13`);
    });

    it('names the discovery already running, and follows it', () => {
        open();
        click('[data-testid="discover"]');
        http.expectOne({ method: 'POST', url: `${BASE}/discoveries` }).flush(
            {
                type: 'urn:vectispire:problem:forge-discovery-in-progress',
                status: 409,
                detail: 'A discovery is already running.',
                discoveryId: 13
            },
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();

        expect(text('[data-testid="in-progress"]')).toContain('Discovery #13 is already running');
        dom().querySelector<HTMLButtonElement>('[data-testid="follow-running"]')!.click();
        fixture.detectChanges();
        http.expectOne({ method: 'GET', url: `${BASE}/discoveries/13` }).flush(RUNNING_DISCOVERY);
        fixture.detectChanges();
        expect(text('[data-testid="discovery-state"]')).toBe('Running');
        fixture.destroy();
    });

    it('carries the selection from the table to the import, and out of it once imported', async () => {
        open();
        click('[data-testid="to-selection"]');
        const selection = `${BASE}/discoveries/12/selection`;
        http.expectOne(`${selection}?limit=50&offset=0&archived=hide&forks=hide&personal=show&present=show`).flush(
            CANDIDATE_PAGE
        );
        http.expectOne({ method: 'POST', url: selection }).flush({
            discoveryId: 12,
            selected: ['101', '102'],
            count: 2,
            dropped: []
        });
        fixture.detectChanges();
        expect(text('[data-testid="step-import"]')).toBe('3. Place and import (2)');

        click('[data-testid="to-import"]');
        http.expectOne('/api/v1/ssh-keys').flush([]);
        http.expectOne('/api/v1/git-tokens').flush([]);
        http.expectOne('/api/v1/solutions').flush({ solutions: [], unfiled: { openIssues: {}, repositories: [] } });
        const preview = http.expectOne({ method: 'POST', url: `${BASE}/imports/preview` });
        expect(preview.request.body).toMatchObject({ discoveryId: 12, forgeIds: ['101', '102'] });
        preview.flush(PREVIEW);
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();

        click('[data-testid="import"]');
        http.expectOne({ method: 'POST', url: `${BASE}/imports` }).flush(RESULT);
        http.expectOne({ method: 'GET', url: BASE }).flush({ ...CONNECTION, importedTargets: 7 });
        fixture.detectChanges();

        expect(text('[data-testid="result-summary"]')).toContain('2 targets created.');
        expect(text('[data-testid="step-import"]')).toBe('3. Place and import (0)');
    });

    it('says that a GitHub connection cannot be discovered yet', () => {
        open();
        click('[data-testid="discover"]');
        http.expectOne({ method: 'POST', url: `${BASE}/discoveries` }).flush(
            { type: 'urn:vectispire:problem:forge-discovery-unsupported', status: 409, detail: 'Not yet.' },
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();
        expect(text('[data-testid="unsupported"]')).toContain('GitLab only');
    });

    it('says a connection that does not exist is not found', () => {
        fixture = TestBed.createComponent(ForgeDiscoveryPage);
        fixture.componentRef.setInput('connectionId', 'missing');
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne('/api/v1/forge-connections/missing').flush(
            { status: 404, detail: 'Forge connection not found.' },
            { status: 404, statusText: 'Not Found' }
        );
        http.expectOne('/api/v1/forge-connections/missing/discoveries').flush(
            { status: 404, detail: 'Forge connection not found.' },
            { status: 404, statusText: 'Not Found' }
        );
        fixture.detectChanges();
        expect(text('[data-testid="not-found"]')).toBe('No connection has this id.');
    });
});
