import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, TestRequest, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { ForgeSelectionTable } from './forge-selection';
import { useEnglish } from '@/app/core/testing/english';
import { asSchema } from '@/app/core/testing/contract';
import { CANDIDATE_PAGE, CONNECTION_ID } from '@/app/core/testing/forges.fixtures';

/**
 * The selection table, through the DOM: which rows can be ticked and why not, what the first selection
 * leaves out, what each filter could not judge, and what every gesture sends — the selection held by the
 * screen, sent whole, with the filters the table shows.
 */
describe('the selection table', () => {
    let fixture: ComponentFixture<ForgeSelectionTable>;
    let http: HttpTestingController;
    const BASE = `/api/v1/forge-connections/${CONNECTION_ID}/discoveries/12/selection`;
    const DEFAULT_QUERY = 'archived=hide&forks=hide&personal=show&present=show';

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string, root: ParentNode = dom()) =>
        root.querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
    const row = (forgeId: string) => dom().querySelector<HTMLElement>(`[data-forge-id="${forgeId}"]`)!;
    const tick = (forgeId: string) => row(forgeId).querySelector<HTMLInputElement>('[data-testid="tick"]')!;

    async function settle(): Promise<void> {
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();
    }

    async function click(selector: string): Promise<void> {
        const host = dom().querySelector<HTMLElement>(selector)!;
        (host.tagName === 'BUTTON' || host.tagName === 'INPUT' ? host : host.querySelector('button')!).click();
        await settle();
    }

    function selectionChange(): TestRequest {
        return http.expectOne({ method: 'POST', url: BASE });
    }

    async function open(selected: string[] = ['101', '102']): Promise<void> {
        fixture = TestBed.createComponent(ForgeSelectionTable);
        fixture.componentRef.setInput('connectionId', CONNECTION_ID);
        fixture.componentRef.setInput('discoveryId', 12);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne(`${BASE}?limit=50&offset=0&${DEFAULT_QUERY}`).flush(CANDIDATE_PAGE);
        const proposed = selectionChange();
        expect(proposed.request.body).toEqual({
            operation: 'proposed',
            selected: [],
            filters: { archived: 'hide', forks: 'hide', personal: 'show', present: 'show' },
            forgeIds: []
        });
        proposed.flush(asSchema('ForgeSelection', { discoveryId: 12, selected, count: selected.length, dropped: [] }));
        await settle();
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [ForgeSelectionTable],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
    }, 20_000);

    it('starts from the proposal: personal namespaces unticked, targets already present greyed with why', async () => {
        await open();

        expect(tick('101').checked).toBe(true);
        expect(tick('102').checked).toBe(true);
        expect(tick('104').checked).toBe(false);
        expect(text('[data-testid="candidate-state"]', row('104'))).toBe('Personal: not proposed');
        expect(text('[data-testid="personal"]', row('104'))).toBe('Personal');

        expect(tick('103').disabled).toBe(true);
        expect(text('[data-testid="candidate-state"]', row('103'))).toBe('Already a target (3 targets)');
        expect(text('[data-testid="selected-count"]')).toBe('2 selected');
        expect(text('[data-testid="matching"]')).toBe('4 repositories match, of 37 listed.');
    });

    it('counts what a filter could not judge, and says how unknown values are treated', async () => {
        await open();

        const unjudged = text('[data-testid="unjudged"]');
        expect(unjudged).toContain('fork: 30 repositories whose source the forge did not name');
        expect(unjudged).toContain('A filter that hides keeps a repository it cannot judge');
    });

    it('applies the filters typed, and sends those the table shows with every operation', async () => {
        await open();

        const archived = dom().querySelector<HTMLSelectElement>('#filter-archived')!;
        archived.value = 'show';
        archived.dispatchEvent(new Event('change'));
        const path = dom().querySelector<HTMLInputElement>('#filter-path')!;
        path.value = 'acme/backend/*';
        path.dispatchEvent(new Event('input'));
        const inactive = dom().querySelector<HTMLInputElement>('#filter-inactive')!;
        inactive.value = '90';
        inactive.dispatchEvent(new Event('input'));
        await settle();
        await click('[data-testid="apply-filters"]');

        http.expectOne(
            `${BASE}?limit=50&offset=0&archived=show&forks=hide&inactiveDays=90&path=acme/backend/*&personal=show&present=show`
        ).flush(CANDIDATE_PAGE);
        await settle();

        await click('[data-testid="op-all"]');
        const all = selectionChange();
        expect(all.request.body).toEqual({
            operation: 'all',
            selected: ['101', '102'],
            filters: {
                archived: 'show',
                forks: 'hide',
                inactiveDays: 90,
                path: 'acme/backend/*',
                personal: 'show',
                present: 'show'
            },
            forgeIds: []
        });
        all.flush({ discoveryId: 12, selected: ['101', '102', '104'], count: 3, dropped: [] });
        await settle();
        expect(text('[data-testid="selected-count"]')).toBe('3 selected');

        await click('[data-testid="op-invert"]');
        expect(selectionChange().request.body).toMatchObject({ operation: 'invert', selected: ['101', '102', '104'] });
    });

    it('ticks and unticks one row by its id', async () => {
        await open();

        await click(`[data-forge-id="104"] [data-testid="tick"]`);
        const add = selectionChange();
        expect(add.request.body).toMatchObject({ operation: 'add', selected: ['101', '102'], forgeIds: ['104'] });
        add.flush({ discoveryId: 12, selected: ['101', '102', '104'], count: 3, dropped: [] });
        await settle();
        expect(tick('104').checked).toBe(true);

        await click(`[data-forge-id="101"] [data-testid="tick"]`);
        expect(selectionChange().request.body).toMatchObject({ operation: 'remove', forgeIds: ['101'] });
    });

    it('ticks pasted ids, and names those it could not tick', async () => {
        await open();

        const ids = dom().querySelector<HTMLInputElement>('#select-by-id')!;
        ids.value = '104, 999 104';
        ids.dispatchEvent(new Event('input'));
        await settle();
        await click('[data-testid="add-by-id"]');

        const add = selectionChange();
        expect(add.request.body).toMatchObject({ operation: 'add', forgeIds: ['104', '999'] });
        add.flush({ discoveryId: 12, selected: ['101', '102', '104'], count: 3, dropped: ['999'] });
        await settle();

        const dropped = text('[data-testid="dropped"]');
        expect(dropped).toContain('1 id could not be ticked');
        expect(dropped).toContain('999');
    });

    it('clears nothing on the way back: a selection already made is not replaced by the proposal', async () => {
        fixture = TestBed.createComponent(ForgeSelectionTable);
        fixture.componentRef.setInput('connectionId', CONNECTION_ID);
        fixture.componentRef.setInput('discoveryId', 12);
        fixture.componentRef.setInput('selected', ['104']);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne(`${BASE}?limit=50&offset=0&${DEFAULT_QUERY}`).flush(CANDIDATE_PAGE);
        http.expectNone({ method: 'POST', url: BASE });
        await settle();
        expect(tick('104').checked).toBe(true);
    });

    it('says when a newer discovery supersedes this one, and hands its id up', async () => {
        fixture = TestBed.createComponent(ForgeSelectionTable);
        fixture.componentRef.setInput('connectionId', CONNECTION_ID);
        fixture.componentRef.setInput('discoveryId', 12);
        fixture.componentRef.setInput('selected', ['101']);
        const handed: number[] = [];
        fixture.componentInstance.superseded.subscribe((id) => handed.push(id));
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne(`${BASE}?limit=50&offset=0&${DEFAULT_QUERY}`).flush(
            {
                type: 'urn:vectispire:problem:forge-discovery-superseded',
                status: 409,
                detail: 'Discovery 14 is newer.',
                latestDiscoveryId: 14
            },
            { status: 409, statusText: 'Conflict' }
        );
        await settle();

        expect(text('[data-testid="blocked"]')).toContain('A newer discovery (#14) has ended');
        expect(handed).toEqual([14]);
    });
});
