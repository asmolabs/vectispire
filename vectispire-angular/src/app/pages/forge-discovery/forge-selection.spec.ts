import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, TestRequest, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { MultiSelect } from '@openng/optimus-ui/multiselect';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { ForgeSelectionTable } from './forge-selection';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import { asSchema } from '@/app/core/testing/contract';
import { CANDIDATE_PAGE, CONNECTION_ID, candidate, repository } from '@/app/core/testing/forges.fixtures';
import type { ForgeCandidatePage, Schema } from '@/app/core/api.models';

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

    async function open(selected: string[] = ['101', '102'], page: ForgeCandidatePage = CANDIDATE_PAGE): Promise<void> {
        fixture = TestBed.createComponent(ForgeSelectionTable);
        fixture.componentRef.setInput('connectionId', CONNECTION_ID);
        fixture.componentRef.setInput('discoveryId', 12);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne(`${BASE}?limit=50&offset=0&${DEFAULT_QUERY}`).flush(page);
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

    it('says why a row cannot be ticked in the reader language, after a switch too', async () => {
        const empty = candidate(repository('105', 'acme/empty'), {
            selectable: false,
            notSelectable: 'no_default_branch',
            offered: false
        });
        await open(['101'], { ...CANDIDATE_PAGE, items: [...CANDIDATE_PAGE.items, empty], total: 5 });
        expect(tick('105').disabled).toBe(true);
        expect(text('[data-testid="candidate-state"]', row('105'))).toBe('Empty repository: no default branch');

        useFrench();
        await settle();
        expect(text('[data-testid="candidate-state"]', row('105'))).toBe('Dépôt vide : pas de branche par défaut');
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
        all.flush(
            asSchema('ForgeSelection', { discoveryId: 12, selected: ['101', '102', '104'], count: 3, dropped: [] })
        );
        await settle();
        expect(text('[data-testid="selected-count"]')).toBe('3 selected');

        await click('[data-testid="op-invert"]');
        expect(selectionChange().request.body).toMatchObject({ operation: 'invert', selected: ['101', '102', '104'] });
    });

    it("shows each repository's default branch and the tracked ones it has, unknown apart from none", async () => {
        const none = candidate(repository('105', 'acme/trunk-only', { defaultBranch: 'trunk', trackedBranches: [] }));
        const unknown = candidate(repository('106', 'acme/unread', { trackedBranches: null }));
        await open(['101'], { ...CANDIDATE_PAGE, items: [...CANDIDATE_PAGE.items, none, unknown], total: 6 });
        const tags = (forgeId: string, testId: string) =>
            Array.from(row(forgeId).querySelectorAll(`[data-testid="${testId}"]`)).map(
                (tag) => tag.textContent?.trim() ?? ''
            );

        // Read: main is the default and is not repeated, develop is the other tracked branch it has.
        expect(tags('101', 'default-branch')).toEqual(['main (default)']);
        expect(tags('101', 'tracked-branch')).toEqual(['develop']);
        expect(tags('101', 'branches-unknown')).toEqual([]);
        // Read and none found: the default branch alone, and nothing claiming ignorance.
        expect(tags('105', 'default-branch')).toEqual(['trunk (default)']);
        expect(tags('105', 'tracked-branch')).toEqual([]);
        expect(tags('105', 'branches-unknown')).toEqual([]);
        // Never read: said so, since a branch filter leaves it out and an import naming a branch skips it.
        expect(tags('106', 'default-branch')).toEqual(['main (default)']);
        expect(tags('106', 'tracked-branch')).toEqual([]);
        expect(tags('106', 'branches-unknown')).toEqual(['Other branches unknown']);

        useFrench();
        await settle();
        expect(tags('105', 'default-branch')).toEqual(['trunk (par défaut)']);
        expect(tags('106', 'branches-unknown')).toEqual(['Autres branches inconnues']);
    });

    it('offers the tracked names the server reads as the branch filter, and sends those chosen', async () => {
        const handed: string[][] = [];
        await open();
        fixture.componentInstance.trackedBranches.subscribe((names) => handed.push(names));

        const select = fixture.debugElement.query(By.directive(MultiSelect));
        expect((select.componentInstance as MultiSelect).options).toEqual(['main', 'master', 'develop']);
        expect(dom().querySelector('label[for="filter-branches"]')?.textContent?.trim()).toBe('Branches');
        expect(fixture.componentInstance.trackedBranches()).toEqual(['main', 'master', 'develop']);

        fixture.componentInstance.form.branches = ['develop', 'master'];
        await click('[data-testid="apply-filters"]');
        http.expectOne(`${BASE}?limit=50&offset=0&${DEFAULT_QUERY}&branches=develop&branches=master`).flush(
            asSchema('ForgeCandidatePage', { ...CANDIDATE_PAGE, trackedBranches: ['main', 'release'] })
        );
        await settle();
        // The import offers what the server named, read again with every page.
        expect(handed).toEqual([['main', 'release']]);

        await click('[data-testid="op-all"]');
        expect((selectionChange().request.body as Schema<'ForgeSelectionChange'>).filters).toEqual({
            archived: 'hide',
            forks: 'hide',
            personal: 'show',
            present: 'show',
            branches: ['develop', 'master']
        });
    });

    it('counts the repositories whose branches the forge did not say, as it counts the other filters', async () => {
        await open(['101'], { ...CANDIDATE_PAGE, unjudged: { fork: 30, branch: 1 } });
        expect(text('[data-testid="unjudged"]')).toContain(
            'branches: 1 repository whose branches the forge did not say'
        );

        await open(['101'], { ...CANDIDATE_PAGE, unjudged: { branch: 4 } });
        useFrench();
        await settle();
        expect(text('[data-testid="unjudged"]')).toContain(
            "branches : 4 dépôts dont la forge n'a pas dit les branches"
        );
    });

    it('names every target an import made of a repository, one per branch', async () => {
        const imported = candidate(repository('107', 'acme/imported'), {
            selectable: false,
            notSelectable: 'already_imported',
            offered: false,
            importedAs: 41,
            importedTargets: [41, 42]
        });
        await open(['101'], { ...CANDIDATE_PAGE, items: [imported], total: 1 });
        expect(text('[data-testid="candidate-state"]', row('107'))).toBe('Imported as targets 41, 42');
    });

    it('ticks and unticks one row by its id', async () => {
        await open();

        await click(`[data-forge-id="104"] [data-testid="tick"]`);
        const add = selectionChange();
        expect(add.request.body).toMatchObject({ operation: 'add', selected: ['101', '102'], forgeIds: ['104'] });
        add.flush(
            asSchema('ForgeSelection', { discoveryId: 12, selected: ['101', '102', '104'], count: 3, dropped: [] })
        );
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
        add.flush(
            asSchema('ForgeSelection', { discoveryId: 12, selected: ['101', '102', '104'], count: 3, dropped: ['999'] })
        );
        await settle();

        const dropped = text('[data-testid="dropped"]');
        expect(dropped).toContain('1 id could not be ticked');
        expect(dropped).toContain('999');
        // The row ticked by the server's answer, not by a click on its box, reads ticked.
        expect(tick('104').checked).toBe(true);
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
