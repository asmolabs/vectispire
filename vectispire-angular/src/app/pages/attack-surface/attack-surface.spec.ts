import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { useEnglish } from '@/app/core/testing/english';
import { AttackSurface } from './attack-surface';
import { asSchema } from '@/app/core/testing/contract';
import english from '../../../../public/i18n/en.json';

/**
 * The attack-surface screen, and the two things it gets wrong quietly.
 *
 * <p>The figures on this page are an exposure count. A stat that keeps showing the estate's
 * numbers under one repository's heading understates or overstates that repository's exposure
 * without looking broken, and a filter that drops an unauthenticated endpoint hides the row the
 * screen exists to surface.
 *
 * <p><b>Read through the page, not the component.</b> This suite used to assert `currentStats()` and
 * `filteredEndpoints()`: it would have stayed green with a template that showed neither. Each case
 * now chooses through the selects and reads the cards and the rows a reader sees.
 */
describe('the attack surface screen', () => {
    let fixture: ComponentFixture<AttackSurface>;
    let http: HttpTestingController;

    const LABELS = english.attack_surface;

    const endpoint = (
        id: number,
        method: string,
        path: string,
        authRequired: boolean,
        visibility: 'PUBLIC' | 'INTERNAL' | 'UNKNOWN'
    ) => ({
        id,
        scanId: 1,
        repositoryId: 7,
        method,
        path,
        authRequired,
        authType: authRequired ? 'bearer' : null,
        visibility,
        filePath: 'src/main/java/Controller.java',
        lineNumber: 10,
        framework: 'spring',
        operationId: null,
        summary: null,
        tags: null,
        shadowStatus: 'DOCUMENTED' as const,
        createdAt: '2026-08-26T00:00:00Z'
    });

    const GLOBAL = asSchema('GlobalAttackSurface', {
        totalEndpoints: 40,
        publicEndpoints: 12,
        internalEndpoints: 28,
        unauthenticatedEndpoints: 5,
        shadowEndpoints: 2,
        sensitiveUnprotectedEndpoints: 1,
        frameworks: ['spring', 'express'],
        highRiskEndpoints: []
    });

    const REPO_OVERVIEW = asSchema('RepositoryApisOverview', {
        repositoryId: 7,
        endpoints: [
            endpoint(1, 'GET', '/api/admin/users', false, 'PUBLIC'),
            endpoint(2, 'POST', '/api/admin/users', true, 'PUBLIC'),
            endpoint(3, 'GET', '/api/health', false, 'INTERNAL')
        ],
        contracts: [],
        summary: {
            totalEndpoints: 3,
            publicEndpoints: 2,
            internalEndpoints: 1,
            unauthenticatedEndpoints: 2,
            shadowEndpoints: 0,
            sensitiveUnprotectedEndpoints: 1
        }
    });

    const REPOSITORIES = [
        { id: 7, name: 'ours', displayName: 'Ours', url: 'ssh://git@example.invalid/ours.git', branch: 'main' }
    ];

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [AttackSurface],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();

        fixture = TestBed.createComponent(AttackSurface);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        http.expectOne((call) => call.url === '/api/v1/attack-surface').flush(GLOBAL);
        http.expectOne((call) => call.url === '/api/v1/repositories').flush(REPOSITORIES);
        fixture.detectChanges();
    }, 20_000);

    function page(): HTMLElement {
        fixture.detectChanges();
        return fixture.nativeElement as HTMLElement;
    }

    function text(): string {
        return page().textContent;
    }

    /** The five figures at the top, in their order on screen. */
    function figures(): string[] {
        return [...page().querySelectorAll('span.text-3xl')].slice(0, 5).map((node) => node.textContent.trim());
    }

    /** The line under the first figure: the frameworks the count covers. */
    function frameworks(): string {
        return (
            page()
                .querySelector('span.text-3xl')
                ?.closest('div.p-4')
                ?.querySelector('.text-xs.mt-1')
                ?.textContent?.trim() ?? ''
        );
    }

    /** The routes listed, as "METHOD path", in table order. */
    function routes(): string[] {
        return [...page().querySelectorAll('p-table tbody tr')]
            .filter((row) => row.querySelector('p-tag'))
            .map(
                (row) =>
                    `${row.querySelector('p-tag')!.textContent.trim()} ${row.querySelector('.font-mono')!.textContent.trim()}`
            );
    }

    /** A select of the page: the repository picker by its id, a filter by its accessible name. */
    function select(name: string): HTMLElement {
        const found = name.startsWith('#')
            ? page().querySelector<HTMLElement>(`p-select:has(${name})`)
            : [...page().querySelectorAll<HTMLElement>('p-select')].find(
                  (candidate) => candidate.querySelector('[role="combobox"]')?.getAttribute('aria-label') === name
              );
        expect(found, `select ${name}`).toBeTruthy();
        return found!;
    }

    /** Opens a select and clicks the option labelled so, as a reader does. */
    async function choose(name: string, label: string): Promise<void> {
        select(name).click();
        fixture.detectChanges();
        await fixture.whenStable();
        const option = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find(
            (candidate) => candidate.textContent.trim() === label
        );
        expect(option, `option ${label}`).toBeTruthy();
        option!.click();
        fixture.detectChanges();
        await fixture.whenStable();
    }

    async function chooseOurs(): Promise<void> {
        await choose('#attack-surface-repo', 'Ours');
        http.expectOne((call) => call.url === '/api/v1/repositories/7/apis').flush(REPO_OVERVIEW);
        fixture.detectChanges();
    }

    function button(label: string): HTMLButtonElement {
        const found = [...page().querySelectorAll('button')].find((b) => b.textContent.includes(label));
        expect(found, `button ${label}`).toBeDefined();
        return found!;
    }

    it("shows the estate figures until a repository is chosen, then that repository's", async () => {
        expect(figures()).toEqual(['40', '12', '5', '2', '1']);
        expect(frameworks()).toBe('spring, express');

        await chooseOurs();

        // The whole point of selecting a target. Keeping 40 here would put the estate's exposure
        // under one repository's name, which reads as that repository being far worse than it is.
        expect(figures()).toEqual(['3', '2', '2', '0', '1']);
        // Frameworks are derived from the endpoints rather than taken from the summary, and
        // deduplicated: three endpoints, one framework.
        expect(frameworks()).toBe('spring');
    });

    it('lists nothing until a repository is chosen, rather than everything', () => {
        // An empty list here is deliberate: the endpoint table belongs to one target, and
        // defaulting to the estate's would be the same disclosure the API routes were corrected for.
        expect(page().querySelector('p-table')).toBeNull();
        expect(text()).toContain(LABELS.pick_repository_routes);
    });

    it('lists the chosen repository’s routes', async () => {
        await chooseOurs();

        expect(routes()).toEqual(['GET /api/admin/users', 'POST /api/admin/users', 'GET /api/health']);
        expect(text()).not.toContain(LABELS.pick_repository_routes);
    });

    it('combines the method, authentication and visibility filters', async () => {
        await chooseOurs();

        await choose(LABELS.col_auth, LABELS.auth.none);
        expect(routes()).toEqual(['GET /api/admin/users', 'GET /api/health']);

        // Both at once: /api/admin/users appears twice, once per method, and only the GET is
        // unauthenticated. A page that applied one filter instead of both would keep the POST.
        await choose(LABELS.col_method, LABELS.methods.get);
        expect(routes()).toEqual(['GET /api/admin/users', 'GET /api/health']);

        await choose(LABELS.col_visibility, LABELS.visibility.public);
        expect(routes()).toEqual(['GET /api/admin/users']);

        await choose(LABELS.col_auth, LABELS.auth.required);
        expect(routes()).toEqual([]);
    });

    it('opens the unauthenticated routes from the figure that counts them', async () => {
        await chooseOurs();

        // A figure that opens a list disagreeing with it reads as a wrong figure.
        page().querySelectorAll<HTMLElement>('div[role="button"]')[0].click();
        fixture.detectChanges();
        await fixture.whenStable();

        expect(routes()).toEqual(['GET /api/admin/users', 'GET /api/health']);
        expect(select(LABELS.col_auth).querySelector('[role="combobox"]')?.textContent?.trim()).toBe(LABELS.auth.none);
    });

    it('names each filter of the route list by what it filters', async () => {
        // The three selects had no name but their value ("All methods"), and the search box only
        // its placeholder, which is gone as soon as somebody types.
        await chooseOurs();
        await choose(LABELS.col_method, LABELS.methods.get);

        const search = page().querySelector<HTMLInputElement>('input[type="text"]');
        expect(search?.getAttribute('aria-label')).toBe('Filter the routes');
        const toolbar = search?.closest('.flex-wrap');
        const boxes = Array.from(toolbar?.querySelectorAll('p-select [role="combobox"]') ?? []);
        expect(boxes[0].textContent?.trim()).toBe('GET');
        expect(boxes.map((box) => box.getAttribute('aria-label'))).toEqual(['Method', 'Visibility', 'Authentication']);
    });

    it('names the repository picker by its label, whatever it shows', async () => {
        // The label's `for` pointed at the select's combobox, a span no label can name: the picker
        // was announced as its placeholder, then as the repository chosen.
        await chooseOurs();

        const picker = page().querySelector('#attack-surface-repo');
        expect(picker?.getAttribute('role')).toBe('combobox');
        expect(picker?.textContent.trim()).toBe('Ours');
        // The accessible name: aria-labelledby wins over aria-label, which holds the value shown.
        const name = (picker?.getAttribute('aria-labelledby') ?? '')
            .split(/\s+/)
            .map((id) => page().querySelector(`#${id}`)?.textContent.trim() ?? '')
            .join(' ')
            .trim();
        expect(name).toBe('Repository:');
    });

    it('searches the path, and does not ask the server to do it', async () => {
        await chooseOurs();

        const search = page().querySelector<HTMLInputElement>('input[aria-label="Filter the routes"]')!;
        search.value = 'HEALTH';
        search.dispatchEvent(new Event('input'));
        // Case-insensitive, and local: no request is issued, which is why typing is not throttled.
        expect(routes()).toEqual(['GET /api/health']);
        http.expectNone(() => true);
    });

    it('clearing the selection drops the overview instead of refetching it', async () => {
        await chooseOurs();

        page()
            .querySelector('p-select:has(#attack-surface-repo) .p-select-clear-icon')!
            .dispatchEvent(new MouseEvent('click', { bubbles: true }));
        fixture.detectChanges();
        await fixture.whenStable();

        expect(page().querySelector('p-table')).toBeNull();
        expect(text()).toContain(LABELS.pick_repository_routes);
        expect(figures()).toEqual(['40', '12', '5', '2', '1']);
        http.expectNone(() => true);
    });

    it("says why a repository's routes are missing, in the server's words", async () => {
        await choose('#attack-surface-repo', 'Ours');
        http.expectOne('/api/v1/repositories/7/apis').flush(
            { detail: 'The route index is being rebuilt.', status: 503 },
            { status: 503, statusText: 'Service Unavailable' }
        );

        expect(text()).toContain('The route index is being rebuilt.');
        expect(routes()).toEqual([]);
    });

    it("says why the repository list is missing, in the server's words", () => {
        button('Refresh').click();
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/attack-surface').flush(GLOBAL);
        http.expectOne((call) => call.url === '/api/v1/repositories').flush(
            { detail: 'The inventory is being rebuilt.', status: 503 },
            { status: 503, statusText: 'Service Unavailable' }
        );

        // Swallowed, it left the picker empty and the reader with no reason.
        expect(text()).toContain('The inventory is being rebuilt.');
    });

    it('a second load cancels the first instead of racing it', () => {
        // The refresh button disables itself while loading; a purge reloads whatever is in flight.
        button('Refresh').click();
        button(LABELS.purge_inventory).click();
        http.expectOne({ method: 'DELETE', url: '/api/v1/attack-surface' }).flush(null);
        fixture.detectChanges();

        const surfaces = http.match((call) => call.url === '/api/v1/attack-surface');
        const lists = http.match((call) => call.url === '/api/v1/repositories');
        expect(surfaces.map((call) => call.cancelled)).toEqual([true, false]);
        expect(lists.map((call) => call.cancelled)).toEqual([true, false]);
        surfaces[1].flush({ ...GLOBAL, totalEndpoints: 0 });
        lists[1].flush([]);
        expect(figures()[0]).toBe('0');
    });
});
