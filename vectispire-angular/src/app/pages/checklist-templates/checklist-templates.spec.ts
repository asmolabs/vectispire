import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting, TestRequest } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import type { ChecklistPreview, ChecklistVersionSummary } from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import {
    CONFIRMED_PREVIEW,
    DRAFT,
    PREVIEW,
    PUBLISHED,
    TEMPLATE,
    VERSION
} from '@/app/core/testing/checklists.fixtures';
import { useEnglish } from '@/app/core/testing/english';
import english from '../../../../public/i18n/en.json';
import french from '../../../../public/i18n/fr.json';
import {
    CHANGE_KEYS,
    COLUMN_KEYS,
    ChecklistTemplates,
    draftFrom,
    gridOf,
    HEADER_KEYS,
    layoutOf,
    layoutProblem,
    PROBLEM_KEYS,
    REFUSAL_KEYS,
    refusalOf,
    STATUS_KEYS
} from './checklist-templates';

/**
 * The checklist templates screen (decision 0032 §3, §4, §8).
 *
 * What it must get right is who is offered what — an auditor reads, a security lead writes — and the
 * three moments where the server's rule has to reach the person: a file past the ceiling refused
 * before it is sent, a layout confirmed as typed, and a publication that names the revision the
 * reader has on screen and, when refused, says why in a sentence they can act on.
 */
describe('the checklist templates screen', () => {
    let fixture: ComponentFixture<ChecklistTemplates>;
    let http: HttpTestingController;

    const TEMPLATE_URL = '/api/v1/checklist-templates';
    const VERSION_URL = `${TEMPLATE_URL}/release/versions/2`;

    async function start(role: string, username = 'someone'): Promise<void> {
        await TestBed.configureTestingModule({
            imports: [ChecklistTemplates],
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
        fixture = TestBed.createComponent(ChecklistTemplates);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne(TEMPLATE_URL).flush([TEMPLATE]);
        fixture.detectChanges();
    }

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string) => dom().querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';

    /** The `<button>` a `p-button` renders, found by the host's id or by its accessible name. */
    function button(idOrName: string): HTMLButtonElement {
        const host = dom().querySelector(`#${idOrName}`);
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

    function type(selector: string, value: string): void {
        const input = dom().querySelector(selector) as HTMLInputElement;
        input.value = value;
        input.dispatchEvent(new Event('input'));
        fixture.detectChanges();
    }

    /** Opens version 2 through its row's button, and answers the two reads it makes. */
    function openDraft(preview: ChecklistPreview, version = VERSION): void {
        button('Open version 2 of release').click();
        fixture.detectChanges();
        http.expectOne((call) => call.url === `${VERSION_URL}/preview`).flush(preview);
        http.expectOne(VERSION_URL).flush(version);
        fixture.detectChanges();
    }

    /** The reads a write is followed by: the preview, the version and the template's row. */
    function answerRereads(preview: ChecklistPreview = CONFIRMED_PREVIEW): void {
        http.expectOne((call) => call.url === `${VERSION_URL}/preview`).flush(preview);
        http.expectOne(VERSION_URL).flush(VERSION);
        http.expectOne(`${TEMPLATE_URL}/release`).flush(TEMPLATE);
        fixture.detectChanges();
    }

    // ------------------------------------------------------------------ roles

    it('shows an auditor every version with where it stands, and no write control anywhere', async () => {
        await start('AUDITOR');

        expect(text('[data-testid="version-release-1"]')).toContain('Published');
        expect(text('[data-testid="version-release-1"]')).toContain('bob');
        expect(text('[data-testid="version-release-2"]')).toContain('Draft');
        expect(dom().querySelector('[data-testid="import-card"]')).toBeNull();
        expect(dom().querySelector('input[type="file"]')).toBeNull();
        expect(dom().querySelector('[data-testid="new-version-release"]')).toBeNull();

        openDraft(CONFIRMED_PREVIEW);
        // The auditor reads the sheet, the layout, the items and the pairing — and can change none.
        expect(dom().querySelector('[data-testid="sheet-grid"]')).not.toBeNull();
        expect(dom().querySelector('[data-testid="layout-read"]')).not.toBeNull();
        expect(dom().querySelector('[data-testid="pairing"]')).not.toBeNull();
        expect(dom().querySelector('[data-testid="layout-form"]')).toBeNull();
        expect(dom().querySelector('#confirm-layout')).toBeNull();
        expect(dom().querySelector('[data-testid="pair-form"]')).toBeNull();
        expect(dom().querySelector('[data-testid="acts"]')).toBeNull();
        expect(dom().querySelector('#publish-version')).toBeNull();
    });

    it('offers a security lead the import, the layout form and the acts on a draft', async () => {
        await start('CISO');

        expect(dom().querySelector('[data-testid="import-card"]')).not.toBeNull();
        openDraft(CONFIRMED_PREVIEW);
        expect(dom().querySelector('[data-testid="layout-form"]')).not.toBeNull();
        expect(dom().querySelector('[data-testid="pair-form"]')).not.toBeNull();
        expect(button('publish-version').textContent).toContain('Publish revision 4');
    });

    it('offers no layout form on a published version, even to a security lead: it never changes', async () => {
        await start('ADMIN');

        button('Open version 1 of release').click();
        fixture.detectChanges();
        const published = { ...CONFIRMED_PREVIEW, version: PUBLISHED };
        http.expectOne((call) => call.url === `${TEMPLATE_URL}/release/versions/1/preview`).flush(published);
        http.expectOne(`${TEMPLATE_URL}/release/versions/1`).flush({ ...VERSION, version: PUBLISHED });
        fixture.detectChanges();

        expect(dom().querySelector('[data-testid="layout-form"]')).toBeNull();
        expect(dom().querySelector('[data-testid="layout-read"]')).not.toBeNull();
        expect(dom().querySelector('#publish-version')).toBeNull();
        expect(dom().querySelector('#derive-version')).not.toBeNull();
        expect(dom().querySelector('#retire-version')).not.toBeNull();
    });

    // ------------------------------------------------------------------ import

    it('refuses a workbook past ten megabytes before sending it, in the words the server uses', async () => {
        await start('CISO');
        type('#checklist-slug', 'release');

        const input = dom().querySelector('#checklist-file') as HTMLInputElement;
        const big = new File([new Uint8Array(10 * 1024 * 1024 + 1)], 'big.xlsx');
        Object.defineProperty(input, 'files', { value: [big], configurable: true });
        input.dispatchEvent(new Event('change'));
        fixture.detectChanges();

        expect(text('[data-testid="upload-error"]')).toBe(
            'The request body is larger than the 10485760 bytes this route accepts.'
        );
        expect(button('import-workbook').disabled).toBe(true);
        http.expectNone((call) => call.method === 'POST');
    });

    it('imports a workbook for a new template with its name, then opens the draft it became', async () => {
        await start('CISO');
        type('#checklist-slug', 'onboarding');
        type('#checklist-name', 'Onboarding checklist');
        type('#checklist-label', 'first');

        const input = dom().querySelector('#checklist-file') as HTMLInputElement;
        const workbook = new File([new Uint8Array([0x50, 0x4b])], 'onboarding.xlsx');
        Object.defineProperty(input, 'files', { value: [workbook], configurable: true });
        input.dispatchEvent(new Event('change'));
        fixture.detectChanges();
        button('import-workbook').click();

        const request = http.expectOne((call) => call.method === 'POST');
        expect(request.request.url).toBe(`${TEMPLATE_URL}/onboarding/versions`);
        expect(request.request.body).toBe(workbook);
        expect(request.request.params.get('name')).toBe('Onboarding checklist');
        expect(request.request.params.get('label')).toBe('first');
        request.flush(
            { ...VERSION, templateSlug: 'onboarding', version: { ...DRAFT, ordinal: 1, previousOrdinal: null } },
            { status: 201, statusText: 'Created' }
        );
        fixture.detectChanges();

        expect(text('[data-testid="notice"]')).toContain('Version 1 of "onboarding" imported as a draft');
        http.expectOne(TEMPLATE_URL).flush([TEMPLATE]);
        http.expectOne((call) => call.url === `${TEMPLATE_URL}/onboarding/versions/1/preview`).flush(PREVIEW);
        http.expectOne(`${TEMPLATE_URL}/onboarding/versions/1`).flush(VERSION);
    });

    it("does not send a name for a template that exists — the server would ignore it — and shows the server's refusal", async () => {
        await start('CISO');
        type('#checklist-slug', 'release');
        expect(dom().querySelector('#checklist-name')).toBeNull();

        const input = dom().querySelector('#checklist-file') as HTMLInputElement;
        Object.defineProperty(input, 'files', { value: [new File(['x'], 'r.xlsx')], configurable: true });
        input.dispatchEvent(new Event('change'));
        fixture.detectChanges();
        button('import-workbook').click();

        const request = http.expectOne((call) => call.method === 'POST');
        expect(request.request.params.has('name')).toBe(false);
        request.flush(
            {
                detail: 'Checklist template "release" already has a draft: publish it or set it aside before making another.'
            },
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();
        expect(text('[data-testid="upload-error"]')).toContain('already has a draft');
    });

    // ------------------------------------------------------------------ the layout

    it('draws the proposal on the grid: the column heads name their field, the header cells and item rows stand out', async () => {
        await start('CISO');
        openDraft(PREVIEW);

        expect(text('[data-testid="grid-column-C"]')).toBe('C · Control');
        expect(text('[data-testid="grid-column-E"]')).toBe('E · Answer');
        expect(text('[data-testid="column-header-row"]')).toContain('4');
        const cell = (row: number, column: number) =>
            dom().querySelectorAll(`[data-testid="grid-row-${row}"] td`)[column] as HTMLElement;
        expect(cell(5, 2).className).toContain('bg-blue-100');
        expect(cell(4, 2).className).not.toContain('bg-blue-100');
        expect(cell(2, 1).className).toContain('bg-amber-100');

        // Correcting a letter moves the highlight: what the grid shows is what will be confirmed.
        type('#layout-column-control', 'D');
        expect(text('[data-testid="grid-column-C"]')).toBe('C');
        expect(text('[data-testid="grid-column-D"]')).toBe('D · Control, KPI');
        expect(cell(5, 2).className).not.toContain('bg-blue-100');
        expect(cell(5, 3).className).toContain('bg-blue-100');
    });

    it('never guesses the answer words, and refuses to confirm until yes and no are named', async () => {
        await start('CISO');
        openDraft(PREVIEW);

        expect(text('[data-testid="answer-values"]')).toContain('Oui');
        expect((dom().querySelector('#layout-word-yes') as HTMLInputElement).value).toBe('');
        button('confirm-layout').click();
        fixture.detectChanges();

        expect(text('[data-testid="layout-error"]')).toBe("Map the template's answer words to yes and no.");
        http.expectNone((call) => call.method === 'PUT');
    });

    it('confirms the layout as typed — the proposal, the words, not applicable — and reads the version again', async () => {
        await start('CISO');
        openDraft(PREVIEW, { ...VERSION, layout: null, items: [] });

        type('#layout-word-yes', 'Oui');
        type('#layout-word-no', 'Non');
        fixture.componentInstance.setDraft({ offersNotApplicable: true });
        fixture.detectChanges();
        type('#layout-word-na', 'N/A');
        type('#layout-column-id', 'g');
        button('confirm-layout').click();

        const request = http.expectOne((call) => call.method === 'PUT' && call.url === `${VERSION_URL}/layout`);
        // The revision on screen, so that a layout another lead confirmed meanwhile refuses this one.
        expect(request.request.params.get('revision')).toBe('4');
        expect(request.request.body).toEqual({
            sheet: 'Checklist',
            columns: { id: 'G', domain: 'A', objective: 'B', control: 'C', kpi: 'D', answer: 'E', comment: 'F' },
            firstItemRow: 5,
            lastItemRow: 7,
            header: { date: { label: 'A2', value: 'B2' }, product: { label: 'A1', value: 'B1' } },
            answers: { yes: 'Oui', no: 'Non', notApplicable: 'N/A' }
        });
        request.flush(VERSION);
        fixture.detectChanges();
        expect(text('[data-testid="notice"]')).toBe('Layout confirmed: 3 items read.');
        answerRereads();
    });

    it("shows the server's refusal of a layout in its own words", async () => {
        await start('CISO');
        openDraft(CONFIRMED_PREVIEW);
        button('confirm-layout').click();

        http.expectOne((call) => call.method === 'PUT' && call.url === `${VERSION_URL}/layout`).flush(
            { detail: 'The product header cell B6 lies among the item rows.' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();
        expect(text('[data-testid="layout-error"]')).toBe('The product header cell B6 lies among the item rows.');
    });

    it('switches sheets on the server, and takes the layout with it', async () => {
        await start('CISO');
        openDraft(PREVIEW);

        fixture.componentInstance.showSheet('Lists');
        const request = http.expectOne((call) => call.url === `${VERSION_URL}/preview`);
        expect(request.request.params.get('sheet')).toBe('Lists');
        request.flush({ ...PREVIEW, sheet: 'Lists', cells: [] });
        expect(fixture.componentInstance.layoutDraft()?.sheet).toBe('Lists');
        // What was typed stays: choosing a sheet is not starting over.
        expect(fixture.componentInstance.layoutDraft()?.columns.control).toBe('C');
    });

    // ------------------------------------------------------------------ the pairing

    it('shows each fate against the previous version, and pairs an added item with a removed one', async () => {
        await start('CISO');
        // A pair made earlier, on another line: the new one is added to it, since the route replaces the list.
        const earlier = { added: 'text:a', removed: 'text:b' };
        openDraft(CONFIRMED_PREVIEW, { ...VERSION, pairs: [earlier] });

        expect(
            Array.from(dom().querySelectorAll('[data-testid="pairing-counts"] p-tag')).map((tag) =>
                tag.textContent?.trim()
            )
        ).toEqual(['1 unchanged', '1 changed', '1 added', '1 removed']);
        expect(text('[data-testid="change-removed"]')).toContain('Secrets are rotated yearly');

        const page = fixture.componentInstance;
        expect(page.addedOptions().map((option) => option.value)).toEqual([
            'text:secrets are rotated every ninety days'
        ]);
        expect(page.removedOptions().map((option) => option.value)).toEqual(['text:secrets are rotated yearly']);
        page.pairAdded.set('text:secrets are rotated every ninety days');
        page.pairRemoved.set('text:secrets are rotated yearly');
        fixture.detectChanges();
        button('pair-items').click();

        const request = http.expectOne((call) => call.method === 'PUT' && call.url === `${VERSION_URL}/pairs`);
        expect(request.request.params.get('revision')).toBe('4');
        expect(request.request.body).toEqual({
            pairs: [
                earlier,
                { added: 'text:secrets are rotated every ninety days', removed: 'text:secrets are rotated yearly' }
            ]
        });
        request.flush(VERSION);
        answerRereads();
    });

    it('undoes a pair made by hand by sending the list without it — the route replaces the list whole', async () => {
        await start('CISO');
        const kept = { added: 'text:a', removed: 'text:b' };
        const undone = {
            added: 'text:secrets are rotated every ninety days',
            removed: 'text:secrets are rotated yearly'
        };
        const paired: ChecklistPreview = {
            ...CONFIRMED_PREVIEW,
            pairing: [
                {
                    change: 'changed',
                    pairedByHand: true,
                    readKey: undone.added,
                    row: 6,
                    control: 'Secrets are rotated every ninety days',
                    previousKey: undone.removed,
                    previousRow: 6,
                    previousControl: 'Secrets are rotated yearly'
                }
            ]
        };
        openDraft(paired, { ...VERSION, pairs: [kept, undone] });

        expect(text('[data-testid="change-changed"]')).toContain('Paired by hand');
        button('Unpair').click();

        const request = http.expectOne((call) => call.method === 'PUT' && call.url === `${VERSION_URL}/pairs`);
        expect(request.request.body).toEqual({ pairs: [kept] });
        request.flush(VERSION);
        answerRereads();
    });

    it('says a first version has nothing to pair with', async () => {
        await start('CISO');
        openDraft({ ...CONFIRMED_PREVIEW, version: { ...DRAFT, previousOrdinal: null }, pairing: [] });

        expect(dom().querySelector('[data-testid="no-previous"]')).not.toBeNull();
        expect(dom().querySelector('[data-testid="pair-form"]')).toBeNull();
    });

    // ------------------------------------------------------------------ publish

    /** Opens the confirmed draft, asks to publish, confirms, and hands back the request. */
    function publishShown(): TestRequest {
        openDraft(CONFIRMED_PREVIEW);
        button('publish-version').click();
        fixture.detectChanges();
        expect(text('[data-testid="confirm-act"]')).toContain('Publish revision 4, as shown on this page?');
        button('confirm-act').click();
        return http.expectOne({ method: 'POST', url: `${VERSION_URL}/publish` });
    }

    /** The 409, then the version read again to name its cause. */
    function refuse(request: TestRequest, fresh: ChecklistVersionSummary, detail: string): void {
        request.flush({ detail }, { status: 409, statusText: 'Conflict' });
        http.expectOne(VERSION_URL).flush({ ...VERSION, version: fresh });
        fixture.detectChanges();
    }

    it('publishes the revision on screen, not one read afterwards', async () => {
        await start('CISO', 'bob');
        const request = publishShown();

        expect(request.request.body).toEqual({ revision: 4 });
        request.flush({ ...VERSION, version: { ...DRAFT, status: 'published', revision: 5 } });
        fixture.detectChanges();
        expect(text('[data-testid="notice"]')).toBe('Version 2 published.');
        answerRereads();
    });

    it('explains a four-eyes refusal to the author: a second person must publish it', async () => {
        await start('CISO', 'Alice');
        openDraft(CONFIRMED_PREVIEW);
        // Said before the click too — the name compared as the server compares it, without case.
        expect(dom().querySelector('[data-testid="four-eyes-hint"]')).not.toBeNull();
        button('publish-version').click();
        fixture.detectChanges();
        button('confirm-act').click();

        refuse(
            http.expectOne({ method: 'POST', url: `${VERSION_URL}/publish` }),
            DRAFT,
            'Four-eyes approval: version 2 of "release" was written by alice, so it has to be published by somebody else.'
        );
        expect(text('[data-testid="refusal"]')).toContain('You wrote this draft');
        expect(text('[data-testid="refusal"]')).toContain('a second person must publish it');
        expect(dom().querySelector('#reload-version')).toBeNull();
    });

    it('explains a draft edited since it was read, names both revisions, and offers to reload', async () => {
        await start('CISO', 'bob');
        refuse(publishShown(), { ...DRAFT, revision: 6, draftAuthors: ['alice', 'carol'] }, 'Version 2 has changed.');

        expect(text('[data-testid="refusal"]')).toContain(
            'The draft changed since you read it: you reviewed revision 4, and it is now at revision 6.'
        );
        // The panel still shows what was reviewed, not what somebody changed meanwhile.
        expect(text('[data-testid="shown-revision"]')).toBe('4');

        button('reload-version').click();
        http.expectOne((call) => call.url === `${VERSION_URL}/preview`).flush({
            ...CONFIRMED_PREVIEW,
            version: { ...DRAFT, revision: 6 }
        });
        http.expectOne(VERSION_URL).flush(VERSION);
        http.expectOne(`${TEMPLATE_URL}/release`).flush(TEMPLATE);
        fixture.detectChanges();
        expect(text('[data-testid="shown-revision"]')).toBe('6');
        expect(dom().querySelector('[data-testid="refusal"]')).toBeNull();
    });

    it("falls back to the server's sentence for a 409 the version does not explain", async () => {
        await start('CISO', 'bob');
        refuse(publishShown(), DRAFT, 'Something only the server knows.');

        expect(text('[data-testid="refusal"]')).toBe('Something only the server knows.');
    });

    it('explains a four-eyes refusal of a retirement to the author of the published version', async () => {
        await start('ADMIN', 'alice');
        button('Open version 1 of release').click();
        fixture.detectChanges();
        http.expectOne((call) => call.url === `${TEMPLATE_URL}/release/versions/1/preview`).flush({
            ...CONFIRMED_PREVIEW,
            version: PUBLISHED
        });
        http.expectOne(`${TEMPLATE_URL}/release/versions/1`).flush({ ...VERSION, version: PUBLISHED });
        fixture.detectChanges();

        button('retire-version').click();
        fixture.detectChanges();
        button('confirm-act').click();
        http.expectOne({ method: 'POST', url: `${TEMPLATE_URL}/release/versions/1/retire` }).flush(
            { detail: 'Four-eyes approval.' },
            { status: 409, statusText: 'Conflict' }
        );
        http.expectOne(`${TEMPLATE_URL}/release/versions/1`).flush({ ...VERSION, version: PUBLISHED });
        fixture.detectChanges();

        expect(text('[data-testid="refusal"]')).toContain('a second person must retire it');
    });

    // ------------------------------------------------------------------ the words

    it('has every label its maps name, in both languages — keys the i18n check cannot count', () => {
        const lookup = (bundle: unknown, key: string) =>
            key
                .split('.')
                .reduce<unknown>((node, part) => (node as Record<string, unknown> | undefined)?.[part], bundle);
        for (const map of [COLUMN_KEYS, HEADER_KEYS, STATUS_KEYS, CHANGE_KEYS, REFUSAL_KEYS, PROBLEM_KEYS]) {
            for (const key of Object.values(map)) {
                expect(typeof lookup(english, key), `${key} in English`).toBe('string');
                expect(typeof lookup(french, key), `${key} in French`).toBe('string');
            }
        }
    });
});

describe('the checklist layout helpers', () => {
    it('orders columns as the sheet does, so AA comes after Z', () => {
        const cell = (ref: string, column: string, row: number) => ({ ref, column, row, text: ref, formula: false });
        const grid = gridOf([cell('AA1', 'AA', 1), cell('B2', 'B', 2), cell('Z1', 'Z', 1)]);
        expect(grid.columns).toEqual(['B', 'Z', 'AA']);
        expect(grid.rows.map((row) => row.row)).toEqual([1, 2]);
    });

    it('starts from the confirmed layout when there is one, else from the proposal', () => {
        expect(draftFrom(CONFIRMED_PREVIEW).yes).toBe('Oui');
        expect(draftFrom(CONFIRMED_PREVIEW).offersNotApplicable).toBe(true);
        expect(draftFrom(PREVIEW).yes).toBe('');
        expect(draftFrom(PREVIEW).columns.control).toBe('C');
    });

    it('refuses a layout missing what the server requires, one reason at a time', () => {
        const valid = draftFrom(CONFIRMED_PREVIEW);
        expect(layoutProblem(valid)).toBeNull();
        expect(layoutProblem({ ...valid, sheet: ' ' })).toBe('sheet');
        expect(layoutProblem({ ...valid, columns: { ...valid.columns, comment: '' } })).toBe('required');
        expect(layoutProblem({ ...valid, columns: { ...valid.columns, kpi: 'D4' } })).toBe('letters');
        expect(layoutProblem({ ...valid, firstItemRow: 8 })).toBe('rows');
        expect(layoutProblem({ ...valid, lastItemRow: null })).toBe('rows');
        expect(layoutProblem({ ...valid, header: { ...valid.header, author: { label: 'A3', value: '' } } })).toBe(
            'header_cells'
        );
        expect(layoutProblem({ ...valid, no: '' })).toBe('words');
        expect(layoutProblem({ ...valid, notApplicable: '' })).toBe('not_applicable');
        expect(layoutProblem({ ...valid, offersNotApplicable: false, notApplicable: '' })).toBeNull();
    });

    it('sends no not-applicable word when the version does not offer it, and leaves blanks out', () => {
        const valid = draftFrom(CONFIRMED_PREVIEW);
        const layout = layoutOf({ ...valid, offersNotApplicable: false, columns: { ...valid.columns, kpi: ' ' } });
        expect(layout.answers.notApplicable).toBeNull();
        expect('kpi' in layout.columns).toBe(false);
        expect('author' in layout.header).toBe(false);
    });

    it("names a 409's cause in the order the service checks", () => {
        expect(refusalOf('publish', 4, { ...DRAFT, status: 'published' }, 'alice')).toBe('not_draft');
        expect(refusalOf('publish', 4, { ...DRAFT, layoutConfirmed: false, revision: 5 }, 'alice')).toBe('no_layout');
        expect(refusalOf('publish', 4, { ...DRAFT, revision: 5 }, 'alice')).toBe('changed');
        expect(refusalOf('publish', 4, DRAFT, ' ALICE ')).toBe('four_eyes_publish');
        expect(refusalOf('publish', 4, DRAFT, 'bob')).toBeNull();
        expect(refusalOf('retire', 3, { ...PUBLISHED, status: 'retired' }, 'alice')).toBe('retired');
        expect(refusalOf('retire', 3, PUBLISHED, 'alice')).toBe('four_eyes_retire');
        // Setting a draft aside asks nobody else, so its author is not refused under four-eyes.
        expect(refusalOf('retire', 4, DRAFT, 'alice')).toBeNull();
    });
});
