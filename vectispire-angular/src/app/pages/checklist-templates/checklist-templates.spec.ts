import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting, TestRequest } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import type { ChecklistPreview } from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import { asSchema } from '@/app/core/testing/contract';
import {
    conflict,
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
    CONFLICT_TYPES,
    conflictOf,
    ChecklistTemplates,
    draftFrom,
    EVIDENCE_KIND_KEYS,
    evidenceChangesOf,
    gridOf,
    HEADER_KEYS,
    layoutOf,
    layoutProblem,
    PROBLEM_KEYS,
    REFUSAL_KEYS,
    STATUS_KEYS,
    validityAllowed
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

    it('does not send a name for a template that exists — the server would ignore it — and says why a draft refuses it', async () => {
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
        request.flush(conflict('checklist-template-has-draft'), { status: 409, statusText: 'Conflict' });
        fixture.detectChanges();
        expect(text('[data-testid="upload-error"]')).toBe(
            'This template already has a draft, and it has one at a time: publish that draft or set it aside before importing or deriving another version.'
        );
    });

    it("shows any other refusal of an import in the server's own words", async () => {
        await start('CISO');
        type('#checklist-slug', 'release');
        const input = dom().querySelector('#checklist-file') as HTMLInputElement;
        Object.defineProperty(input, 'files', { value: [new File(['x'], 'r.xlsx')], configurable: true });
        input.dispatchEvent(new Event('change'));
        fixture.detectChanges();
        button('import-workbook').click();

        http.expectOne((call) => call.method === 'POST').flush(
            { type: 'about:blank', title: 'Bad Request', status: 400, detail: 'The file is not an .xlsx workbook.' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();
        expect(text('[data-testid="upload-error"]')).toBe('The file is not an .xlsx workbook.');
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

    // ------------------------------------------------------------------ what proof each line asks for

    function choose(selector: string, label: string): void {
        const select = dom().querySelector(selector) as HTMLSelectElement;
        const index = Array.from(select.options).findIndex((option) => option.textContent?.trim() === label);
        if (index < 0) throw new Error(`no option ${label} in ${selector}`);
        select.selectedIndex = index;
        select.dispatchEvent(new Event('change'));
        fixture.detectChanges();
    }

    /** `ngModel` writes a value, and its `disabled`, a tick after the change it follows. */
    async function settle(): Promise<void> {
        await fixture.whenStable();
        fixture.detectChanges();
    }

    const months = (id: number) => dom().querySelector(`#evidence-months-${id}`) as HTMLInputElement;
    const evidencePut = () => http.expectOne((call) => call.method === 'PUT' && call.url === `${VERSION_URL}/evidence`);

    /** Version 2 as the server answers once line 2 asks for a link or a file, valid a year, and line 3 for a file. */
    const WITH_EVIDENCE = {
        ...VERSION,
        version: { ...DRAFT, revision: 5 },
        items: [
            VERSION.items[0],
            { ...VERSION.items[1], evidenceKind: 'link_or_file' as const, evidenceValidityMonths: 12 },
            { ...VERSION.items[2], evidenceKind: 'file' as const }
        ]
    };

    it('sets what proof each line asks for on a confirmed draft, sending only the lines changed on the revision shown', async () => {
        await start('CISO', 'bob');
        openDraft(CONFIRMED_PREVIEW);

        expect(text('[data-testid="evidence-explain"]')).toContain('Only the lines you change are sent');
        expect(button('save-evidence').disabled).toBe(true);
        // Each control is named for its row: a screen reader hears which line it sets.
        expect(text('label[for="evidence-kind-102"]')).toBe('Proof asked by the item of row 6');
        expect(text('label[for="evidence-months-102"]')).toBe('Months a proof of the item of row 6 holds');
        // Asking nothing, a line has no validity to give.
        await settle();
        expect(months(102).disabled).toBe(true);

        choose('#evidence-kind-102', 'Link or file');
        await settle();
        expect(months(102).disabled).toBe(false);
        type('#evidence-months-102', '12');
        choose('#evidence-kind-103', 'File');
        expect(button('save-evidence').textContent).toContain('Save the proof asked (2 changed)');
        button('save-evidence').click();

        const request = evidencePut();
        expect(request.request.params.get('revision')).toBe('4');
        expect(asSchema('ChecklistEvidenceRequest', request.request.body)).toEqual({
            items: [
                {
                    itemKey: 'text:secrets are rotated every ninety days',
                    evidenceKind: 'link_or_file',
                    evidenceValidityMonths: 12
                },
                {
                    itemKey: 'text:dependencies carry no known critical vulnerability',
                    evidenceKind: 'file',
                    evidenceValidityMonths: null
                }
            ]
        });
        request.flush(WITH_EVIDENCE);
        fixture.detectChanges();

        expect(text('[data-testid="notice"]')).toBe('Proof asked set on 2 items.');
        // The view answered is adopted: its revision is the one the next write names.
        expect(text('[data-testid="shown-revision"]')).toBe('5');
        http.expectOne((call) => call.url === `${VERSION_URL}/preview`).flush({
            ...CONFIRMED_PREVIEW,
            version: WITH_EVIDENCE.version
        });
        http.expectOne(VERSION_URL).flush(WITH_EVIDENCE);
        http.expectOne(`${TEMPLATE_URL}/release`).flush(TEMPLATE);
        await settle();
        expect(
            (dom().querySelector('#evidence-kind-102') as HTMLSelectElement).selectedOptions[0].textContent?.trim()
        ).toBe('Link or file');
        expect(months(102).value).toBe('12');
        expect(button('save-evidence').disabled).toBe(true);
    });

    it('sends nothing for a line edited back to what it asked', async () => {
        await start('CISO', 'bob');
        openDraft(CONFIRMED_PREVIEW);

        choose('#evidence-kind-101', 'File');
        expect(button('save-evidence').disabled).toBe(false);
        choose('#evidence-kind-101', 'None');
        expect(button('save-evidence').disabled).toBe(true);
    });

    it('drops the validity of a line set back to asking nothing', async () => {
        await start('CISO', 'bob');
        openDraft(CONFIRMED_PREVIEW, WITH_EVIDENCE);

        await settle();
        expect(months(102).value).toBe('12');
        choose('#evidence-kind-102', 'None');
        await settle();
        expect(months(102).disabled).toBe(true);
        expect(months(102).value).toBe('');
        button('save-evidence').click();

        const request = evidencePut();
        expect(request.request.body).toEqual({
            items: [
                {
                    itemKey: 'text:secrets are rotated every ninety days',
                    evidenceKind: 'none',
                    evidenceValidityMonths: null
                }
            ]
        });
        request.flush(VERSION);
        answerRereads();
    });

    it.each(['0', '121', '1.5'])('refuses a validity of %s months before sending it', async (value) => {
        await start('CISO', 'bob');
        openDraft(CONFIRMED_PREVIEW);

        choose('#evidence-kind-102', 'File');
        type('#evidence-months-102', value);
        button('save-evidence').click();
        fixture.detectChanges();

        expect(text('[data-testid="evidence-error"]')).toBe(
            'A validity is a whole number of months from 1 to 120, or left empty for a proof that does not expire.'
        );
        http.expectNone((call) => call.method === 'PUT');
    });

    it('accepts both bounds, 1 and 120 months', () => {
        const change = { itemKey: 'k', evidenceKind: 'file' as const, evidenceValidityMonths: 1 };
        expect(validityAllowed(change)).toBe(true);
        expect(validityAllowed({ ...change, evidenceValidityMonths: 120 })).toBe(true);
        expect(validityAllowed({ ...change, evidenceValidityMonths: null })).toBe(true);
        expect(validityAllowed({ ...change, evidenceValidityMonths: 0 })).toBe(false);
        expect(validityAllowed({ ...change, evidenceValidityMonths: 121 })).toBe(false);
        expect(validityAllowed({ ...change, evidenceKind: 'none', evidenceValidityMonths: 12 })).toBe(false);
    });

    it("explains a requirement refused for a draft changed meanwhile, and shows another refusal in the server's words", async () => {
        await start('CISO', 'bob');
        openDraft(CONFIRMED_PREVIEW);

        choose('#evidence-kind-102', 'File');
        button('save-evidence').click();
        refuse(evidencePut(), 'checklist-template-changed');
        expect(text('[data-testid="refusal-message"]')).toContain('you had revision 4 on screen');
        expect(dom().querySelector('[data-testid="evidence-error"]')).toBeNull();

        button('save-evidence').click();
        evidencePut().flush(
            { type: 'about:blank', title: 'Bad Request', status: 400, detail: 'Line "text:x" is not in version 2.' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();
        expect(text('[data-testid="evidence-error"]')).toBe('Line "text:x" is not in version 2.');
        expect(dom().querySelector('[data-testid="refusal"]')).toBeNull();
    });

    it('offers no requirement to set on a draft whose layout is not confirmed', async () => {
        await start('CISO', 'bob');
        openDraft(PREVIEW);

        expect(dom().querySelector('#evidence-kind-101')).toBeNull();
        expect(dom().querySelector('#save-evidence')).toBeNull();
        expect(text('[data-testid="item-5"] [data-testid="item-evidence"]')).toBe('None');
    });

    it('shows each line of a published version with what it asks, and nothing to change', async () => {
        await start('ADMIN', 'bob');
        button('Open version 1 of release').click();
        fixture.detectChanges();
        http.expectOne((call) => call.url === `${TEMPLATE_URL}/release/versions/1/preview`).flush({
            ...CONFIRMED_PREVIEW,
            version: PUBLISHED
        });
        http.expectOne(`${TEMPLATE_URL}/release/versions/1`).flush({ ...WITH_EVIDENCE, version: PUBLISHED });
        fixture.detectChanges();

        expect(text('[data-testid="item-5"] [data-testid="item-evidence"]')).toBe('None');
        expect(text('[data-testid="item-6"] [data-testid="item-evidence"]')).toBe('Link or file · valid 12 months');
        expect(text('[data-testid="item-7"] [data-testid="item-evidence"]')).toBe('File');
        expect(dom().querySelector('#evidence-kind-102')).toBeNull();
        expect(dom().querySelector('#save-evidence')).toBeNull();
    });

    it('shows an auditor what each line of a draft asks, and nothing to change', async () => {
        await start('AUDITOR');
        openDraft(CONFIRMED_PREVIEW, WITH_EVIDENCE);

        expect(text('[data-testid="item-6"] [data-testid="item-evidence"]')).toBe('Link or file · valid 12 months');
        expect(dom().querySelector('select')).toBeNull();
        expect(dom().querySelector('#save-evidence')).toBeNull();
        expect(dom().querySelector('[data-testid="evidence-explain"]')).toBeNull();
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

    /**
     * The 409, naming its cause in its type — and nothing read after it: the cause is the problem's,
     * and the version is not read again to guess it.
     */
    function refuse(request: TestRequest, token: string, detail?: string): void {
        request.flush(conflict(token, detail), { status: 409, statusText: 'Conflict' });
        fixture.detectChanges();
        http.expectNone((call) => call.method === 'GET');
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

    /** The settings catalog as the page reads it: only the four-eyes entry matters here. */
    function answerFourEyes(value: 'true' | 'false'): void {
        http.expectOne({ method: 'GET', url: '/api/v1/settings' }).flush({
            settings: [
                {
                    key: 'triage_four_eyes_required',
                    type: 'boolean',
                    section: 'triage',
                    label: 'Four-eyes',
                    help: '',
                    default: 'true',
                    value
                }
            ]
        });
        fixture.detectChanges();
    }

    it("withholds publishing from the draft's author under four-eyes, and says who may publish", async () => {
        await start('CISO', 'Alice');
        openDraft(CONFIRMED_PREVIEW);
        // The name compared as the server compares it, without case.
        answerFourEyes('true');

        const publish = button('publish-version');
        expect(publish.disabled).toBe(true);
        expect(text('#publish-four-eyes')).toContain(
            'a security lead (platform governor, administrator or CISO) who did not write it'
        );
        // Setting it aside is not the four-eyes rule's to withhold.
        expect(button('retire-version').disabled).toBe(false);
    });

    it('withholds publishing from an author when the setting cannot be read: four-eyes ships switched on', async () => {
        await start('CISO', 'alice');
        openDraft(CONFIRMED_PREVIEW);
        http.expectOne('/api/v1/settings').flush(null, { status: 500, statusText: 'Server Error' });
        fixture.detectChanges();

        expect(button('publish-version').disabled).toBe(true);
        expect(dom().querySelector('[data-testid="publish-four-eyes"]')).not.toBeNull();
    });

    it('offers publishing to a security lead who wrote none of the draft, without reading the settings', async () => {
        await start('CISO', 'bob');
        openDraft(CONFIRMED_PREVIEW);

        http.expectNone('/api/v1/settings');
        expect(button('publish-version').disabled).toBe(false);
        expect(dom().querySelector('[data-testid="publish-four-eyes"]')).toBeNull();
    });

    it('offers publishing to the author when four-eyes is off', async () => {
        await start('CISO', 'alice');
        openDraft(CONFIRMED_PREVIEW);
        answerFourEyes('false');

        expect(button('publish-version').disabled).toBe(false);
        expect(dom().querySelector('[data-testid="publish-four-eyes"]')).toBeNull();
    });

    it('explains a four-eyes refusal met anyway — the setting switched on since it was read', async () => {
        await start('CISO', 'alice');
        openDraft(CONFIRMED_PREVIEW);
        answerFourEyes('false');
        button('publish-version').click();
        fixture.detectChanges();
        button('confirm-act').click();

        refuse(http.expectOne({ method: 'POST', url: `${VERSION_URL}/publish` }), 'checklist-four-eyes');
        expect(text('[data-testid="refusal"]')).toContain('You wrote this draft');
        expect(text('[data-testid="refusal"]')).toContain('a second person must publish it');
        expect(text('[data-testid="refusal"]')).toContain('Written by: alice.');
        expect(dom().querySelector('#reload-version')).toBeNull();
    });

    const SENTENCES: [string, string, boolean][] = [
        [
            'checklist-template-changed',
            'This version changed since you read it: you had revision 4 on screen, and somebody else has edited, published or retired it since. Nothing was written over their change. Reload it, look at what changed, then try again.',
            true
        ],
        [
            'checklist-template-not-draft',
            'This version is no longer a draft: it is published or retired, and a published version never changes. To change it, derive a new draft from the published version.',
            true
        ],
        [
            'checklist-template-no-layout',
            'This draft has no confirmed layout, so it has no items yet: confirm its layout first.',
            true
        ],
        [
            'checklist-template-has-draft',
            'This template already has a draft, and it has one at a time: publish that draft or set it aside before importing or deriving another version.',
            true
        ],
        [
            'checklist-template-not-published',
            "A new draft is derived from a published version only, and this one is a draft or retired. Derive it from the template's published version instead.",
            true
        ],
        ['checklist-template-retired', 'This version is already retired. Reload it to see where it stands.', true],
        [
            'checklist-template-nothing-to-pair',
            'This draft follows no published version, so there is nothing to pair its items with: every item is new.',
            false
        ],
        [
            'checklist-four-eyes',
            'You wrote this draft — you imported or derived it, confirmed its layout, paired its items or set what proof its lines ask for. Four-eyes approval is on, so a second person must publish it: another platform governor, administrator or CISO who did not write it. Written by: alice.',
            false
        ]
    ];

    it.each(SENTENCES)('explains a 409 %s in one sentence of its own', async (token, sentence, reload) => {
        await start('CISO', 'bob');
        refuse(publishShown(), token);

        expect(text('[data-testid="refusal-message"]')).toBe(sentence);
        expect(dom().querySelector('#reload-version') !== null).toBe(reload);
    });

    it('explains a draft edited since it was read, naming the revision reviewed, and offers to reload', async () => {
        await start('CISO', 'bob');
        refuse(publishShown(), 'checklist-template-changed', 'Version 2 has changed.');

        expect(text('[data-testid="refusal"]')).toContain('you had revision 4 on screen');
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

    it.each([
        ['names a cause this screen does not know', conflict('checklist-template-something-new', 'Something new.')],
        ['names no cause', { type: 'about:blank', title: 'Conflict', status: 409, detail: 'Something new.' }]
    ])("falls back to the server's sentence for a 409 that %s", async (_, body) => {
        await start('CISO', 'bob');
        publishShown().flush(body, { status: 409, statusText: 'Conflict' });
        fixture.detectChanges();

        expect(text('[data-testid="panel-error"]')).toBe('Something new.');
        expect(dom().querySelector('[data-testid="refusal"]')).toBeNull();
        http.expectNone((call) => call.method === 'GET');
    });

    it('explains a layout confirmed over a change made meanwhile, and offers to reload', async () => {
        await start('CISO', 'bob');
        openDraft(CONFIRMED_PREVIEW);
        button('confirm-layout').click();

        refuse(
            http.expectOne((call) => call.method === 'PUT' && call.url === `${VERSION_URL}/layout`),
            'checklist-template-changed'
        );
        expect(text('[data-testid="refusal"]')).toContain('you had revision 4 on screen');
        expect(dom().querySelector('[data-testid="layout-error"]')).toBeNull();
        expect(dom().querySelector('#reload-version')).not.toBeNull();
    });

    it('says a first version has nothing to pair with when the server refuses a pair', async () => {
        await start('CISO', 'bob');
        openDraft(CONFIRMED_PREVIEW);
        const page = fixture.componentInstance;
        page.pairAdded.set('text:secrets are rotated every ninety days');
        page.pairRemoved.set('text:secrets are rotated yearly');
        fixture.detectChanges();
        button('pair-items').click();

        refuse(
            http.expectOne((call) => call.method === 'PUT' && call.url === `${VERSION_URL}/pairs`),
            'checklist-template-nothing-to-pair'
        );
        expect(text('[data-testid="refusal"]')).toContain('nothing to pair its items with');
        expect(dom().querySelector('#reload-version')).toBeNull();
    });

    it('says a template has a draft already when deriving from its published version', async () => {
        await start('ADMIN', 'bob');
        button('Open version 1 of release').click();
        fixture.detectChanges();
        http.expectOne((call) => call.url === `${TEMPLATE_URL}/release/versions/1/preview`).flush({
            ...CONFIRMED_PREVIEW,
            version: PUBLISHED
        });
        http.expectOne(`${TEMPLATE_URL}/release/versions/1`).flush({ ...VERSION, version: PUBLISHED });
        fixture.detectChanges();
        button('derive-version').click();

        refuse(
            http.expectOne({ method: 'POST', url: `${TEMPLATE_URL}/release/versions/1/derive` }),
            'checklist-template-has-draft'
        );
        expect(text('[data-testid="refusal"]')).toContain('This template already has a draft');
        expect(dom().querySelector('[data-testid="panel-error"]')).toBeNull();
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
        refuse(
            http.expectOne({ method: 'POST', url: `${TEMPLATE_URL}/release/versions/1/retire` }),
            'checklist-four-eyes'
        );

        expect(text('[data-testid="refusal-message"]')).toBe(
            'You wrote this version. Four-eyes approval is on, so a second person must retire it: another platform governor, administrator or CISO who did not write it. Written by: alice.'
        );
    });

    // ------------------------------------------------------------------ the words

    it('has every label its maps name, in both languages — keys the i18n check cannot count', () => {
        const lookup = (bundle: unknown, key: string) =>
            key
                .split('.')
                .reduce<unknown>((node, part) => (node as Record<string, unknown> | undefined)?.[part], bundle);
        for (const map of [
            COLUMN_KEYS,
            HEADER_KEYS,
            STATUS_KEYS,
            CHANGE_KEYS,
            REFUSAL_KEYS,
            PROBLEM_KEYS,
            EVIDENCE_KIND_KEYS
        ]) {
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

    it('sends the lines changed only, in the version order, a line asking nothing without a validity', () => {
        const [first, second, third] = VERSION.items;
        expect(evidenceChangesOf(VERSION.items, {})).toEqual([]);
        expect(
            evidenceChangesOf(VERSION.items, {
                [third.itemKey]: { kind: 'file', months: 6 },
                [first.itemKey]: { kind: 'none', months: null },
                [second.itemKey]: { kind: 'none', months: 24 }
            })
        ).toEqual([{ itemKey: third.itemKey, evidenceKind: 'file', evidenceValidityMonths: 6 }]);
        // A validity alone is a change on a line that asks for a proof.
        const asking = [{ ...first, evidenceKind: 'file' as const, evidenceValidityMonths: 12 }];
        expect(evidenceChangesOf(asking, { [first.itemKey]: { kind: 'file', months: 24 } })).toEqual([
            { itemKey: first.itemKey, evidenceKind: 'file', evidenceValidityMonths: 24 }
        ]);
        expect(evidenceChangesOf(asking, { [first.itemKey]: { kind: 'file', months: 12 } })).toEqual([]);
    });

    it('knows every cause the template routes name, and no other', () => {
        // `ChecklistConflict.Cause`, the template causes and the one shared token — a cause added there
        // and not here falls back to the English detail, which is survivable; a token misspelt here
        // never matches, which is not.
        expect(Object.keys(CONFLICT_TYPES).sort()).toEqual(
            [
                'checklist-template-not-draft',
                'checklist-template-no-layout',
                'checklist-template-changed',
                'checklist-template-has-draft',
                'checklist-template-not-published',
                'checklist-template-retired',
                'checklist-template-nothing-to-pair',
                'checklist-four-eyes'
            ]
                .map((token) => `urn:vectispire:problem:${token}`)
                .sort()
        );
        expect(conflictOf({ error: conflict('checklist-template-retired') })).toBe('retired');
        // The project checklists' own causes are not this screen's.
        expect(conflictOf({ error: conflict('checklist-changed') })).toBeNull();
        expect(conflictOf({ error: 'text' })).toBeNull();
        expect(conflictOf(null)).toBeNull();
    });
});
