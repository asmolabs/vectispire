import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
    CHECKLIST,
    CONFIRMED_PREVIEW,
    CONTEXT,
    DRAFT_REVISION,
    LAYOUT,
    LINE_HISTORY,
    OFFERED,
    PROJECT_ID,
    TEMPLATE,
    VERSION
} from '../testing/checklists.fixtures';
import { asSchema } from '../testing/contract';
import { ChecklistsApi, MAX_EVIDENCE_BYTES, MAX_WORKBOOK_BYTES, XLSX_TYPE } from './checklists.api';

/**
 * The checklist template client, pinned route by route. What matters most: the workbook leaves as
 * the raw body with the xlsx type (there is no multipart route), and publishing names the revision
 * it is given — never one the client read on its own.
 */
describe('the checklist template client', () => {
    let api: ChecklistsApi;
    let http: HttpTestingController;

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
        api = TestBed.inject(ChecklistsApi);
        http = TestBed.inject(HttpTestingController);
    });

    afterEach(() => http.verify());

    it('lists the templates and reads one', () => {
        api.checklistTemplates().subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/checklist-templates' }).flush([TEMPLATE]);

        api.checklistTemplate('release').subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/checklist-templates/release' }).flush(TEMPLATE);
    });

    it('sends the workbook as the raw body, typed as xlsx, with the name and label as parameters', () => {
        const workbook = new Blob([new Uint8Array([0x50, 0x4b, 0x03, 0x04])], { type: XLSX_TYPE });
        api.importChecklistWorkbook('release', workbook, { name: '  Release checklist ', label: '2026' }).subscribe();

        const request = http.expectOne((call) => call.url === '/api/v1/checklist-templates/release/versions');
        expect(request.request.method).toBe('POST');
        expect(request.request.body).toBe(workbook);
        expect(request.request.headers.get('Content-Type')).toBe(XLSX_TYPE);
        expect(request.request.params.get('name')).toBe('Release checklist');
        expect(request.request.params.get('label')).toBe('2026');
        request.flush(VERSION, { status: 201, statusText: 'Created' });
    });

    it('leaves blank parameters out rather than sending them empty', () => {
        api.importChecklistWorkbook('release', new Blob(['x']), { name: ' ', label: null }).subscribe();

        const request = http.expectOne((call) => call.url === '/api/v1/checklist-templates/release/versions');
        expect(request.request.params.keys()).toEqual([]);
        request.flush(VERSION, { status: 201, statusText: 'Created' });
    });

    it('holds the ceiling the server holds: ten megabytes as Spring reads them', () => {
        expect(MAX_WORKBOOK_BYTES).toBe(10_485_760);
    });

    it('reads a version and its preview, naming the sheet only when one is chosen', () => {
        api.checklistVersion('release', 2).subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/checklist-templates/release/versions/2' }).flush(VERSION);

        api.checklistPreview('release', 2).subscribe();
        const plain = http.expectOne((call) => call.url === '/api/v1/checklist-templates/release/versions/2/preview');
        expect(plain.request.params.has('sheet')).toBe(false);
        plain.flush(CONFIRMED_PREVIEW);

        api.checklistPreview('release', 2, 'Lists').subscribe();
        const named = http.expectOne((call) => call.url === '/api/v1/checklist-templates/release/versions/2/preview');
        expect(named.request.params.get('sheet')).toBe('Lists');
        named.flush(CONFIRMED_PREVIEW);
    });

    it('confirms a layout and replaces the pairs with the bodies the server reads, on the revision shown', () => {
        api.confirmChecklistLayout('release', 2, 4, LAYOUT).subscribe();
        const layout = http.expectOne(
            (request) =>
                request.method === 'PUT' && request.url === '/api/v1/checklist-templates/release/versions/2/layout'
        );
        expect(layout.request.params.get('revision')).toBe('4');
        expect(asSchema('ChecklistLayoutForm', layout.request.body)).toEqual(LAYOUT);
        layout.flush(VERSION);

        const pairs = [
            { added: 'text:secrets are rotated every ninety days', removed: 'text:secrets are rotated yearly' }
        ];
        api.pairChecklistItems('release', 2, 5, pairs).subscribe();
        const paired = http.expectOne(
            (request) =>
                request.method === 'PUT' && request.url === '/api/v1/checklist-templates/release/versions/2/pairs'
        );
        expect(paired.request.params.get('revision')).toBe('5');
        expect(asSchema('ChecklistPairsRequest', paired.request.body)).toEqual({ pairs });
        paired.flush(VERSION);
    });

    it('sets the proof the lines named ask for, on the revision shown, in the body the server reads', () => {
        const items = [
            { itemKey: 'text:a', evidenceKind: 'file' as const, evidenceValidityMonths: 12 },
            { itemKey: 'text:b', evidenceKind: 'none' as const, evidenceValidityMonths: null }
        ];
        api.setChecklistEvidence('release', 2, 6, items).subscribe();
        const request = http.expectOne(
            (call) => call.method === 'PUT' && call.url === '/api/v1/checklist-templates/release/versions/2/evidence'
        );
        expect(request.request.params.get('revision')).toBe('6');
        expect(asSchema('ChecklistEvidenceRequest', request.request.body)).toEqual({ items });
        request.flush(VERSION);
    });

    it('derives, with the label only when there is one', () => {
        api.deriveChecklistVersion('release', 1, ' 2027 ').subscribe();
        const labelled = http.expectOne({
            method: 'POST',
            url: '/api/v1/checklist-templates/release/versions/1/derive'
        });
        expect(asSchema('ChecklistDeriveRequest', labelled.request.body)).toEqual({ label: '2027' });
        labelled.flush(VERSION, { status: 201, statusText: 'Created' });

        api.deriveChecklistVersion('release', 1).subscribe();
        const bare = http.expectOne({ method: 'POST', url: '/api/v1/checklist-templates/release/versions/1/derive' });
        expect(bare.request.body).toEqual({});
        bare.flush(VERSION, { status: 201, statusText: 'Created' });
    });

    it('publishes naming the revision it is given, and retires', () => {
        api.publishChecklistVersion('release', 2, 4).subscribe();
        const publish = http.expectOne({
            method: 'POST',
            url: '/api/v1/checklist-templates/release/versions/2/publish'
        });
        expect(asSchema('ChecklistPublishRequest', publish.request.body)).toEqual({ revision: 4 });
        publish.flush(VERSION);

        api.retireChecklistVersion('release', 1).subscribe();
        http.expectOne({ method: 'POST', url: '/api/v1/checklist-templates/release/versions/1/retire' }).flush(VERSION);
    });
});

/**
 * The project checklist client. What matters most: every write carries the edition it is given —
 * the one on screen — in the body the server reads (or, for a file, in the query), opening names no
 * edition when none is given, and a proof's file leaves as the raw body typed as the file says.
 */
describe('the project checklist client', () => {
    let api: ChecklistsApi;
    let http: HttpTestingController;
    const BASE = '/api/v1/projects/7/checklists';

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
        api = TestBed.inject(ChecklistsApi);
        http = TestBed.inject(HttpTestingController);
    });

    afterEach(() => http.verify());

    it('lists the revisions, reads the context and the offered versions, one revision and a line history', () => {
        api.projectChecklists(PROJECT_ID).subscribe();
        http.expectOne({ method: 'GET', url: BASE }).flush([DRAFT_REVISION]);

        api.projectChecklistContext(PROJECT_ID).subscribe();
        http.expectOne({ method: 'GET', url: `${BASE}/context` }).flush(CONTEXT);

        api.offeredChecklistVersions(PROJECT_ID).subscribe();
        http.expectOne({ method: 'GET', url: `${BASE}/offered` }).flush(OFFERED);

        api.projectChecklist(PROJECT_ID, 2).subscribe();
        http.expectOne({ method: 'GET', url: `${BASE}/2` }).flush(CHECKLIST);

        api.checklistLineHistory(PROJECT_ID, 2, 102).subscribe();
        http.expectOne({ method: 'GET', url: `${BASE}/2/items/102/history` }).flush(LINE_HISTORY);
    });

    it('opens with no edition when none is given, and moves naming the newest revision edition', () => {
        api.openProjectChecklist(PROJECT_ID, 'release', 1, null).subscribe();
        const opened = http.expectOne({ method: 'POST', url: BASE });
        expect(asSchema('ChecklistOpenRequest', opened.request.body)).toEqual({ template: 'release', version: 1 });
        expect('edition' in (opened.request.body as object)).toBe(false);
        opened.flush(CHECKLIST, { status: 201, statusText: 'Created' });

        api.openProjectChecklist(PROJECT_ID, 'release', 2, 5).subscribe();
        const moved = http.expectOne({ method: 'POST', url: BASE });
        expect(asSchema('ChecklistOpenRequest', moved.request.body)).toEqual({
            template: 'release',
            version: 2,
            edition: 5
        });
        moved.flush(CHECKLIST, { status: 201, statusText: 'Created' });
    });

    it('answers with the value, the trimmed comment and the edition; a blank comment is left out', () => {
        api.answerChecklistLine(PROJECT_ID, 2, 103, 'no', '  Two criticals, fix planned. ', 5).subscribe();
        const commented = http.expectOne({ method: 'POST', url: `${BASE}/2/items/103/answers` });
        expect(asSchema('ChecklistAnswerRequest', commented.request.body)).toEqual({
            value: 'no',
            comment: 'Two criticals, fix planned.',
            edition: 5
        });
        commented.flush(CHECKLIST, { status: 201, statusText: 'Created' });

        api.answerChecklistLine(PROJECT_ID, 2, 101, 'yes', '   ', 6).subscribe();
        const bare = http.expectOne({ method: 'POST', url: `${BASE}/2/items/101/answers` });
        expect(asSchema('ChecklistAnswerRequest', bare.request.body)).toEqual({ value: 'yes', edition: 6 });
        bare.flush(CHECKLIST, { status: 201, statusText: 'Created' });
    });

    it('confirms, withdraws and moves the revision through its life naming the edition', () => {
        const writes: [() => unknown, string][] = [
            [() => api.confirmChecklistAnswer(PROJECT_ID, 2, 102, 5).subscribe(), `${BASE}/2/items/102/confirmation`],
            [
                () => api.withdrawChecklistEvidence(PROJECT_ID, 2, 900, 5).subscribe(),
                `${BASE}/2/evidence/900/withdrawal`
            ],
            [() => api.submitChecklist(PROJECT_ID, 2, 5).subscribe(), `${BASE}/2/submission`],
            [() => api.signOffChecklist(PROJECT_ID, 2, 5).subscribe(), `${BASE}/2/sign-off`],
            [() => api.reopenChecklist(PROJECT_ID, 2, 5).subscribe(), `${BASE}/2/reopen`]
        ];
        for (const [write, url] of writes) {
            write();
            const request = http.expectOne({ method: 'POST', url });
            expect(asSchema('ChecklistEditionRequest', request.request.body)).toEqual({ edition: 5 });
            request.flush(CHECKLIST);
        }

        api.returnChecklist(PROJECT_ID, 2, ' Line 3 needs its evidence. ', 8).subscribe();
        const returned = http.expectOne({ method: 'POST', url: `${BASE}/2/return` });
        expect(asSchema('ChecklistReturnRequest', returned.request.body)).toEqual({
            reason: 'Line 3 needs its evidence.',
            edition: 8
        });
        returned.flush(CHECKLIST);
    });

    it('attaches a link with the day and the edition', () => {
        api.attachChecklistLink(
            PROJECT_ID,
            2,
            102,
            ' https://wiki.example.invalid/rotation ',
            '2026-09-01',
            5
        ).subscribe();
        const request = http.expectOne({ method: 'POST', url: `${BASE}/2/items/102/evidence/links` });
        expect(asSchema('ChecklistLinkRequest', request.request.body)).toEqual({
            link: 'https://wiki.example.invalid/rotation',
            performedOn: '2026-09-01',
            edition: 5
        });
        request.flush(CHECKLIST, { status: 201, statusText: 'Created' });
    });

    it('sends a file as the raw body typed as the file says, with its name, day and edition in the query', () => {
        const file = new File([new Uint8Array([0x25, 0x50, 0x44, 0x46])], 'pentest report.pdf', {
            type: 'application/pdf'
        });
        api.attachChecklistFile(PROJECT_ID, 2, 101, file, '2026-09-01', 5).subscribe();

        const request = http.expectOne((call) => call.url === `${BASE}/2/items/101/evidence/files`);
        expect(request.request.method).toBe('POST');
        expect(request.request.body).toBe(file);
        expect(request.request.headers.get('Content-Type')).toBe('application/pdf');
        expect(request.request.params.get('name')).toBe('pentest report.pdf');
        expect(request.request.params.get('performedOn')).toBe('2026-09-01');
        expect(request.request.params.get('edition')).toBe('5');
        request.flush(CHECKLIST, { status: 201, statusText: 'Created' });
    });

    it('types a file the browser could not type as opaque bytes', () => {
        api.attachChecklistFile(PROJECT_ID, 2, 101, new File(['x'], 'notes'), '2026-09-01', 5).subscribe();
        const request = http.expectOne((call) => call.url === `${BASE}/2/items/101/evidence/files`);
        expect(request.request.headers.get('Content-Type')).toBe('application/octet-stream');
        request.flush(CHECKLIST, { status: 201, statusText: 'Created' });
    });

    it('fetches a proof file as a blob with the response, for a download', () => {
        api.checklistEvidenceFile(PROJECT_ID, 2, 901).subscribe();
        const request = http.expectOne({ method: 'GET', url: `${BASE}/2/evidence/901/file` });
        expect(request.request.responseType).toBe('blob');
        request.flush(new Blob(['%PDF']));
    });

    it('holds the ceiling the server holds: twenty-five megabytes as Spring reads them', () => {
        expect(MAX_EVIDENCE_BYTES).toBe(26_214_400);
    });
});
