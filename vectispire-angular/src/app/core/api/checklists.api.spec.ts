import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { CONFIRMED_PREVIEW, LAYOUT, TEMPLATE, VERSION } from '../testing/checklists.fixtures';
import { asSchema } from '../testing/contract';
import { ChecklistsApi, MAX_WORKBOOK_BYTES, XLSX_TYPE } from './checklists.api';

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

    it('confirms a layout and replaces the pairs with the bodies the server reads', () => {
        api.confirmChecklistLayout('release', 2, LAYOUT).subscribe();
        const layout = http.expectOne({ method: 'PUT', url: '/api/v1/checklist-templates/release/versions/2/layout' });
        expect(asSchema('ChecklistLayoutForm', layout.request.body)).toEqual(LAYOUT);
        layout.flush(VERSION);

        const pairs = [
            { added: 'text:secrets are rotated every ninety days', removed: 'text:secrets are rotated yearly' }
        ];
        api.pairChecklistItems('release', 2, pairs).subscribe();
        const paired = http.expectOne({ method: 'PUT', url: '/api/v1/checklist-templates/release/versions/2/pairs' });
        expect(asSchema('ChecklistPairsRequest', paired.request.body)).toEqual({ pairs });
        paired.flush(VERSION);
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
