import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ForgesApi } from './forges.api';

/**
 * The forge client, pinned route by route: every method the screens call, its verb, its path and its body —
 * the token sent in a body and nowhere else, the selection sent whole with each gesture.
 */
describe('the forge client', () => {
    let api: ForgesApi;
    let http: HttpTestingController;
    const ID = '6f1c2a9e-0b7d-4c3e-9a51-3d2e8f40b7aa';
    const BASE = `/api/v1/forge-connections/${ID}`;

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
        api = TestBed.inject(ForgesApi);
        http = TestBed.inject(HttpTestingController);
    });

    afterEach(() => http.verify());

    it('lists, reads, creates, changes, rotates and deletes a connection', () => {
        api.forgeConnections().subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/forge-connections' }).flush([]);

        api.forgeConnection(ID).subscribe();
        http.expectOne({ method: 'GET', url: BASE }).flush({});

        api.createForgeConnection({ name: 'n', kind: 'gitlab', token: 'glpat-x' }).subscribe(); // gitleaks:allow
        const created = http.expectOne({ method: 'POST', url: '/api/v1/forge-connections' });
        expect(created.request.body).toEqual({ name: 'n', kind: 'gitlab', token: 'glpat-x' }); // gitleaks:allow
        created.flush({});

        api.updateForgeConnection(ID, { caPem: '' }).subscribe();
        const changed = http.expectOne({ method: 'PATCH', url: BASE });
        expect(changed.request.body).toEqual({ caPem: '' });
        changed.flush({});

        api.replaceForgeConnectionToken(ID, 'glpat-new').subscribe(); // gitleaks:allow
        const rotated = http.expectOne({ method: 'PUT', url: `${BASE}/token` });
        expect(rotated.request.body).toEqual({ token: 'glpat-new' }); // gitleaks:allow
        rotated.flush({});

        api.deleteForgeConnection(ID).subscribe();
        http.expectOne({ method: 'DELETE', url: BASE }).flush(null, { status: 204, statusText: 'No Content' });
    });

    it('requests, lists and reads discoveries, and pages their comparison', () => {
        api.requestForgeDiscovery(ID).subscribe();
        http.expectOne({ method: 'POST', url: `${BASE}/discoveries` }).flush({});

        api.forgeDiscoveries(ID).subscribe();
        http.expectOne({ method: 'GET', url: `${BASE}/discoveries` }).flush([]);

        api.forgeDiscovery(ID, 12).subscribe();
        http.expectOne({ method: 'GET', url: `${BASE}/discoveries/12` }).flush({});

        api.discoveredRepositories(ID, 12, 'gone', 50, 100).subscribe();
        http.expectOne({
            method: 'GET',
            url: `${BASE}/discoveries/12/repositories?change=gone&limit=50&offset=100`
        }).flush({});
    });

    it('sends the filters in the query of the table and in the body of a selection change', () => {
        api.importCandidates(
            ID,
            12,
            { archived: 'show', forks: 'hide', language: '', inactiveDays: 90 },
            50,
            0
        ).subscribe();
        // A blank filter is no filter: sent empty, the server would read it as a value to match.
        http.expectOne({
            method: 'GET',
            url: `${BASE}/discoveries/12/selection?limit=50&offset=0&archived=show&forks=hide&inactiveDays=90`
        }).flush({});

        api.changeImportSelection(ID, 12, 'add', ['101'], { personal: 'hide' }, ['102']).subscribe();
        const change = http.expectOne({ method: 'POST', url: `${BASE}/discoveries/12/selection` });
        expect(change.request.body).toEqual({
            operation: 'add',
            selected: ['101'],
            filters: { personal: 'hide' },
            forgeIds: ['102']
        });
        change.flush({});
    });

    it('previews and imports with the same body', () => {
        const body = { discoveryId: 12, forgeIds: ['101'], firstScan: false, spacingSeconds: 60 };

        api.previewForgeImport(ID, body).subscribe();
        expect(http.expectOne({ method: 'POST', url: `${BASE}/imports/preview` }).request.body).toEqual(body);

        api.importForgeRepositories(ID, body).subscribe();
        expect(http.expectOne({ method: 'POST', url: `${BASE}/imports` }).request.body).toEqual(body);
    });
});
