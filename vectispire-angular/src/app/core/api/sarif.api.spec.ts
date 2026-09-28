import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { SarifSourceDeclaration } from '../api.models';
import { asSchema } from '../testing/contract';
import { SOURCE } from '../testing/plugins.fixtures';
import { SarifApi } from './sarif.api';

/**
 * The SARIF client, pinned route by route: the declarations are governance, and there is no upload
 * method at all — an import comes from a declared key, never from a session.
 */
describe('the SARIF client', () => {
    let api: SarifApi;
    let http: HttpTestingController;

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
        api = TestBed.inject(SarifApi);
        http = TestBed.inject(HttpTestingController);
    });

    afterEach(() => http.verify());

    it('declares a source with the body the server reads', () => {
        const declaration: SarifSourceDeclaration = asSchema('SourceDeclaration', {
            slug: 'payments-ci',
            name: 'Payments CI',
            api_key_id: SOURCE.apiKeyId,
            project_id: 12,
            tools: ['Semgrep OSS'],
            kinds: ['sarif', 'coverage']
        });
        api.declareSarifSource(declaration).subscribe();
        const request = http.expectOne({ method: 'POST', url: '/api/v1/sarif-sources' });
        expect(request.request.body).toEqual(declaration);
        request.flush(SOURCE, { status: 201, statusText: 'Created' });
    });

    it('lists, enables and removes', () => {
        api.sarifSources().subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/sarif-sources' }).flush([SOURCE]);

        api.setSarifSourceEnabled(3, false).subscribe();
        const toggle = http.expectOne({ method: 'PUT', url: '/api/v1/sarif-sources/3/enabled' });
        expect(asSchema('SourceEnabled', toggle.request.body)).toEqual({ enabled: false });
        toggle.flush({ ...SOURCE, enabled: false });

        api.removeSarifSource(3).subscribe();
        http.expectOne({ method: 'DELETE', url: '/api/v1/sarif-sources/3' }).flush(null);
    });

    it("reads a repository's import history", () => {
        api.sarifImports(42).subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/repositories/42/sarif-imports' }).flush([]);
    });
});
