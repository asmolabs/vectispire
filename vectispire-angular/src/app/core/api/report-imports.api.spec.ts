import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ReportImportsApi } from './report-imports.api';

/**
 * The report-import client, pinned route by route: two reads, and no upload method at all — an
 * import comes from a declared key holding `report_import`, never from a session.
 */
describe('the report-import client', () => {
    let api: ReportImportsApi;
    let http: HttpTestingController;

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
        api = TestBed.inject(ReportImportsApi);
        http = TestBed.inject(HttpTestingController);
    });

    afterEach(() => http.verify());

    it("reads a repository's coverage and test-report histories", () => {
        api.coverageImports(42).subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/repositories/42/coverage-imports' }).flush([]);

        api.testReportImports(42).subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/repositories/42/test-report-imports' }).flush([]);
    });

    it('offers no upload', () => {
        const methods = Object.getOwnPropertyNames(ReportImportsApi.prototype).filter((name) => name !== 'constructor');
        expect(methods.sort()).toEqual(['coverageImports', 'testReportImports']);
    });
});
