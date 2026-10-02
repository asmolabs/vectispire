import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { threeWeeks } from '../testing/owasp-weekly.fixtures';
import { OwaspApi } from './owasp.api';

describe('the weekly OWASP coverage client', () => {
    let api: OwaspApi;
    let http: HttpTestingController;

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
        api = TestBed.inject(OwaspApi);
        http = TestBed.inject(HttpTestingController);
    });

    it('sends what is set and nothing else — the window defaults belong to the server', () => {
        let weeks = 0;
        api.weeklyCoverage({ from: '2026-07-13', project_id: 12 }).subscribe(
            (coverage) => (weeks = coverage.weeks.length)
        );
        const call = http.expectOne((request) => request.url === '/api/v1/owasp/coverage/weekly');
        expect(call.request.method).toBe('GET');
        expect(call.request.params.keys().sort()).toEqual(['from', 'project_id']);
        expect(call.request.params.get('from')).toBe('2026-07-13');
        expect(call.request.params.get('project_id')).toBe('12');
        call.flush(threeWeeks());
        expect(weeks).toBe(3);
    });

    it('asks the server defaults when nothing is set', () => {
        api.weeklyCoverage().subscribe();
        const call = http.expectOne((request) => request.url === '/api/v1/owasp/coverage/weekly');
        expect(call.request.params.keys()).toEqual([]);
        call.flush(threeWeeks());

        // An absent value never becomes the word "undefined" in the query string.
        api.weeklyCoverage({ from: '2026-07-13', to: undefined, solution_id: undefined }).subscribe();
        const partial = http.expectOne((request) => request.url === '/api/v1/owasp/coverage/weekly');
        expect(partial.request.urlWithParams).toBe('/api/v1/owasp/coverage/weekly?from=2026-07-13');
        partial.flush(threeWeeks());
    });
});
