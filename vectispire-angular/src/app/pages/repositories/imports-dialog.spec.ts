import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { repositorySummary } from '@/app/core/testing/targets.fixtures';
import { ImportsDialog } from './imports-dialog';
import { mountOnRepositories } from './repositories-page.testing';

/** A repository's imports, on their own: the panels load for the repository opened, and nothing while closed. */
describe("a repository's imports", () => {
    afterEach(() => TestBed.resetTestingModule());

    it('loads the imports of the repository opened, and none while closed', () => {
        const repository = repositorySummary(5, { displayName: 'payments-api' });
        const { fixture, http, page } = mountOnRepositories(ImportsDialog, { repositories: [repository] });
        expect(http.match(() => true)).toEqual([]);
        page.openSarifImports(repository);
        fixture.detectChanges();
        const asked = http.match(() => true).map((call) => call.request.url);
        expect(asked.length).toBeGreaterThan(0);
        expect(asked.every((url) => url.includes('5'))).toBe(true);
    });
});
