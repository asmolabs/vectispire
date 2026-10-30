import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { asSchema } from '@/app/core/testing/contract';
import { SCORECARD } from '@/app/core/testing/scopes.fixtures';
import { repositorySummary } from '@/app/core/testing/targets.fixtures';
import { ScorecardDialog } from './scorecard-dialog';
import { mountOnRepositories, namedButton } from './repositories-page.testing';

/**
 * The scorecard, on its own: a badge offered for publishing only once the server says there is none,
 * published on request — and a badge that cannot be read taking nothing else down.
 */
describe("a repository's scorecard", () => {
    afterEach(() => TestBed.resetTestingModule());

    const repository = repositorySummary(5);
    const card = { ...SCORECARD, targetId: 5 };

    function open() {
        const mounted = mountOnRepositories(ScorecardDialog, { repositories: [repository] });
        mounted.page.openScorecard(repository);
        mounted.http.expectOne('/api/v1/scorecards/repositories/5').flush(asSchema('SecurityScorecard', card));
        return mounted;
    }

    it('offers to publish a badge none was published for, and publishes it', () => {
        const { fixture, http, page } = open();
        http.expectOne('/api/v1/scorecards/repositories/5/badge').flush(
            asSchema('BadgeState', { published: false, token: null, url: null })
        );
        fixture.detectChanges();
        namedButton(document, 'Publish badge').click();
        http.expectOne(
            (call) => call.method === 'POST' && call.url === '/api/v1/scorecards/repositories/5/badge'
        ).flush(asSchema('BadgeState', { published: true, token: 't', url: '/badges/t.svg' }));
        expect(page.badge()?.published).toBe(true);
    });

    it('keeps the scorecard when its badge cannot be read', () => {
        const { http, page } = open();
        http.expectOne('/api/v1/scorecards/repositories/5/badge').flush(null, { status: 403, statusText: 'Forbidden' });
        expect(page.scorecardVisible()).toBe(true);
        expect(page.badge()).toEqual({ published: false, token: null, url: null });
    });
});
