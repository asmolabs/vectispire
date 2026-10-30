import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { repositorySummary } from '@/app/core/testing/targets.fixtures';
import { CicdDialog } from './cicd-dialog';
import { CLI_SCRIPT_SHA256 } from './repository-model';
import { mountOnRepositories, textOf } from './repositories-page.testing';

/**
 * The pipeline snippets, on their own: the tab chosen shows its snippet for the repository opened, and
 * every pipeline runs the release's CLI only at its digest.
 */
describe('the pipeline snippets of a repository', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('shows the chosen tab for the repository opened, the CLI checked against its digest', () => {
        const repository = repositorySummary(42);
        const { fixture, page } = mountOnRepositories(CicdDialog, { repositories: [repository] });
        page.openCicd(repository);
        page.cicdActiveTab.set('github');
        fixture.detectChanges();
        const shown = textOf(document, 'pre');
        expect(shown).toContain('.github/workflows/vectispire.yml');
        expect(shown).toContain('--repo-id 42');
        expect(shown).toContain(CLI_SCRIPT_SHA256);
    });
});
