import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ProjectNode } from '@/app/core/api.models';
import { asSchemaList } from '@/app/core/testing/contract';
import { ACTIVATION, PLUGIN } from '@/app/core/testing/plugins.fixtures';
import { SOLUTION_TREE } from '@/app/core/testing/solutions.fixtures';
import { PluginsDialog } from './plugins-dialog';
import { mountOnSolutions, textOf } from './solutions-page.testing';

/**
 * A project's plugins, on their own: each plugin's languages against the project's — "so far" while a
 * repository is uncounted — the switch on for an activation, and a switch a reader cannot move.
 */
describe("a project's plugins", () => {
    afterEach(() => TestBed.resetTestingModule());

    const payments = SOLUTION_TREE.solutions[0];
    const gateway: ProjectNode = { ...payments.projects[0], detectedLanguages: ['python'], languagesUnknownFor: [9] };

    function open(role = 'CISO') {
        const mounted = mountOnSolutions(PluginsDialog, { role });
        mounted.page.openPlugins(payments, gateway);
        mounted.http.expectOne('/api/v1/plugins').flush(asSchemaList('PluginView', [PLUGIN]));
        mounted.http
            .expectOne(`/api/v1/projects/${gateway.id}/plugins`)
            .flush(asSchemaList('PluginActivationView', [ACTIVATION]));
        mounted.fixture.detectChanges();
        return mounted;
    }

    it('says a plugin finds none of its languages so far, and names what is not counted', () => {
        open();
        expect(
            textOf(document, `[data-testid="project-plugin-${PLUGIN.id}"] [data-testid="plugin-languages-absent"]`)
        ).toBe('None of its languages among the repositories counted so far; those not yet scanned may hold one.');
        expect(textOf(document, '[data-testid="plugins-languages-unknown"]')).toContain('api-gateway');
    });

    it('shows the switch on for an activation, and holds it for a reader', async () => {
        // The switch's model is written a tick after the render.
        const { fixture } = open('AUDITOR');
        await fixture.whenStable();
        fixture.detectChanges();
        const toggle = document.querySelector<HTMLInputElement>(`#project-plugin-toggle-${PLUGIN.id}`)!;
        expect(toggle.checked).toBe(true);
        expect(toggle.disabled).toBe(true);
    });
});
