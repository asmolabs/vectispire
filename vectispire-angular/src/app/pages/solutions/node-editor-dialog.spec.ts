import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { SOLUTION_TREE } from '@/app/core/testing/solutions.fixtures';
import { NodeEditorDialog } from './node-editor-dialog';
import { mountOnSolutions } from './solutions-page.testing';

/**
 * The name-and-description dialog, on its own: a form whose name is required, a blank one refused on
 * the field before anything is sent, a submit that creates, and a name already taken said in the dialog.
 */
describe('the name and description dialog', () => {
    afterEach(() => TestBed.resetTestingModule());

    const mobile = SOLUTION_TREE.solutions[1];
    const name = () => document.querySelector<HTMLInputElement>('#node-name')!;
    const form = () => document.querySelector<HTMLFormElement>('form#node-editor')!;

    function open() {
        const mounted = mountOnSolutions(NodeEditorDialog);
        mounted.page.newProject(mobile);
        mounted.fixture.detectChanges();
        return mounted;
    }

    it('requires a name, and says so on the field when it is blank', () => {
        const { fixture, http } = open();
        expect(name().required).toBe(true);
        form().dispatchEvent(new Event('submit'));
        fixture.detectChanges();
        expect(document.querySelector('#node-error')?.textContent?.trim()).toBe('A name is required.');
        expect(name().getAttribute('aria-invalid')).toBe('true');
        http.expectNone('/api/v1/solutions/2/projects');
    });

    it('creates the project on a submit, trimmed, and reads the tree again', () => {
        const { fixture, http, page } = open();
        page.formName.set('  Wallet  ');
        fixture.detectChanges();
        form().dispatchEvent(new Event('submit'));
        const sent = http.expectOne('/api/v1/solutions/2/projects');
        expect(sent.request.body).toEqual({ name: 'Wallet', description: '' });
        sent.flush(null);
        expect(page.editorVisible()).toBe(false);
        http.expectOne('/api/v1/solutions');
    });

    it('says a taken name in the dialog, which stays open', () => {
        const { fixture, http, page } = open();
        page.formName.set('App');
        form().dispatchEvent(new Event('submit'));
        http.expectOne('/api/v1/solutions/2/projects').flush(
            { type: 'urn:vectispire:problem:project-name-taken', title: 'Conflict', status: 409, detail: 'English.' },
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();
        expect(page.editorVisible()).toBe(true);
        expect(page.formError()).toContain('App');
    });
});
