import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { MAX_WORKBOOK_BYTES } from '@/app/core/api/checklists.api';
import { conflict, TEMPLATE } from '@/app/core/testing/checklists.fixtures';
import { buttonIn, mountOnTemplates, TEMPLATES_URL, textOf, typeInto } from './templates-page.testing';
import { TemplateImport } from './template-import';

/**
 * The import form, on its own: what it requires, a slug the server would refuse said on the field, the
 * name asked only of a new template, and the one refusal an import meets said by the form.
 */
describe('importing a checklist workbook', () => {
    afterEach(() => TestBed.resetTestingModule());

    function pickFile(dom: HTMLElement, size = 1024): void {
        const input = dom.querySelector<HTMLInputElement>('#checklist-file')!;
        const file = new File(['x'], 'checklist.xlsx');
        Object.defineProperty(file, 'size', { value: size });
        Object.defineProperty(input, 'files', { value: [file], configurable: true });
        input.dispatchEvent(new Event('change'));
    }

    it('is a form that requires a slug and a workbook, and marks a slug the server would refuse', () => {
        const { dom, fixture } = mountOnTemplates(TemplateImport, { templates: [TEMPLATE] });
        const slug = dom().querySelector<HTMLInputElement>('#checklist-slug')!;
        expect(dom().querySelector('form')).not.toBeNull();
        expect(slug.required).toBe(true);
        expect(dom().querySelector<HTMLInputElement>('#checklist-file')!.required).toBe(true);
        expect(slug.getAttribute('aria-invalid')).toBe('false');

        typeInto(dom(), '#checklist-slug', 'Release 2026');
        fixture.detectChanges();
        expect(slug.getAttribute('aria-invalid')).toBe('true');
        expect(buttonIn(dom(), 'import-workbook').disabled).toBe(true);
    });

    it('asks a name of a new template only', () => {
        const { dom, fixture } = mountOnTemplates(TemplateImport, { templates: [TEMPLATE] });
        typeInto(dom(), '#checklist-slug', 'release');
        fixture.detectChanges();
        expect(dom().querySelector('#checklist-name')).toBeNull();
        typeInto(dom(), '#checklist-slug', 'onboarding');
        fixture.detectChanges();
        expect(dom().querySelector('#checklist-name')).not.toBeNull();
    });

    it('refuses a workbook past the ceiling before sending it', () => {
        const { dom, fixture } = mountOnTemplates(TemplateImport, { templates: [TEMPLATE] });
        pickFile(dom(), MAX_WORKBOOK_BYTES + 1);
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="upload-error"]')).toContain(String(MAX_WORKBOOK_BYTES));
        expect(dom().querySelector('#checklist-file')!.getAttribute('aria-describedby')).toBe('upload-error');
    });

    it('imports on a submit, and says a template with a draft already has one', () => {
        const { dom, fixture, http, page } = mountOnTemplates(TemplateImport, { templates: [TEMPLATE] });
        typeInto(dom(), '#checklist-slug', 'release');
        pickFile(dom());
        fixture.detectChanges();
        dom().querySelector('form')!.dispatchEvent(new Event('submit'));

        http.expectOne((call) => call.method === 'POST' && call.url === `${TEMPLATES_URL}/release/versions`).flush(
            conflict('checklist-template-has-draft'),
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="upload-error"]')).toBe(
            'This template already has a draft, and it has one at a time: publish that draft or set it aside before importing or deriving another version.'
        );
        expect(page.selected()).toBeNull();
    });
});
