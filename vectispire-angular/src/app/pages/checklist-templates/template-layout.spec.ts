import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { CONFIRMED_PREVIEW, PREVIEW, VERSION } from '@/app/core/testing/checklists.fixtures';
import { buttonIn, mountOnTemplates, textOf, typeInto, VERSION_URL } from './templates-page.testing';
import { TemplateLayout } from './template-layout';

/**
 * The layout form, on its own: the fields a layout cannot do without are required, a submit makes the
 * client's checks before anything is sent, and the layout is confirmed naming the revision on screen.
 */
describe('the layout of a checklist template', () => {
    afterEach(() => TestBed.resetTestingModule());

    const field = (dom: HTMLElement, id: string) => dom.querySelector<HTMLInputElement>(`#${id}`)!;

    it('is a form whose required columns, rows and answer words say so, and the others not', () => {
        const { dom } = mountOnTemplates(TemplateLayout, { preview: PREVIEW });
        expect(dom().querySelector('form')).not.toBeNull();
        for (const id of ['layout-column-control', 'layout-column-answer', 'layout-column-comment']) {
            expect(field(dom(), id).required, id).toBe(true);
        }
        expect(field(dom(), 'layout-column-kpi').required).toBe(false);
        for (const id of ['layout-first-row', 'layout-last-row', 'layout-word-yes', 'layout-word-no']) {
            expect(field(dom(), id).required, id).toBe(true);
        }
    });

    it('refuses a layout without its answer words before sending it', () => {
        const { dom, fixture, http } = mountOnTemplates(TemplateLayout, { preview: PREVIEW });
        dom().querySelector('form')!.dispatchEvent(new Event('submit'));
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="layout-error"]')).toBe("Map the template's answer words to yes and no.");
        http.expectNone((call) => call.method === 'PUT');
    });

    it('confirms the layout as typed, naming the revision on screen', () => {
        const { dom, fixture, http, page } = mountOnTemplates(TemplateLayout, { preview: PREVIEW });
        typeInto(dom(), '#layout-word-yes', 'Oui');
        typeInto(dom(), '#layout-word-no', 'Non');
        fixture.detectChanges();
        buttonIn(dom(), 'confirm-layout').click();

        const sent = http.expectOne((call) => call.method === 'PUT' && call.url === `${VERSION_URL}/layout`);
        expect(sent.request.params.get('revision')).toBe(String(PREVIEW.version.revision));
        sent.flush(VERSION);
        expect(page.notice()).toBe('Layout confirmed: 3 items read.');
    });

    it('shows a reader the layout, and no form', () => {
        const { dom } = mountOnTemplates(TemplateLayout, { preview: CONFIRMED_PREVIEW, role: 'AUDITOR' });
        expect(dom().querySelector('form')).toBeNull();
        expect(textOf(dom(), '[data-testid="layout-read"]')).toContain('Oui');
    });
});
