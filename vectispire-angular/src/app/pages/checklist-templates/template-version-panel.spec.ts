import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { CONFIRMED_PREVIEW, PUBLISHED, VERSION } from '@/app/core/testing/checklists.fixtures';
import { buttonIn, mountOnTemplates, textOf, VERSION_URL } from './templates-page.testing';
import { TemplateVersionPanel } from './template-version-panel';

/**
 * The version panel, on its own: its summary in words, the parts a version has drawn below it, the acts
 * withheld from a retired one, and a refusal that asks for a reload reading everything again.
 */
describe('the version panel of a checklist template', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('states the version, and draws its sheet, layout, items, pairing and acts', () => {
        const { dom } = mountOnTemplates(TemplateVersionPanel, { preview: CONFIRMED_PREVIEW, version: VERSION });
        expect(textOf(dom(), '[data-testid="shown-status"]')).toBe('Draft');
        expect(textOf(dom(), '[data-testid="shown-revision"]')).toBe('4');
        expect(textOf(dom(), '[data-testid="shown-authors"]')).toBe('alice');
        for (const part of ['sheet-grid', 'layout-form', 'items', 'pairing', 'acts']) {
            expect(dom().querySelector(`[data-testid="${part}"]`), part).not.toBeNull();
        }
    });

    it('withholds the acts from a retired version', () => {
        const { dom } = mountOnTemplates(TemplateVersionPanel, {
            preview: { ...CONFIRMED_PREVIEW, version: { ...PUBLISHED, status: 'retired' } },
            version: VERSION
        });
        expect(dom().querySelector('[data-testid="acts"]')).toBeNull();
    });

    it('reads everything again when a refusal asks for it', () => {
        const { dom, fixture, http, page } = mountOnTemplates(TemplateVersionPanel, {
            preview: CONFIRMED_PREVIEW,
            version: VERSION
        });
        page.refusal.set({ message: 'Changed meanwhile.', reload: true });
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="refusal-message"]')).toBe('Changed meanwhile.');
        buttonIn(dom(), 'reload-version').click();
        http.expectOne((call) => call.url === `${VERSION_URL}/preview`);
        http.expectOne(VERSION_URL);
        http.expectOne('/api/v1/checklist-templates/release');
        expect(page.refusal()).toBeNull();
    });
});
