import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ChecklistVersion } from '@/app/core/api.models';
import { CONFIRMED_PREVIEW, SECRETS_RULE, VERSION } from '@/app/core/testing/checklists.fixtures';
import { buttonIn, mountOnTemplates, textOf, VERSION_URL } from './templates-page.testing';
import { TemplateItems } from './template-items';

/**
 * The items of a version, on its own: each line's proof and rule in words, the requirements edited on a
 * draft and sent for the lines changed only, a validity out of bounds refused first — and a month being
 * typed keeping its field while the rows are worked out again around it.
 */
describe('the items of a checklist template', () => {
    afterEach(() => TestBed.resetTestingModule());

    const asked: ChecklistVersion = {
        ...VERSION,
        items: VERSION.items.map((item, index) =>
            index === 1 ? { ...item, evidenceKind: 'file', evidenceValidityMonths: 12, boundRule: SECRETS_RULE } : item
        )
    };

    function months(dom: HTMLElement, id: number): HTMLInputElement {
        return dom.querySelector<HTMLInputElement>(`#evidence-months-${id}`)!;
    }

    it('reads each requirement and rule in words to a reader', () => {
        const { dom } = mountOnTemplates(TemplateItems, {
            preview: CONFIRMED_PREVIEW,
            version: asked,
            role: 'AUDITOR'
        });
        expect(textOf(dom(), '[data-testid="item-6"] [data-testid="item-evidence"]')).toBe('File · valid 12 months');
        expect(textOf(dom(), '[data-testid="item-5"] [data-testid="item-rule"]')).toBe('No rule');
        expect(textOf(dom(), '[data-testid="item-6"] [data-testid="item-rule-kind"]')).not.toBe('');
    });

    it('keeps the field a month is typed in, and sends the changed line only', () => {
        const { dom, fixture, http } = mountOnTemplates(TemplateItems, { preview: CONFIRMED_PREVIEW, version: asked });
        const before = months(dom(), 102);
        before.value = '24';
        before.dispatchEvent(new Event('input'));
        fixture.detectChanges();
        expect(months(dom(), 102)).toBe(before);

        buttonIn(dom(), 'save-evidence').click();
        const sent = http.expectOne((call) => call.method === 'PUT' && call.url === `${VERSION_URL}/evidence`);
        expect(sent.request.body).toEqual({
            items: [{ itemKey: asked.items[1].itemKey, evidenceKind: 'file', evidenceValidityMonths: 24 }]
        });
    });

    it('refuses a validity out of bounds before sending it', () => {
        const { dom, fixture, http } = mountOnTemplates(TemplateItems, { preview: CONFIRMED_PREVIEW, version: asked });
        months(dom(), 102).value = '121';
        months(dom(), 102).dispatchEvent(new Event('input'));
        fixture.detectChanges();
        buttonIn(dom(), 'save-evidence').click();
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="evidence-error"]')).toContain('from 1 to 120');
        http.expectNone((call) => call.method === 'PUT');
    });

    it('marks a rule unbound on screen as not saved, and undoes it', () => {
        const { dom, fixture, page } = mountOnTemplates(TemplateItems, { preview: CONFIRMED_PREVIEW, version: asked });
        page.ruleEdits.set({ [asked.items[1].itemKey]: null });
        fixture.detectChanges();
        expect(dom().querySelector('[data-testid="item-6"] [data-testid="item-rule-pending"]')).not.toBeNull();
        buttonIn(dom(), 'Undo the rule change on row 6').click();
        fixture.detectChanges();
        expect(dom().querySelector('[data-testid="item-rule-pending"]')).toBeNull();
    });
});
