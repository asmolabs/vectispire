import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { MAX_EVIDENCE_BYTES } from '@/app/core/api/checklists.api';
import { CHECKLIST, CARRIED_LINE, OPEN_LINE } from '@/app/core/testing/checklists.fixtures';
import type { ChecklistLine } from '@/app/core/api.models';
import { BASE, buttonIn, mountOnPage, textOf } from './checklist-page.testing';
import { LineProofForm } from './line-proof-form';

/**
 * The proof form of one line, on its own: the fields it marks as needed, the refusals it makes before
 * anything is sent — a day in the future, a link that is no address, a file past the route's ceiling —
 * and the link it sends with its day and the edition.
 */
describe('the proof form of a checklist line', () => {
    afterEach(() => TestBed.resetTestingModule());

    function open(line: ChecklistLine = CARRIED_LINE) {
        const mounted = mountOnPage(LineProofForm, { view: CHECKLIST }, { line });
        mounted.page.proving.set({
            itemId: line.itemId,
            kind: line.evidenceKind === 'file' ? 'file' : 'link',
            link: '',
            file: null,
            performedOn: mounted.page.today
        });
        mounted.fixture.detectChanges();
        return mounted;
    }

    function type(dom: HTMLElement, selector: string, value: string): void {
        const input = dom.querySelector<HTMLInputElement>(selector)!;
        input.value = value;
        input.dispatchEvent(new Event('input'));
    }

    it('is a form whose link and day are required', () => {
        const { dom } = open();
        expect(dom().querySelector('form')).not.toBeNull();
        expect(dom().querySelector<HTMLInputElement>(`#evidence-link-${CARRIED_LINE.itemId}`)!.required).toBe(true);
        expect(dom().querySelector<HTMLInputElement>(`#evidence-day-${CARRIED_LINE.itemId}`)!.required).toBe(true);
    });

    it('refuses a day in the future, then a link that is no address, before sending anything', () => {
        const { dom, fixture, http } = open();
        type(dom(), `#evidence-link-${CARRIED_LINE.itemId}`, 'https://wiki.example.org/rotation');
        type(dom(), `#evidence-day-${CARRIED_LINE.itemId}`, '2999-01-01');
        fixture.detectChanges();
        buttonIn(dom(), `save-evidence-${CARRIED_LINE.itemId}`).click();
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="evidence-error"]')).toBe(
            'State the day the work was done: a day, and not in the future.'
        );
        expect(dom().querySelector(`#evidence-link-${CARRIED_LINE.itemId}`)!.getAttribute('aria-describedby')).toBe(
            `evidence-error-${CARRIED_LINE.itemId}`
        );

        type(dom(), `#evidence-day-${CARRIED_LINE.itemId}`, '2026-09-02');
        type(dom(), `#evidence-link-${CARRIED_LINE.itemId}`, 'wiki page');
        fixture.detectChanges();
        buttonIn(dom(), `save-evidence-${CARRIED_LINE.itemId}`).click();
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="evidence-error"]')).toBe('A link proof is an https: or http: address.');
        http.expectNone(`${BASE}/2/items/${CARRIED_LINE.itemId}/evidence/links`);
    });

    it('sends the link with its day and the edition on a submit', () => {
        const { dom, fixture, http, page } = open();
        type(dom(), `#evidence-link-${CARRIED_LINE.itemId}`, 'https://wiki.example.org/rotation');
        type(dom(), `#evidence-day-${CARRIED_LINE.itemId}`, '2026-09-02');
        fixture.detectChanges();
        dom().querySelector('form')!.dispatchEvent(new Event('submit'));

        const sent = http.expectOne(`${BASE}/2/items/${CARRIED_LINE.itemId}/evidence/links`);
        expect(sent.request.body).toEqual({
            link: 'https://wiki.example.org/rotation',
            performedOn: '2026-09-02',
            edition: CHECKLIST.checklist.edition
        });
        sent.flush(CHECKLIST);
        expect(page.proving()).toBeNull();
    });

    it('refuses a file past the ceiling in the words the server uses, and keeps the save greyed out', () => {
        const line: ChecklistLine = { ...OPEN_LINE, evidenceKind: 'file' };
        const { dom, fixture } = open(line);
        const input = dom().querySelector<HTMLInputElement>(`#evidence-file-${line.itemId}`)!;
        expect(input.required).toBe(true);
        const big = new File(['x'], 'sbom.json');
        Object.defineProperty(big, 'size', { value: MAX_EVIDENCE_BYTES + 1 });
        Object.defineProperty(input, 'files', { value: [big] });
        input.dispatchEvent(new Event('change'));
        fixture.detectChanges();

        expect(textOf(dom(), '[data-testid="evidence-error"]')).toBe(
            `The request body is larger than the ${MAX_EVIDENCE_BYTES} bytes this route accepts.`
        );
        expect(buttonIn(dom(), `save-evidence-${line.itemId}`).disabled).toBe(true);
    });
});
