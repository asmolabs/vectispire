import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ChecklistLineHistory } from '@/app/core/api.models';
import { LINE_HISTORY } from '@/app/core/testing/checklists.fixtures';
import { useEnglish } from '@/app/core/testing/english';
import { LineHistory } from './line-history';

/**
 * A line's history, on its own: a person's answer by its author, Vectispire's by the product's name
 * whatever its `answeredBy` says, a withdrawn automatic answer as withdrawn, and the proofs after.
 */
describe('the history of a checklist line', () => {
    afterEach(() => TestBed.resetTestingModule());

    const AUTOMATIC: ChecklistLineHistory = {
        ...LINE_HISTORY,
        answers: [
            ...LINE_HISTORY.answers,
            { ...LINE_HISTORY.answers[1], id: 612, answeredBy: 'erin', answeredByKind: 'system' },
            { ...LINE_HISTORY.answers[1], id: 613, answeredByKind: 'system', withdrawn: true }
        ]
    };

    function render(history: ChecklistLineHistory | null): HTMLElement {
        TestBed.configureTestingModule({ imports: [LineHistory] });
        useEnglish();
        const fixture = TestBed.createComponent(LineHistory);
        fixture.componentRef.setInput('history', history);
        fixture.detectChanges();
        return fixture.nativeElement as HTMLElement;
    }

    const row = (dom: HTMLElement, id: number) =>
        dom.querySelector(`[data-testid="history-row-${id}"]`)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';

    it('names a person by their name and Vectispire by its own, never the account it wrote under', () => {
        const dom = render(AUTOMATIC);
        expect(row(dom, 610)).toMatch(/^No — erin, 21\/09\/2026 \d\d:\d\d Not yet automated\.$/);
        expect(row(dom, 612)).toMatch(/^Yes · automatic — Vectispire, 22\/09\/2026 \d\d:\d\d$/);
        expect(row(dom, 613)).toContain('Automatic answer withdrawn (no more data) — Vectispire');
    });

    it('lists the proofs, a withdrawn one with who withdrew it', () => {
        const dom = render(LINE_HISTORY);
        expect(dom.textContent).toContain('withdrawn by dave');
    });

    it('says it is reading while the history is on its way', () => {
        expect(render(null).textContent?.trim()).toBe('Loading...');
    });
});
