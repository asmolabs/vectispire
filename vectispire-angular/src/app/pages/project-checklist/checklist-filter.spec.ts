import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ChecklistContacts, ChecklistLine, ChecklistView } from '@/app/core/api.models';
import { CARRIED_LINE, CHECKLIST, CONTACTS, OPEN_LINE, READY_LINE } from '@/app/core/testing/checklists.fixtures';
import { useFrench } from '@/app/core/testing/english';
import { buttonIn, mountOnPage, textOf } from './checklist-page.testing';
import { ChecklistFilterBar } from './checklist-filter';

/**
 * The lines narrowed to the people they are asked of (decision 0044): line 1 is PO's, line 2 is both PO's
 * and BA's — a "PO / BA" cell the server split — line 3 is Arch's, and line 4 is measured (`AUTO`), nobody's.
 * Lines 2 and 3 are still to fill in; 1 and 4 are answered.
 */
describe('the filter of a checklist’s lines', () => {
    afterEach(() => TestBed.resetTestingModule());

    const withProfiles = (line: ChecklistLine, profiles: string[]): ChecklistLine => ({ ...line, profiles });
    const VIEW: ChecklistView = {
        ...CHECKLIST,
        lines: [
            withProfiles(READY_LINE, ['PO']),
            withProfiles(CARRIED_LINE, ['PO', 'BA']),
            withProfiles(OPEN_LINE, ['ARCH']),
            withProfiles({ ...READY_LINE, itemId: 104, position: 4 }, [])
        ]
    };
    const mineIs = (key: string): ChecklistContacts => ({
        ...CONTACTS,
        profiles: CONTACTS.profiles.map((one) => ({ ...one, mine: one.profile === key }))
    });

    function mount(contacts: ChecklistContacts | null = CONTACTS) {
        const mounted = mountOnPage(ChecklistFilterBar, { view: VIEW });
        mounted.page.contacts.set(contacts);
        mounted.fixture.detectChanges();
        return mounted;
    }
    const shown = (page: { shownLines: () => ChecklistLine[] }) => page.shownLines().map((line) => line.position);

    it("offers the profiles the lines name, in the column's spelling, and shows only the chosen ones' lines", () => {
        const { fixture, page, dom } = mount();
        expect(fixture.componentInstance.options()).toEqual([
            { value: 'PO', label: 'PO' },
            { value: 'BA', label: 'BA' },
            { value: 'ARCH', label: 'Arch' }
        ]);
        expect(shown(page)).toEqual([1, 2, 3, 4]);
        expect(dom().querySelector('[data-testid="filter-count"]')).toBeNull();

        fixture.componentInstance.setProfiles(['BA']);
        fixture.detectChanges();
        expect(shown(page), 'a shared line is each of its profiles’').toEqual([2]);
        expect(page.groups().flatMap((group) => group.objectives.flatMap((one) => one.lines))).toHaveLength(1);
        expect(textOf(dom(), '[data-testid="filter-count"]')).toBe('1 of 4 lines shown');

        fixture.componentInstance.setProfiles(['PO', 'ARCH']);
        expect(shown(page), 'no line naming nobody').toEqual([1, 2, 3]);

        buttonIn(dom(), 'filter-clear').click();
        fixture.detectChanges();
        expect(shown(page)).toEqual([1, 2, 3, 4]);
    });

    it('names a profile by its key until the contacts are read', () => {
        expect(
            mount(null)
                .fixture.componentInstance.options()
                .map((option) => option.label)
        ).toEqual(['PO', 'BA', 'ARCH']);
    });

    it('offers "my lines" only to a reader linked to a profile, and shows that profile’s lines', () => {
        const nobody = mount();
        expect(nobody.dom().querySelector('#filter-mine')).toBeNull();
        TestBed.resetTestingModule();

        const { dom, fixture, page } = mount(mineIs('ARCH'));
        buttonIn(dom(), 'filter-mine').click();
        fixture.detectChanges();
        expect(page.lineFilter().profiles).toEqual(['ARCH']);
        expect(shown(page)).toEqual([3]);
    });

    it('keeps the lines still to fill in — unanswered, or carried and waiting — and nothing kept back for a proof', () => {
        const { fixture, page } = mount();
        const keptBackForAProof = withProfiles(
            { ...READY_LINE, itemId: 105, position: 5, problems: ['evidence_required'] },
            []
        );
        page.view.set({ ...VIEW, lines: [...VIEW.lines, keptBackForAProof] });

        fixture.componentInstance.setToFill(true);
        expect(shown(page)).toEqual([2, 3]);

        fixture.componentInstance.setProfiles(['PO']);
        expect(shown(page), 'both narrowings at once').toEqual([2]);
    });

    it('says so when nothing matches, rather than showing an empty card', () => {
        const { fixture, page, dom } = mount();
        fixture.componentInstance.setProfiles(['ARCH']);
        fixture.componentInstance.setToFill(true);
        fixture.detectChanges();
        expect(dom().querySelector('[data-testid="filter-none"]')).toBeNull();

        // Arch answers its line: nothing of Arch's is left to fill in.
        page.view.set({
            ...VIEW,
            lines: VIEW.lines.map((line) => (line.position === 3 ? { ...line, problems: [] } : line))
        });
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="filter-none"]')).toBe('No line matches this filter.');
        expect(textOf(dom(), '[data-testid="filter-count"]')).toBe('0 of 4 lines shown');
    });

    it('words itself in French', () => {
        const { fixture, dom } = mount(mineIs('PO'));
        fixture.componentInstance.setToFill(true);
        useFrench();
        fixture.detectChanges();
        expect(buttonIn(dom(), 'filter-mine').textContent?.trim()).toBe('Mes lignes');
        expect(textOf(dom(), 'label[for="filter-to-fill"]')).toBe('À remplir seulement');
        expect(textOf(dom(), '[data-testid="filter-count"]')).toBe('2 lignes sur 4 affichées');
    });
});
