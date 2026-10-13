import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import type { ChecklistRule } from '@/app/core/api.models';
import { SECRETS_RULE, VERSION } from '@/app/core/testing/checklists.fixtures';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import { ChecklistRuleEditor } from './rule-editor';

/**
 * The rule editor on its own, for what its host's suite (`rule-binding.spec.ts`, which goes through
 * the templates page and the request it sends) does not reach: how the form moves between kinds,
 * the scopes and packages a lead adds and removes by their named buttons, and the two ways out that
 * keep no rule. Nothing is sent from here — what is kept is handed to the page.
 */
describe('the rule editor of a template line', () => {
    let fixture: ComponentFixture<ChecklistRuleEditor>;
    let kept: (ChecklistRule | null)[];
    let cancelled: number;

    // Row 7 of the template, whose KPI is "Zero critical".
    const LINE = VERSION.items[2];

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({ imports: [ChecklistRuleEditor] }).compileComponents();
        useEnglish();
    });

    async function open(rule: ChecklistRule | null): Promise<HTMLElement> {
        fixture = TestBed.createComponent(ChecklistRuleEditor);
        fixture.componentRef.setInput('item', LINE);
        fixture.componentRef.setInput('rule', rule);
        kept = [];
        cancelled = 0;
        fixture.componentInstance.kept.subscribe((value) => kept.push(value));
        fixture.componentInstance.cancelled.subscribe(() => cancelled++);
        fixture.detectChanges();
        await settle();
        return fixture.nativeElement as HTMLElement;
    }

    async function settle(): Promise<void> {
        await fixture.whenStable();
        fixture.detectChanges();
    }

    const dom = (): HTMLElement => fixture.nativeElement as HTMLElement;
    const text = (selector: string): string =>
        dom().querySelector(selector)?.textContent.replace(/\s+/g, ' ').trim() ?? '';

    /** A button by its id, or by its accessible name when it shows an icon only. */
    function button(name: string): HTMLButtonElement {
        const found = [...dom().querySelectorAll('button')].find(
            (candidate) =>
                candidate.closest('p-button')?.id === name ||
                candidate.getAttribute('aria-label') === name ||
                candidate.textContent.trim() === name
        );
        expect(found, `a button named ${name}`).toBeDefined();
        return found!;
    }

    async function type(selector: string, value: string): Promise<void> {
        const input = dom().querySelector(selector) as HTMLInputElement;
        input.value = value;
        input.dispatchEvent(new Event('input'));
        fixture.detectChanges();
        await settle();
    }

    async function choose(label: string): Promise<void> {
        const select = dom().querySelector('#rule-kind') as HTMLSelectElement;
        select.selectedIndex = [...select.options].findIndex((option) => option.textContent.trim() === label);
        expect(select.selectedIndex, `an option ${label}`).toBeGreaterThanOrEqual(0);
        select.dispatchEvent(new Event('change'));
        fixture.detectChanges();
        await settle();
    }

    it("opens on the line's rule, its KPI and the rule in words beside it", async () => {
        await open(SECRETS_RULE);

        expect(text('h4')).toBe('The rule of row 7');
        expect(text('[data-testid="rule-kpi"]')).toBe('Zero critical');
        expect(text('[data-testid="rule-described"]')).toContain('Findings within thresholds');
        expect((dom().querySelector('#rule-scope-secret') as HTMLInputElement).checked).toBe(true);
    });

    it('keeps the age stated when the kind changes, and nothing else of the kind left', async () => {
        await open(SECRETS_RULE);
        await type('#rule-max-age', '30');

        await choose('Dependencies analysed');
        expect(dom().querySelector('[data-testid="rule-scopes"]')).toBeNull();
        expect((dom().querySelector('#rule-max-age') as HTMLInputElement).value).toBe('30');

        (dom().querySelector('#rule-schedule-yes') as HTMLInputElement).click();
        fixture.detectChanges();
        button('rule-keep').click();

        expect(kept).toEqual([{ kind: 'dependency_analysis', maxAgeDays: 30, requireSchedule: true }]);
    });

    it('adds a scope as typed and removes it by its named button', async () => {
        await open(SECRETS_RULE);
        expect(button('rule-scope-add').disabled).toBe(true);
        await type('#rule-scope-other', '   ');
        expect(button('rule-scope-add').disabled).toBe(true);

        await type('#rule-scope-other', 'plugin:licence-audit');
        button('rule-scope-add').click();
        await settle();
        expect(dom().querySelector('[data-testid="rule-other-plugin:licence-audit"]')).not.toBeNull();
        expect((dom().querySelector('#rule-scope-other') as HTMLInputElement).value).toBe('');

        button('Remove the scope plugin:licence-audit').click();
        await settle();
        expect(dom().querySelector('[data-testid="rule-other-plugin:licence-audit"]')).toBeNull();
    });

    it('removes the package its button names, and only that one', async () => {
        await open(null);
        await choose('Component versions allowed');
        button('rule-component-add').click();
        await settle();
        button('rule-component-add').click();
        await settle();
        await type('#rule-purl-0', 'pkg:maven/org.example/first');
        await type('#rule-purl-1', 'pkg:maven/org.example/second');
        await type('#rule-versions-0', '1.0.0');

        // The second, named by its place in the list as the reader counts it: from one.
        button('Remove package 2').click();
        await settle();

        expect(dom().querySelector('#rule-purl-1')).toBeNull();
        expect((dom().querySelector('#rule-purl-0') as HTMLInputElement).value).toBe('pkg:maven/org.example/first');
        button('rule-keep').click();
        expect(kept).toEqual([
            {
                kind: 'component_versions',
                maxAgeDays: 7,
                components: [{ purlPrefix: 'pkg:maven/org.example/first', versions: ['1.0.0'] }]
            }
        ]);
    });

    it('measures the line by no rule when that is chosen, and keeps nothing when cancelled', async () => {
        await open(SECRETS_RULE);
        button('rule-cancel').click();
        expect(cancelled).toBe(1);
        expect(kept).toEqual([]);

        await choose('No rule');
        expect(text('[data-testid="rule-described"]')).toContain('No rule: people answer the line');
        button('rule-unbind').click();
        expect(kept).toEqual([null]);
    });

    it('speaks French to a French reader, its icon buttons included', async () => {
        await open({ ...SECRETS_RULE, scopes: ['builtin:secret', 'plugin:licence-audit'] });
        useFrench();
        fixture.detectChanges();

        expect(text('h4')).toBe('La règle de la ligne 7');
        expect(button('Retirer le périmètre plugin:licence-audit')).toBeDefined();
        expect(button('Garder cette règle')).toBeDefined();
    });
});
