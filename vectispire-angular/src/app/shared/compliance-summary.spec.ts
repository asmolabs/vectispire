import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { ComplianceSummaryView } from './compliance-summary';
import { useEnglish } from '@/app/core/testing/english';
import { COMPLIANCE_SUMMARY, NO_DATA_SUMMARY } from '@/app/core/testing/scopes.fixtures';

/**
 * The drawing of a compliance summary, shared by the estate, a project and a solution — through the
 * DOM, since a verdict right in the component and drawn as its wire name is the defect this guards.
 */
describe('a compliance summary', () => {
    let fixture: ComponentFixture<ComplianceSummaryView>;

    async function draw(summary: object, inputs: Record<string, unknown> = {}): Promise<void> {
        await TestBed.configureTestingModule({ imports: [ComplianceSummaryView] }).compileComponents();
        useEnglish();
        fixture = TestBed.createComponent(ComplianceSummaryView);
        fixture.componentRef.setInput('summary', summary);
        for (const [name, value] of Object.entries(inputs)) fixture.componentRef.setInput(name, value);
        fixture.autoDetectChanges();
        await fixture.whenStable();
    }

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string) => dom().querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';

    beforeEach(() => TestBed.resetTestingModule());

    it('names each verdict in words, and draws NO_DATA as a dash, neither green nor red', async () => {
        await draw(NO_DATA_SUMMARY);

        const card = text('[data-testid="framework-NIS_2"]');
        expect(card).toContain('No data');
        expect(card).not.toContain('NO_DATA');
        expect(card).toContain('—');
        expect(card).not.toContain('0%');
        expect(fixture.componentInstance.statusSeverity('NO_DATA')).toBe('secondary');
    });

    it('opens the controls of the framework a reader picks', async () => {
        await draw(COMPLIANCE_SUMMARY);
        expect(dom().textContent).toContain('NIS2-ART21-VULN');

        dom().querySelector<HTMLElement>('[data-testid="framework-DORA"]')!.click();
        await fixture.whenStable();

        expect(fixture.componentInstance.activeEvaluation()?.framework).toBe('DORA');
        expect(dom().textContent).not.toContain('NIS2-ART21-VULN');
    });

    it('offers to inspect a matrix row only where the page can narrow to it', async () => {
        await draw(COMPLIANCE_SUMMARY);
        expect(dom().querySelector('[data-testid="matrix-row"] button')).toBeNull();

        TestBed.resetTestingModule();
        await draw(COMPLIANCE_SUMMARY, { inspectable: true });
        const inspected: string[] = [];
        fixture.componentInstance.inspect.subscribe((id) => inspected.push(id));
        dom().querySelector<HTMLButtonElement>('[data-testid="matrix-row"] button')!.click();
        expect(inspected).toEqual(['REPOSITORY:9']);
    });

    it('hides the matrix where the page shows one target', async () => {
        await draw(COMPLIANCE_SUMMARY, { showMatrix: false });
        expect(dom().querySelector('[data-testid="matrix-row"]')).toBeNull();
    });

    /**
     * Freshness, and the one green that should raise an alarm: a target never scanned presents no
     * known vulnerability, and on a table that counts findings it is green.
     */
    it('separates a stale observation from an absent one', async () => {
        await draw({ ...COMPLIANCE_SUMMARY, totalMonitoredTargets: 5, observedTargets: 4, freshTargets: 3 });

        // 3 fresh targets of 5 monitored, and 5 − 4 observed = 1 never looked at.
        expect(fixture.componentInstance.freshnessRate()).toBe(60);
        expect(fixture.componentInstance.neverObserved()).toBe(1);
        expect(fixture.componentInstance.freshnessTone()).toBe('text-red-500');
    });

    it('does not shout on an empty scope: a hundred per cent, not zero', async () => {
        await draw({
            ...COMPLIANCE_SUMMARY,
            totalMonitoredTargets: 0,
            passingGateTargets: 0,
            observedTargets: 0,
            freshTargets: 0
        });

        expect(fixture.componentInstance.freshnessRate()).toBe(100);
        expect(fixture.componentInstance.neverObserved()).toBe(0);
    });
});
