import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { GateVerdicts } from './gate-verdicts';
import { asSchema } from '@/app/core/testing/contract';
import { I18nService } from '@/app/core/i18n/i18n.service';

/**
 * The verdict register, and the number it must not invent.
 *
 * **Zero verdicts do not make zero per cent.** On a fresh instance, a refusal rate of `0 %` reads
 * as "the gate refuses nothing" when the true sentence is "the gate has not answered yet" — and
 * that is exactly the confusion this whole screen exists to prevent.
 */
describe('le registre des verdicts', () => {
    let fixture: ComponentFixture<GateVerdicts>;
    let http: HttpTestingController;

    function row(id: string, passed: boolean) {
        return {
            id,
            target_kind: 'REPOSITORY',
            target_id: 7,
            target_name: 'helios-portal',
            passed,
            evaluated: passed ? 0 : 412,
            violations: passed ? 0 : 3,
            counts_by_severity: { critical: passed ? 0 : 1, high: 0, medium: 0, low: 0 },
            fail_on_severity: 'high',
            policy_source: 'TARGET',
            policy_version: 4,
            relaxations_ignored: false,
            decided_at: '2026-09-14T09:00:00Z',
            decided_by: 'ci-pipeline'
        };
    }

    async function mount(body: Record<string, unknown>) {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [GateVerdicts],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(GateVerdicts);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/gate/verdicts').flush(asSchema('VerdictRegister', body));
    }

    beforeEach(async () => {
        await mount({ verdicts: [row('a', true), row('b', false)], passed: 1, refused: 1 });
    }, 20_000);

    it('produces no refusal rate when the gate has never answered', async () => {
        await mount({ verdicts: [], passed: 0, refused: 0 });

        expect(fixture.componentInstance.refusalRate()).toBeNull();
    });

    it('computes the rate over the total of answers', () => {
        expect(fixture.componentInstance.refusalRate()).toBe(50);
    });

    it('writes the rate with its sign as each language spaces it', () => {
        // The template wrote `&nbsp;%` for every reader: the French space reached English too.
        const shown = () => (fixture.nativeElement as HTMLElement).textContent ?? '';
        fixture.detectChanges();
        expect(shown()).toContain('50%');
        expect(shown()).not.toContain('50 %');

        TestBed.inject(I18nService).currentLang.set('fr');
        fixture.detectChanges();
        expect(shown()).toContain('50 %');
    });

    it('ne garde que les refus quand on le demande', () => {
        const component = fixture.componentInstance;
        expect(component.shown()).toHaveLength(2);

        component.refusalsOnly.set(true);

        expect(component.shown().map((r) => r.id)).toEqual(['b']);
    });

    it('lists a verdict that names no target with no target, never as a container', async () => {
        // The gate writes no such row, but the schema allows one; the server lists it with
        // `target_kind` and `target_id` null rather than failing on it, and the cell has to say so.
        await mount({
            verdicts: [{ ...row('c', false), target_kind: null, target_id: null, target_name: null }],
            passed: 0,
            refused: 1
        });
        fixture.detectChanges();

        const cell = (fixture.nativeElement as HTMLElement).querySelector('tbody tr td')!;
        expect(cell.textContent?.trim()).toBe('—');
    });

    it('names each target as the server names it, and says what kind it is', () => {
        // It printed "Repository 7": an identifier an assessor can do nothing with.
        fixture.detectChanges();
        const cell = (fixture.nativeElement as HTMLElement).querySelector('tbody tr td')!;

        expect(cell.querySelector('.font-medium')?.textContent?.trim()).toBe('helios-portal');
        expect(cell.textContent).toContain('gate_verdicts.kind.repository');
        expect(cell.textContent).not.toContain('7');
    });

    it('falls back to the kind and the identifier when no name came', async () => {
        await mount({ verdicts: [{ ...row('d', true), target_name: null }], passed: 1, refused: 0 });
        fixture.detectChanges();

        const cell = (fixture.nativeElement as HTMLElement).querySelector('tbody tr td')!;
        expect(cell.textContent?.replace(/\s+/g, ' ').trim()).toBe('gate_verdicts.kind.repository 7');
    });

    it('shows only the severities that carry a count', () => {
        // A severity row where three read zero is noise and hides the fourth, which is the only one
        // saying why the gate refused.
        const refusal = fixture.componentInstance.shown().find((r) => !r.passed)!;

        expect(fixture.componentInstance.counts(refusal)).toEqual([{ severity: 'critical', count: 1 }]);
    });
});
