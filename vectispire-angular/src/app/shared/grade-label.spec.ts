import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { GradeLabelPipe, gradeLabel } from './grade-label';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { useEnglish } from '@/app/core/testing/english';
import { SCORECARD } from '@/app/core/testing/scopes.fixtures';
import { ScorecardView } from './scorecard';

/** A grade reads as its letter: `A_PLUS` is the name of a constant, and was printed as one. */
describe('gradeLabel', () => {
    let i18n: I18nService;
    const t = (key: string, params?: Record<string, string | number>) => i18n.t(key, params);

    beforeEach(() => {
        TestBed.resetTestingModule();
        useEnglish();
        i18n = TestBed.inject(I18nService);
    });

    it('reads A_PLUS as A+', () => {
        expect(gradeLabel('A_PLUS', t)).toBe('Grade A+');
    });

    it('reads A as A', () => {
        expect(gradeLabel('A', t)).toBe('Grade A');
    });

    it('reads NO_DATA as no data, not as a grade', () => {
        expect(gradeLabel('NO_DATA', t)).toBe('No data');
    });

    it('translates the prefix and keeps the letter', () => {
        i18n.translations.set({
            repositories: { grade_tag: 'Note {{grade}}' },
            soa: { measured: { NO_DATA: 'Aucune donnée' } }
        });
        expect(TestBed.runInInjectionContext(() => new GradeLabelPipe()).transform('A_PLUS')).toBe('Note A+');
        expect(gradeLabel('NO_DATA', t)).toBe('Aucune donnée');
    });
});

describe('the scorecard grade, in the DOM', () => {
    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({ imports: [ScorecardView] }).compileComponents();
        useEnglish();
    });

    it('shows Grade A+ on an A_PLUS card, never the constant', () => {
        const fixture = TestBed.createComponent(ScorecardView);
        fixture.componentRef.setInput('card', { ...SCORECARD, score: 100, grade: 'A_PLUS' as const });
        fixture.detectChanges();
        const root = fixture.nativeElement as HTMLElement;
        expect(root.querySelector('[data-testid="scorecard-grade"]')?.textContent.trim()).toBe('Grade A+');
        expect(root.textContent).not.toContain('A_PLUS');
    });
});
