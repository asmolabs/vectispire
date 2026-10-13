import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router, UrlTree } from '@angular/router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import { Quality } from './quality';

/**
 * The quality view, as a reader of a four-digit backlog uses it: three figures, the rules, files and
 * repositories that carry most of the debt, and a way into the backlog filtered to what it counts.
 */
describe('the quality view', () => {
    let fixture: ComponentFixture<Quality>;
    let http: HttpTestingController;

    const OVERVIEW = asSchema('QualityOverview', {
        openCount: 1240,
        ruleCount: 37,
        fileCount: 412,
        topRules: [
            { label: 'python.lang.maintainability.useless-assignment', count: 400 },
            { label: 'java.lang.correctness.unused-import', count: 100 }
        ],
        topFiles: [
            { label: 'src/billing/ledger.py', count: 51 },
            // A finding without a file is still counted; it has no name to show.
            { label: null, count: 3 }
        ],
        topTargets: [] as { label: string | null; count: number }[]
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Quality],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
        http = TestBed.inject(HttpTestingController);
        fixture = TestBed.createComponent(Quality);
        fixture.detectChanges();
        // The coverage banner asks on its own; a covered estate makes it say nothing.
        http.expectOne('/api/v1/rule-sets/coverage').flush(
            asSchema('Assessment', {
                state: 'COVERED',
                languagesWithRules: ['python'],
                ecosystemsInEstate: ['pypi'],
                uncovered: [],
                ruleFiles: 4
            })
        );
    });

    const page = (): HTMLElement => fixture.nativeElement as HTMLElement;
    const text = (): string => page().textContent.replace(/\s+/g, ' ');

    /** The headline figures, each with its words — two spans the stylesheet sets apart. */
    const figures = (): string[] =>
        [...page().querySelectorAll('.gap-6.mb-6 > div')].map((figure) =>
            [...figure.querySelectorAll('span')].map((span) => span.textContent.trim()).join(' ')
        );

    /** Each group as a reader sees it: its title, then each row's label, count and bar width. */
    function groups(): { title: string; rows: string[] }[] {
        return [...page().querySelectorAll('.grid > div')].map((group) => ({
            title: group.querySelector('.font-medium')?.textContent.trim() ?? '',
            rows: [...group.querySelectorAll('.mb-3:has(.bg-primary)')].map((row) => {
                const [label, count] = [...row.querySelectorAll('span')].map((span) => span.textContent.trim());
                const bar = row.querySelector<HTMLElement>('.bg-primary')?.style.width;
                return `${label} ${count} ${bar}`;
            })
        }));
    }

    function answer(): void {
        http.expectOne('/api/v1/quality/overview').flush(OVERVIEW);
        fixture.detectChanges();
    }

    it('shows the three figures and where the debt concentrates, each bar against the largest of its group', () => {
        answer();

        expect(figures()).toEqual(['1240 open findings', '37 distinct rules', '412 files affected']);
        expect(groups()).toEqual([
            {
                title: 'Most frequent rules',
                rows: [
                    'python.lang.maintainability.useless-assignment 400 100%',
                    'java.lang.correctness.unused-import 100 25%'
                ]
            },
            { title: 'Most affected files', rows: ['src/billing/ledger.py 51 100%', '— 3 6%'] },
            { title: 'Densest repositories', rows: [] }
        ]);
    });

    it('says a group with nothing in it is empty, rather than leaving a blank column', () => {
        answer();

        const repositories = page().querySelectorAll('.grid > div')[2];
        expect(repositories.textContent).toContain('No finding.');
    });

    it('opens the backlog filtered to quality findings, the ones these figures count', () => {
        answer();
        const router = TestBed.inject(Router);
        const navigate = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);

        const link = [...page().querySelectorAll('button')].find((button) =>
            button.textContent.includes('See every quality finding')
        );
        link!.click();

        expect(router.serializeUrl(navigate.mock.calls[0][0] as UrlTree)).toBe('/issues?type=quality');
    });

    it('says the view could not be loaded, and shows no figure it does not have', () => {
        http.expectOne('/api/v1/quality/overview').flush(null, { status: 502, statusText: 'Bad Gateway' });
        fixture.detectChanges();

        expect(page().querySelector('.p-message-error')?.textContent).toContain('Could not load the quality view.');
        expect(figures()).toEqual([]);
    });

    it('speaks French to a French reader, and says the findings never fail a build', () => {
        answer();
        useFrench();
        fixture.detectChanges();

        expect(figures()[0]).toBe('1240 constats ouverts');
        expect(text()).toContain('Ces constats ne bloquent jamais un build.');
        expect(groups().map((group) => group.title)).toEqual([
            'Règles les plus fréquentes',
            'Fichiers les plus touchés',
            'Dépôts les plus denses'
        ]);
    });
});
