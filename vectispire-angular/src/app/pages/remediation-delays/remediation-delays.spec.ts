import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { RemediationDelays } from './remediation-delays';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish, useFrench } from '@/app/core/testing/english';

/**
 * The deadlines, and the percentage the screen refuses to show.
 *
 * **A severity with no deadline set has nothing to meet.** A bar at zero per cent against it would
 * read as "we never meet the deadlines on the low ones" when the true sentence is "nobody set a
 * deadline for the low ones" — and it is the number that would be quoted in a meeting.
 */
describe('remediation times', () => {
    let fixture: ComponentFixture<RemediationDelays>;
    let http: HttpTestingController;

    const DISTRIBUTION = asSchema('RemediationDistributionView', {
        windowDays: 90,
        oldestOpenDays: 241,
        oldestOpenSeverity: 'critical',
        bySeverity: [
            {
                severity: 'critical',
                windowDays: 7,
                withinSla: 17,
                late: 11,
                percentageWithinSla: 61,
                medianDays: 4.5,
                ninetiethDays: 38,
                openOverdue: 5,
                oldestOpenDays: 241
            },
            {
                severity: 'high',
                windowDays: 30,
                withinSla: 141,
                late: 19,
                percentageWithinSla: 88,
                medianDays: 6,
                ninetiethDays: 52,
                openOverdue: 12,
                oldestOpenDays: 118
            },
            {
                severity: 'low',
                windowDays: 0,
                withinSla: 0,
                late: 0,
                percentageWithinSla: null,
                medianDays: 21,
                ninetiethDays: 147,
                openOverdue: 0,
                oldestOpenDays: 312
            }
        ]
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [RemediationDelays],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(RemediationDelays);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/remediation/distribution').flush(DISTRIBUTION);
    }, 20_000);

    it('does not claim to measure a severity with no deadline set', () => {
        const component = fixture.componentInstance;
        // `low`, like the rest of the API. This test already looked for that spelling and found no
        // row, because the route was the only one sending `LOW` — and its fixture was wrong the
        // same way, which made the absence invisible. The route is fixed; the assertion was right
        // from the start.
        const low = component.rows().find((row) => row.severity === 'low')!;

        expect(component.hasDeadline(low)).toBe(false);
    });

    it('mesure celles qui en ont un', () => {
        const component = fixture.componentInstance;

        expect(component.hasDeadline(component.rows()[0])).toBe(true);
    });

    it('turns the bar red below three quarters, amber below ninety', () => {
        const component = fixture.componentInstance;
        const [critical, high] = component.rows();

        expect(component.barColour(critical)).toBe('#b91c1c');
        expect(component.barColour(high)).toBe('#d97706');
    });

    /** The rows as a reader sees them: the severity cell and the median cell of each. */
    const cells = () =>
        [...(fixture.nativeElement as HTMLElement).querySelectorAll('tbody tr')].map((row) => {
            const tds = row.querySelectorAll('td');
            return { severity: tds[0].textContent.trim(), median: tds[3].textContent.trim() };
        });

    it("names each severity in the reader's language, never as the server spells it", () => {
        useEnglish();
        fixture.detectChanges();
        expect(cells().map((row) => row.severity)).toEqual(['Critical', 'High', 'Low']);

        useFrench();
        fixture.detectChanges();
        expect(cells().map((row) => row.severity)).toEqual(['Critique', 'Élevée', 'Faible']);
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('— Critique');
    });

    it("writes a fractional median with the reader's decimal mark", () => {
        useEnglish();
        fixture.detectChanges();
        expect(cells()[0].median).toBe('4.5');

        // "11.4 jours" on the French screen: a point a French reader takes for a thousands separator.
        useFrench();
        fixture.detectChanges();
        expect(cells()[0].median).toBe('4,5');
        expect(cells()[1].median).toBe('6');
    });
});
