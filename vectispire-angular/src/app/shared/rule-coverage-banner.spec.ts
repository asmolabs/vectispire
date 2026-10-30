import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { RuleCoverageBanner } from './rule-coverage-banner';
import type { RuleCoverageAssessment } from '@/app/core/api.models';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The banner that says an absence of findings is an absence of looking.
 *
 * **The case that matters most is the one where it does not show.** A warning displayed when all
 * is well loses its meaning within days, and then the one that matters becomes invisible too —
 * that is why `COVERED` renders nothing, and it is what the first test pins.
 */
describe('the rule coverage banner', () => {
    let fixture: ComponentFixture<RuleCoverageBanner>;
    let http: HttpTestingController;

    async function mount(body: RuleCoverageAssessment | null, withOwaspTagging = false) {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [RuleCoverageBanner],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(RuleCoverageBanner);
        fixture.componentRef.setInput('withOwaspTagging', withOwaspTagging);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        const call = http.expectOne((request) => request.url === '/api/v1/rule-sets/coverage');
        if (body) {
            // Anchored here rather than at every call: the factory is the only point a response
            // enters through, so checking it once here covers them all.
            call.flush(asSchema('Assessment', body));
        } else {
            call.error(new ProgressEvent('failed'));
        }
        fixture.detectChanges();
    }

    beforeEach(async () => {
        await mount({
            state: 'COVERED',
            languagesWithRules: ['java'],
            ecosystemsInEstate: ['maven'],
            uncovered: [],
            ruleFiles: 40
        });
    }, 20_000);

    it('says nothing when every ecosystem in the estate has rules', () => {
        expect(fixture.componentInstance.visible()).toBe(false);
        expect((fixture.nativeElement as HTMLElement).textContent.trim()).toBe('');
    });

    it('warns when only the shipped rule is there', async () => {
        await mount({
            state: 'UNCONFIGURED',
            languagesWithRules: ['python'],
            ecosystemsInEstate: ['maven'],
            uncovered: ['java'],
            ruleFiles: 1
        });

        expect(fixture.componentInstance.visible()).toBe(true);
    });

    it('names the ecosystems with no rule when coverage is partial', async () => {
        await mount({
            state: 'PARTIAL',
            languagesWithRules: ['java'],
            ecosystemsInEstate: ['maven', 'go'],
            uncovered: ['go'],
            ruleFiles: 40
        });

        expect(fixture.componentInstance.uncovered()).toEqual(['go']);
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('go');
    });

    it('stays quiet when coverage could not be read', async () => {
        // An error banner above valid data would say "something is wrong" without saying what. The
        // host screen carries its own errors.
        await mount(null);

        expect(fixture.componentInstance.visible()).toBe(false);
    });

    /**
     * A rule tagged with the 2025 edition alone used to vanish from the grid without a word (decision
     * 0046 keeps 2021). The rule sets screen names it; the banner on every other screen does not.
     */
    describe('the rules tagged with another OWASP edition only', () => {
        const tagged = (untagged: { reason: string; ruleFiles: number }[]): RuleCoverageAssessment => ({
            state: 'COVERED',
            languagesWithRules: ['java'],
            ecosystemsInEstate: ['maven'],
            uncovered: [],
            ruleFiles: 40,
            owasp: { ruleFiles: 40, tagged: 40 - untagged.reduce((sum, row) => sum + row.ruleFiles, 0), untagged }
        });
        const notice = () =>
            (fixture.nativeElement as HTMLElement).querySelector('[data-testid="owasp-other-edition"]');

        it('are named on the rule sets screen, with their count by reason', async () => {
            await mount(
                tagged([
                    { reason: 'ONLY_2025_EDITION', ruleFiles: 3 },
                    { reason: 'NOT_DECLARED', ruleFiles: 20 }
                ]),
                true
            );

            expect(fixture.componentInstance.otherEditionFiles()).toBe(3);
            expect(fixture.componentInstance.otherEdition().map((row) => row.reason)).toEqual(['ONLY_2025_EDITION']);
            expect(notice()).not.toBeNull();
        });

        it('are not named by the banner of the other screens', async () => {
            await mount(tagged([{ reason: 'ONLY_2025_EDITION', ruleFiles: 3 }]));

            expect(notice()).toBeNull();
        });

        it('leave nothing to say when the untagged rules simply declare no category', async () => {
            // Most of the upstream corpus declares none: a warning about it would fire everywhere.
            await mount(tagged([{ reason: 'NOT_DECLARED', ruleFiles: 20 }]), true);

            expect(notice()).toBeNull();
        });

        it('show a reason this client does not know by its name rather than a key path', async () => {
            // Set past the document's check, which knows today's values only: a newer server is the case.
            await mount(tagged([]), true);
            fixture.componentInstance.coverage.set(tagged([{ reason: 'ONLY_2030_EDITION', ruleFiles: 2 }]));
            fixture.detectChanges();

            expect(fixture.componentInstance.reasonKey('ONLY_2030_EDITION')).toBeUndefined();
            expect(notice()?.textContent).toContain('ONLY_2030_EDITION: 2');
        });
    });
});
