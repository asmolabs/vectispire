import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { RuleCoverageBanner } from './rule-coverage-banner';
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

    async function mount(body: Record<string, unknown> | null) {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [RuleCoverageBanner],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(RuleCoverageBanner);
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
        expect(fixture.nativeElement.textContent.trim()).toBe('');
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
        expect(fixture.nativeElement.textContent).toContain('go');
    });

    it('stays quiet when coverage could not be read', async () => {
        // An error banner above valid data would say "something is wrong" without saying what. The
        // host screen carries its own errors.
        await mount(null);

        expect(fixture.componentInstance.visible()).toBe(false);
    });
});
