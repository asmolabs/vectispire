import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { CertifiedScope } from './certified-scope';
import { asSchema, asSchemaList } from '@/app/core/testing/contract';
import { containerSummary, repositorySummary } from '@/app/core/testing/targets.fixtures';
import type { ScopeCoverage } from '@/app/core/api.models';

/**
 * The certified scope, and the two ways of misreading an absent number.
 *
 * **An undeclared scope reports no gap, for the same reason an empty room reports no noise.** Zero
 * missing assets and complete coverage produce the same number; telling them apart is this
 * screen's entire value, and it is what the first two cases pin.
 *
 * The third is about the denominator: the fresh share is computed against the declared scope, not
 * against what the instance holds. Dividing by what one has is exactly how a tool announces one
 * hundred per cent over a tenth of an estate.
 */
describe('the certified scope', () => {
    let fixture: ComponentFixture<CertifiedScope>;
    let http: HttpTestingController;

    async function mount(coverage: ScopeCoverage) {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [CertifiedScope],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(CertifiedScope);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        http.expectOne((call) => call.url === '/api/v1/compliance/scope').flush(
            asSchema('ScopeView', {
                statement: 'Le SI de production.',
                coverage,
                targets: [{ kind: 'REPOSITORY', id: 7 }]
            })
        );
        http.expectOne((call) => call.url === '/api/v1/repositories').flush(
            asSchemaList('RepositorySummary', [
                repositorySummary(7, { name: 'billing' }),
                repositorySummary(8, { name: 'web' })
            ])
        );
        http.expectOne((call) => call.url === '/api/v1/containers').flush(
            asSchemaList('ContainerSummary', [containerSummary(7, { reference: 'registry/app:1' })])
        );
        fixture.detectChanges();
    }

    beforeEach(async () => {
        await mount({ declaredAssets: 40, inScope: 31, scannedRecently: 20, stale: 8, neverScanned: 3 });
    }, 20_000);

    it('names the claimed assets for which the instance holds no row', () => {
        expect(fixture.componentInstance.unaccountedFor()).toBe(9);
        expect(fixture.componentInstance.declared()).toBe(true);
    });

    it('says "not declared" rather than reporting a gap of zero', async () => {
        await mount({ declaredAssets: 0, inScope: 31, scannedRecently: 20, stale: 8, neverScanned: 3 });

        expect(fixture.componentInstance.declared()).toBe(false);
        expect(fixture.componentInstance.unaccountedFor()).toBe(0);
        expect(fixture.componentInstance.freshShare()).toBeNull();
    });

    it('computes the fresh share against the declared scope, not against what it holds', () => {
        // 20 of 40 declared, not 20 of 31 held: the second would say 65 % where only half the scope
        // carries evidence.
        expect(fixture.componentInstance.freshShare()).toBe(50);
    });

    /** Each box as a reader sees it: the target's name and whether it is ticked. */
    const boxes = () =>
        [...(fixture.nativeElement as HTMLElement).querySelectorAll('label')].map(
            (label) => `${label.textContent.trim()} ${label.querySelector('input')!.checked}`
        );

    it('ticks the targets in scope, by kind as well as id', () => {
        // Repository 7 is in scope; container 7 shares its id and is not.
        expect(boxes()).toEqual(['billing true', 'web false', 'registry/app:1 false']);
    });

    it('ticks the boxes again when the scope changes', () => {
        fixture.componentInstance.scope.update((view) => ({
            ...view!,
            targets: [
                { kind: 'REPOSITORY', id: 8 },
                { kind: 'CONTAINER', id: 7 }
            ]
        }));
        fixture.detectChanges();

        expect(boxes()).toEqual(['billing false', 'web true', 'registry/app:1 true']);
    });
});
