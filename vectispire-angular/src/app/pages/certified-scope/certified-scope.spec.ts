import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { CertifiedScope } from './certified-scope';
import { asSchema } from '@/app/core/testing/contract';

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

    async function mount(coverage: Record<string, number>) {
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
        http.expectOne((call) => call.url === '/api/v1/repositories').flush([]);
        http.expectOne((call) => call.url === '/api/v1/containers').flush([]);
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
        expect(fixture.componentInstance.freshShare())
            .toBeNull();
    });

    it('computes the fresh share against the declared scope, not against what it holds', () => {
        // 20 of 40 declared, not 20 of 31 held: the second would say 65 % where only half the scope
        // carries evidence.
        expect(fixture.componentInstance.freshShare()).toBe(50);
    });

    it('knows which targets are in scope', () => {
        expect(fixture.componentInstance.inScope('REPOSITORY', 7)).toBe(true);
        expect(fixture.componentInstance.inScope('REPOSITORY', 8)).toBe(false);
        expect(fixture.componentInstance.inScope('CONTAINER', 7)).toBe(false);
    });
});
