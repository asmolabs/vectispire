import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { CertifiedScope } from './certified-scope';

/**
 * Le périmètre certifié, et les deux façons de mal lire un nombre absent.
 *
 * **Un périmètre non déclaré ne rapporte aucun écart, pour la même raison qu'une pièce vide ne
 * rapporte aucun bruit.** Zéro actif manquant et une couverture complète produisent le même
 * chiffre ; les distinguer est toute la valeur de cet écran, et c'est ce que les deux premiers
 * cas verrouillent.
 *
 * Le troisième porte sur le dénominateur : la part fraîche se calcule contre le périmètre
 * déclaré, pas contre ce que l'instance détient. Diviser par ce qu'on a est exactement la
 * façon dont un outil annonce cent pour cent sur un dixième d'un parc.
 */
describe('le périmètre certifié', () => {
    let fixture: ComponentFixture<CertifiedScope>;
    let http: HttpTestingController;

    async function mount(coverage: Record<string, number>) {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [CertifiedScope],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(CertifiedScope);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        http.expectOne((call) => call.url === '/api/v1/compliance/scope')
            .flush({ statement: 'Le SI de production.', coverage, targets: [{ kind: 'REPOSITORY', id: 7 }] });
        http.expectOne((call) => call.url === '/api/v1/repositories').flush([]);
        http.expectOne((call) => call.url === '/api/v1/containers').flush([]);
    }

    beforeEach(async () => {
        await mount({ declaredAssets: 40, inScope: 31, scannedRecently: 20, stale: 8, neverScanned: 3 });
    }, 20_000);

    it("nomme les actifs revendiqués dont l'instance n'a aucune ligne", () => {
        expect(fixture.componentInstance.unaccountedFor()).toBe(9);
        expect(fixture.componentInstance.declared()).toBe(true);
    });

    it("dit « non déclaré » plutôt que de rapporter un écart de zéro", async () => {
        await mount({ declaredAssets: 0, inScope: 31, scannedRecently: 20, stale: 8, neverScanned: 3 });

        expect(fixture.componentInstance.declared()).toBe(false);
        expect(fixture.componentInstance.unaccountedFor()).toBe(0);
        expect(fixture.componentInstance.freshShare())
            .toBeNull();
    });

    it('calcule la part fraîche contre le périmètre déclaré, pas contre ce qu’il détient', () => {
        // 20 sur 40 déclarés, pas 20 sur 31 détenus : le second dirait 65 % là où la moitié du
        // périmètre seulement porte une preuve.
        expect(fixture.componentInstance.freshShare()).toBe(50);
    });

    it('sait quelles cibles sont dans le périmètre', () => {
        expect(fixture.componentInstance.inScope('REPOSITORY', 7)).toBe(true);
        expect(fixture.componentInstance.inScope('REPOSITORY', 8)).toBe(false);
        expect(fixture.componentInstance.inScope('CONTAINER', 7)).toBe(false);
    });
});
