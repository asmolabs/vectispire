import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { RuleSets } from './rule-sets';
import { asSchema } from '@/app/core/testing/contract';

/**
 * Ce que l'aperçu du catalogue amont dit avant qu'on l'importe.
 *
 * <p><b>Une case grise de la grille OWASP disait deux choses opposées.</b> Elle est posée quand
 * aucune règle installée ne déclare la catégorie — ce qui peut vouloir dire « aucun scanner d'ici
 * ne sait regarder là », ou « les règles qui savent n'ont pas été importées ». Distinguer les deux
 * demandait d'importer d'abord et de regarder ensuite, soit l'ordre inverse de celui qu'un
 * opérateur veut : il choisit ce qu'il importe.
 *
 * <p>Le décompte est lu dans les règles elles-mêmes, par leur propre {@code metadata.owasp}, au
 * même passage que le décompte par langage.
 */
describe("l'aperçu du catalogue", () => {
    let fixture: ComponentFixture<RuleSets>;
    let http: HttpTestingController;

    const preview = (categories: Record<string, number>) =>
        asSchema('CataloguePreview', {
            upstream: 'opengrep/opengrep-rules',
            commit: '1c7e0f3a9b2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f',
            licenceName: 'LGPL-2.1 with Commons Clause',
            licence: 'the full text',
            licence_sha256: 'abc123',
            languages: { java: 412, python: 388 },
            categories
        });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [RuleSets],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(RuleSets);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        // Ce que l'écran demande de lui-même au démarrage.
        for (const request of http.match(() => true)) {
            request.flush(request.request.url.endsWith('/coverage') ? { state: 'COVERED', ruleFiles: 0 } : { ruleSets: [] });
        }
        fixture.detectChanges();
    }, 20_000);

    function readCatalogue(categories: Record<string, number>): void {
        fixture.componentInstance.readCatalogue();
        http.expectOne('/api/v1/rule-sets/catalogue').flush(preview(categories));
        fixture.detectChanges();
    }

    it('nomme les catégories du Top 10 que ces règles déclarent, avec leur nombre', () => {
        readCatalogue({ A03: 128, A01: 44, A10: 7 });

        // Triées : deux lectures du même catalogue doivent présenter la même liste, et l'ordre
        // d'une carte JSON n'est pas une garantie.
        expect(fixture.componentInstance.categoriesOf(fixture.componentInstance.catalogue()!)).toEqual([
            { id: 'A01', count: 44 },
            { id: 'A03', count: 128 },
            { id: 'A10', count: 7 }
        ]);

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('A01 (44)');
        expect(text).toContain('A03 (128)');
    });

    /**
     * <b>Le cas vide est une réponse, pas une absence d'affichage.</b> Un catalogue dont aucune
     * règle ne déclare de catégorie ne fera bouger aucune case de la grille — le dire évite
     * l'import qu'on ferait en espérant le contraire.
     */
    it('dit qu\'un catalogue sans déclaration ne fera bouger aucune case', () => {
        readCatalogue({});

        expect(fixture.componentInstance.categoriesOf(fixture.componentInstance.catalogue()!)).toEqual([]);
        expect(fixture.nativeElement.textContent as string).toContain('moves no square of the grid');
    });
});
