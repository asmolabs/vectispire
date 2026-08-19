import { TestBed } from '@angular/core/testing';
import { describe, beforeEach, it, expect } from 'vitest';
import { LayoutService } from './layout.service';

/**
 * Test de fumée du service qui porte l'état de la coquille (thème sombre, menu
 * replié, configurateur ouvert).
 *
 * Il existe surtout pour que la cible `test` vérifie réellement quelque chose :
 * une suite vide passe toujours, y compris le jour où le harnais est cassé.
 */
describe('LayoutService', () => {
    let service: LayoutService;

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [LayoutService] });
        service = TestBed.inject(LayoutService);
    });

    it("s'instancie", () => {
        expect(service).toBeTruthy();
    });

    it('démarre en thème clair', () => {
        expect(service.layoutConfig().darkTheme).toBe(false);
    });

    it('bascule le thème sombre', () => {
        service.layoutConfig.update((config) => ({ ...config, darkTheme: true }));
        expect(service.layoutConfig().darkTheme).toBe(true);
    });
});
