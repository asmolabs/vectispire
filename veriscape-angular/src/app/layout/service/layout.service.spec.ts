import { TestBed } from '@angular/core/testing';
import { describe, beforeEach, it, expect } from 'vitest';
import { LayoutService } from './layout.service';

/**
 * Smoke test of the service that carries the shell's state (dark theme, collapsed menu,
 * open configurator).
 *
 * It exists mostly so that the `test` target checks something at all: an empty suite always
 * passes, including on the day the harness is broken.
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

    it('starts in the light theme', () => {
        expect(service.layoutConfig().darkTheme).toBe(false);
    });

    it('toggles the dark theme', () => {
        service.layoutConfig.update((config) => ({ ...config, darkTheme: true }));
        expect(service.layoutConfig().darkTheme).toBe(true);
    });
});
