import { TestBed } from '@angular/core/testing';
import { afterEach, describe, beforeEach, it, expect, vi } from 'vitest';
import { LayoutService } from './layout.service';

/**
 * The service that carries the shell's state: the dark theme, and which menu the toggle in the
 * top bar opens or closes — a different one on a desktop, on a phone and in overlay mode.
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

    describe('the menu toggle', () => {
        afterEach(() => vi.unstubAllGlobals());

        const width = (pixels: number) => vi.stubGlobal('innerWidth', pixels);

        it('collapses the static menu on a desktop, and leaves the phone menu alone', () => {
            width(1280);
            service.onMenuToggle();
            expect(service.layoutState().staticMenuDesktopInactive).toBe(true);
            expect(service.layoutState().mobileMenuActive).toBe(false);

            service.onMenuToggle();
            expect(service.layoutState().staticMenuDesktopInactive).toBe(false);
        });

        it('opens the phone menu below the desktop breakpoint, and leaves the static menu alone', () => {
            width(991);
            service.onMenuToggle();
            expect(service.layoutState().mobileMenuActive).toBe(true);
            expect(service.layoutState().staticMenuDesktopInactive).toBe(false);
        });

        it('opens the overlay in overlay mode, and only then', () => {
            width(1280);
            service.onMenuToggle();
            expect(service.layoutState().overlayMenuActive).toBe(false);

            service.layoutConfig.update((config) => ({ ...config, menuMode: 'overlay' }));
            service.onMenuToggle();
            expect(service.layoutState().overlayMenuActive).toBe(true);
        });
    });
});
