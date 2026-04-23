import { Injectable, computed, signal } from '@angular/core';

export interface LayoutConfig {
    preset: string;
    primary: string;
    surface: string | null | undefined;
    darkTheme: boolean;
    menuMode: string;
}

interface LayoutState {
    staticMenuDesktopInactive: boolean;
    overlayMenuActive: boolean;
    profileSidebarActive: boolean;
    configSidebarActive: boolean;
    staticMenuMobileActive: boolean;
    menuHoverActive: boolean;
}

@Injectable({
    providedIn: 'root'
})
export class LayoutService {
    _config: LayoutConfig = {
        preset: 'Aura',
        primary: 'emerald',
        surface: null,
        darkTheme: false,
        menuMode: 'static'
    };

    config = signal<LayoutConfig>(this._config);

    state = signal<LayoutState>({
        staticMenuDesktopInactive: false,
        overlayMenuActive: false,
        profileSidebarActive: false,
        configSidebarActive: false,
        staticMenuMobileActive: false,
        menuHoverActive: false
    });

    isDarkTheme = computed(() => this.config().darkTheme);

    getLayoutConfig() {
        return this.config();
    }

    toggleDarkMode() {
        this.config.update((config) => {
            const darkTheme = !config.darkTheme;
            if (darkTheme) {
                document.documentElement.classList.add('app-dark');
            } else {
                document.documentElement.classList.remove('app-dark');
            }
            return { ...config, darkTheme };
        });
    }

    onMenuToggle() {
        if (this.isOverlay()) {
            this.state.update((prev) => ({ ...prev, overlayMenuActive: !prev.overlayMenuActive }));

            if (this.state().overlayMenuActive) {
                this.onOverlaySubmenuOpen();
            }
        }

        if (this.isDesktop()) {
            this.state.update((prev) => ({ ...prev, staticMenuDesktopInactive: !prev.staticMenuDesktopInactive }));
        } else {
            this.state.update((prev) => ({ ...prev, staticMenuMobileActive: !prev.staticMenuMobileActive }));
        }
    }

    onOverlaySubmenuOpen() {
        // Implementation for overlay menu
    }

    isOverlay() {
        return this.config().menuMode === 'overlay';
    }

    isDesktop() {
        return window.innerWidth > 991;
    }
}
