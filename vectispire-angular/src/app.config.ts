import { provideHttpClient, withFetch, withInterceptors } from '@angular/common/http';
import { authInterceptor } from './app/core/auth.interceptor';
import { ApplicationConfig, inject, provideAppInitializer, provideZonelessChangeDetection } from '@angular/core';
import { provideRouter, withComponentInputBinding, withEnabledBlockingInitialNavigation, withInMemoryScrolling } from '@angular/router';
import Aura from '@openng/optimus-ui-themes/aura';
import { provideOptimus } from '@openng/optimus-ui/config';
import { appRoutes } from './app.routes';
import { I18nService } from './app/core/i18n/i18n.service';

export const appConfig: ApplicationConfig = {
    providers: [
        provideRouter(
            appRoutes,
            withInMemoryScrolling({ anchorScrolling: 'enabled', scrollPositionRestoration: 'enabled' }),
            withEnabledBlockingInitialNavigation(),
            // **Without this, a route parameter never reaches the component's input.**
            // The scan detail screen sat on "Loading…" while the console log said NG0950 —
            // an error nobody sees who only looks at the page. This is the kind of
            // configuration everybody assumes is implicit.
            withComponentInputBinding()
        ),
        provideHttpClient(withFetch(), withInterceptors([authInterceptor])),
        provideZonelessChangeDetection(),
        provideOptimus({ theme: { preset: Aura, options: { darkModeSelector: '.app-dark' } } }),
        provideAppInitializer(() => {
            const i18n = inject(I18nService);
            return i18n.init();
        })
    ]
};
