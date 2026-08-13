import { provideHttpClient, withFetch, withInterceptors } from '@angular/common/http';
import { authInterceptor } from './app/core/auth.interceptor';
import { ApplicationConfig, provideZonelessChangeDetection } from '@angular/core';
import { provideRouter, withComponentInputBinding, withEnabledBlockingInitialNavigation, withInMemoryScrolling } from '@angular/router';
import Aura from '@openng/optimus-ui-themes/aura';
import { provideOptimus } from '@openng/optimus-ui/config';
import { appRoutes } from './app.routes';

export const appConfig: ApplicationConfig = {
    providers: [
        provideRouter(
            appRoutes,
            withInMemoryScrolling({ anchorScrolling: 'enabled', scrollPositionRestoration: 'enabled' }),
            withEnabledBlockingInitialNavigation(),
            // **Sans cela, un paramètre de route n'atteint jamais l'entrée du composant.**
            // L'écran de détail d'un scan restait sur « Chargement… » et le journal de la
            // console disait NG0950 — une erreur qu'on ne voit pas si l'on se contente de
            // regarder la page. C'est le genre de configuration qu'on croit implicite.
            withComponentInputBinding()
        ),
        provideHttpClient(withFetch(), withInterceptors([authInterceptor])),
        provideZonelessChangeDetection(),
        provideOptimus({ theme: { preset: Aura, options: { darkModeSelector: '.app-dark' } } })
    ]
};
