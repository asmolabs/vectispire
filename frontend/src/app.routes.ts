import { Routes } from '@angular/router';
import { AppLayout } from './app/layout/component/app.layout';

/**
 * Les routes reprennent celles de l'interface Reflex à l'identique — `/depots`,
 * `/securite`, `/qualite` et le reste — parce que les signets et les liens déjà
 * distribués les utilisent. Les renommer serait un gain cosmétique payé par tout
 * le monde.
 *
 * `/login` et `/change-password` vivent hors de `AppLayout` : ce sont les deux
 * seuls écrans sans barre latérale, comme dans l'application Reflex.
 */
export const appRoutes: Routes = [
    {
        path: '',
        component: AppLayout,
        children: [
            { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
            { path: 'dashboard', loadComponent: () => import('./app/pages/dashboard/dashboard').then((m) => m.Dashboard) },
            { path: 'securite', loadComponent: () => import('./app/pages/securite/securite').then((m) => m.Securite) }
        ]
    },
    { path: 'login', loadComponent: () => import('./app/pages/auth/login').then((m) => m.Login) },
    { path: 'access', loadComponent: () => import('./app/pages/auth/access').then((m) => m.Access) },
    { path: 'error', loadComponent: () => import('./app/pages/auth/error').then((m) => m.Error) },
    { path: 'notfound', loadComponent: () => import('./app/pages/notfound/notfound').then((m) => m.Notfound) },
    { path: '**', redirectTo: '/notfound' }
];
