import { Routes } from '@angular/router';
import { AppLayout } from './app/layout/component/app.layout';

/**
 * Three paths changed with the interface's translation: `/depots`, `/securite` and `/qualite`
 * became `/repositories`, `/security` and `/quality`. **Bookmarks and links handed out against
 * the old paths now land on `/notfound`** — the catch-all route below sends anything unmatched
 * there, so the failure is visible rather than silent, which is the cheapest form this breakage
 * can take. Adding redirects from the old paths would keep them working; nobody asked for that,
 * and a redirect kept for ever is its own kind of debt.
 *
 * The other paths were already English and are unchanged.
 *
 * `/login` and `/change-password` live outside `AppLayout`: they are the only two screens
 * with no sidebar, as in the Reflex application.
 */
export const appRoutes: Routes = [
    {
        path: '',
        component: AppLayout,
        children: [
            { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
            { path: 'dashboard', loadComponent: () => import('./app/pages/dashboard/dashboard').then((m) => m.Dashboard) },
            { path: 'repositories', loadComponent: () => import('./app/pages/repositories/repositories').then((m) => m.Repositories) },
            { path: 'containers', loadComponent: () => import('./app/pages/containers/containers').then((m) => m.Containers) },
            { path: 'ssh-keys', loadComponent: () => import('./app/pages/ssh-keys/ssh-keys').then((m) => m.SshKeys) },
            { path: 'users', loadComponent: () => import('./app/pages/users/users').then((m) => m.Users) },
            { path: 'teams', loadComponent: () => import('./app/pages/teams/teams').then((m) => m.Teams) },
            { path: 'api-keys', loadComponent: () => import('./app/pages/api-keys/api-keys').then((m) => m.ApiKeys) },
            { path: 'audit-log', loadComponent: () => import('./app/pages/audit-log/audit-log').then((m) => m.AuditLog) },
            { path: 'settings', loadComponent: () => import('./app/pages/settings/settings').then((m) => m.Settings) },
            { path: 'agents', loadComponent: () => import('./app/pages/agents/agents').then((m) => m.Agents) },
            { path: 'gate-policies', loadComponent: () => import('./app/pages/gate-policies/gate-policies').then((m) => m.GatePolicies) },
            { path: 'rule-sets', loadComponent: () => import('./app/pages/rule-sets/rule-sets').then((m) => m.RuleSets) },
            { path: 'scans/:id', loadComponent: () => import('./app/pages/scans/scan-detail').then((m) => m.ScanDetailPage) },
            { path: 'security', loadComponent: () => import('./app/pages/security/security').then((m) => m.Security) },
            { path: 'issues', loadComponent: () => import('./app/pages/issues/issues').then((m) => m.Issues) },
            {
                path: 'issues/:id',
                loadComponent: () => import('./app/pages/issues/issue-detail').then((m) => m.IssueDetailPage)
            },
            { path: 'history', loadComponent: () => import('./app/pages/history/history').then((m) => m.History) },
            { path: 'inventory', loadComponent: () => import('./app/pages/inventory/inventory').then((m) => m.Inventory) },
            { path: 'owasp', loadComponent: () => import('./app/pages/owasp/owasp').then((m) => m.Owasp) },
            { path: 'compliance', loadComponent: () => import('./app/pages/compliance/compliance').then((m) => m.Compliance) },
            { path: 'licenses', loadComponent: () => import('./app/pages/licenses/licenses').then((m) => m.Licenses) },
            { path: 'quality', loadComponent: () => import('./app/pages/quality/quality').then((m) => m.Quality) }
        ]
    },
    { path: 'change-password', loadComponent: () => import('./app/pages/auth/change-password').then((m) => m.ChangePassword) },
    { path: 'login', loadComponent: () => import('./app/pages/auth/login').then((m) => m.Login) },
    { path: 'access', loadComponent: () => import('./app/pages/auth/access').then((m) => m.Access) },
    { path: 'error', loadComponent: () => import('./app/pages/auth/error').then((m) => m.Error) },
    { path: 'notfound', loadComponent: () => import('./app/pages/notfound/notfound').then((m) => m.Notfound) },
    { path: '**', redirectTo: '/notfound' }
];
