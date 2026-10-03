import { Routes } from '@angular/router';
import { AppLayout } from './app/layout/component/app.layout';
import { requires } from './app/core/role.guard';
import { hasSession, signedIn } from './app/core/auth.guard';

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
 *
 * **Every route names its tab title as a translation key** (`titles.*`), resolved by
 * `TranslatedTitleStrategy`; `check-i18n-keys.mjs` reads this file for them, and refuses a title
 * that is a sentence rather than a key.
 *
 * **The shell is guarded as a whole** (`signedIn`, on the parent, for every child): the session
 * lives in memory, so a reload arrives signed out and must reach the sign-in page before the shell
 * fires a single call — remembering the page — and an account still carrying `mustChangePassword`
 * goes nowhere but the change form. The role guards below come after it and answer a different
 * question.
 */
export const appRoutes: Routes = [
    {
        path: '',
        component: AppLayout,
        canActivate: [signedIn],
        canActivateChild: [signedIn],
        children: [
            { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
            {
                path: 'dashboard',
                title: 'titles.dashboard',
                loadComponent: () => import('./app/pages/dashboard/dashboard').then((m) => m.Dashboard)
            },
            {
                path: 'repositories',
                title: 'titles.repositories',
                loadComponent: () => import('./app/pages/repositories/repositories').then((m) => m.Repositories)
            },
            {
                // Readable by every account: the server answers with what the reader may see, and
                // the page offers the writes to administrators only.
                path: 'solutions',
                title: 'titles.solutions',
                loadComponent: () => import('./app/pages/solutions/solutions').then((m) => m.Solutions)
            },
            {
                // Readable by every account that sees part of the project: the server computes every
                // figure over what the reader sees, says \`partial\`, and answers 404 to the others.
                path: 'projects/:projectId',
                title: 'titles.project',
                loadComponent: () => import('./app/pages/project/project').then((m) => m.Project)
            },
            {
                path: 'solutions/:solutionId/compliance',
                title: 'titles.solution_compliance',
                loadComponent: () =>
                    import('./app/pages/solution-compliance/solution-compliance').then((m) => m.SolutionCompliance)
            },
            {
                // Readable by every account that sees the whole project, and no role guard can say
                // which those are: the server answers 404 to the others, and the page says so.
                path: 'projects/:projectId/checklist',
                title: 'titles.project_checklist',
                loadComponent: () =>
                    import('./app/pages/project-checklist/project-checklist').then((m) => m.ProjectChecklist)
            },
            {
                // Readable by every account, like the server's GET: an image, arguments and
                // languages name no target. The page offers the writes to the platform governor only.
                path: 'plugins',
                title: 'titles.plugins',
                loadComponent: () => import('./app/pages/plugins/plugins').then((m) => m.Plugins)
            },
            {
                // Governance reading, like the server's GET (decision 0035 §4): the registry says which
                // code may produce documents under the installation's key. The writes are offered to the
                // platform governor and the approval to the security leads.
                path: 'report-plugins',
                title: 'titles.report_plugins',
                canActivate: [requires('governance-read')],
                loadComponent: () => import('./app/pages/report-plugins/report-plugins').then((m) => m.ReportPlugins)
            },
            {
                path: 'containers',
                title: 'titles.containers',
                loadComponent: () => import('./app/pages/containers/containers').then((m) => m.Containers)
            },
            {
                path: 'ssh-keys',
                title: 'titles.ssh_keys',
                canActivate: [requires('administrator')],
                loadComponent: () => import('./app/pages/ssh-keys/ssh-keys').then((m) => m.SshKeys)
            },
            {
                path: 'git-tokens',
                title: 'titles.git_tokens',
                canActivate: [requires('administrator')],
                loadComponent: () => import('./app/pages/git-tokens/git-tokens').then((m) => m.GitTokens)
            },
            {
                path: 'forge-connections',
                title: 'titles.forge_connections',
                canActivate: [requires('administrator')],
                loadComponent: () =>
                    import('./app/pages/forge-connections/forge-connections').then((m) => m.ForgeConnections)
            },
            {
                // Discovery, selection and import of one connection: administrators, as the routes behind it —
                // a discovery names repositories no grant covers yet (decision 0037 §3).
                path: 'forge-connections/:connectionId',
                title: 'titles.forge_discovery',
                canActivate: [requires('administrator')],
                loadComponent: () =>
                    import('./app/pages/forge-discovery/forge-discovery').then((m) => m.ForgeDiscoveryPage)
            },
            {
                path: 'users',
                title: 'titles.users',
                canActivate: [requires('administrator')],
                loadComponent: () => import('./app/pages/users/users').then((m) => m.Users)
            },
            {
                path: 'teams',
                title: 'titles.teams',
                canActivate: [requires('administrator')],
                loadComponent: () => import('./app/pages/teams/teams').then((m) => m.Teams)
            },
            {
                path: 'api-keys',
                title: 'titles.api_keys',
                canActivate: [requires('administrator')],
                loadComponent: () => import('./app/pages/api-keys/api-keys').then((m) => m.ApiKeys)
            },
            {
                path: 'audit-log',
                title: 'titles.audit_log',
                canActivate: [requires('governance-read')],
                loadComponent: () => import('./app/pages/audit-log/audit-log').then((m) => m.AuditLog)
            },
            {
                path: 'settings',
                title: 'titles.settings',
                canActivate: [requires('security-lead')],
                loadComponent: () => import('./app/pages/settings/settings').then((m) => m.Settings)
            },
            {
                path: 'agents',
                title: 'titles.agents',
                canActivate: [requires('administrator')],
                loadComponent: () => import('./app/pages/agents/agents').then((m) => m.Agents)
            },
            {
                path: 'gate-policies',
                title: 'titles.gate_policies',
                canActivate: [requires('governance-read')],
                loadComponent: () => import('./app/pages/gate-policies/gate-policies').then((m) => m.GatePolicies)
            },
            {
                path: 'sarif-sources',
                title: 'titles.sarif_sources',
                canActivate: [requires('governance-read')],
                loadComponent: () => import('./app/pages/sarif-sources/sarif-sources').then((m) => m.SarifSources)
            },
            {
                path: 'checklist-templates',
                title: 'titles.checklist_templates',
                canActivate: [requires('governance-read')],
                loadComponent: () =>
                    import('./app/pages/checklist-templates/checklist-templates').then((m) => m.ChecklistTemplates)
            },
            {
                path: 'rule-sets',
                title: 'titles.rule_sets',
                canActivate: [requires('governance-read')],
                loadComponent: () => import('./app/pages/rule-sets/rule-sets').then((m) => m.RuleSets)
            },
            {
                path: 'scans/:id',
                title: 'titles.scan',
                loadComponent: () => import('./app/pages/scans/scan-detail').then((m) => m.ScanDetailPage)
            },
            {
                path: 'security',
                title: 'titles.security',
                loadComponent: () => import('./app/pages/security/security').then((m) => m.Security)
            },
            {
                path: 'issues',
                title: 'titles.issues',
                loadComponent: () => import('./app/pages/issues/issues').then((m) => m.Issues)
            },
            {
                path: 'issues/:id',
                title: 'titles.issue',
                loadComponent: () => import('./app/pages/issues/issue-detail').then((m) => m.IssueDetailPage)
            },
            {
                path: 'history',
                title: 'titles.history',
                loadComponent: () => import('./app/pages/history/history').then((m) => m.History)
            },
            {
                path: 'inventory',
                title: 'titles.inventory',
                loadComponent: () => import('./app/pages/inventory/inventory').then((m) => m.Inventory)
            },
            {
                path: 'owasp',
                title: 'titles.owasp',
                loadComponent: () => import('./app/pages/owasp/owasp').then((m) => m.Owasp)
            },
            {
                path: 'compliance',
                title: 'titles.compliance',
                loadComponent: () => import('./app/pages/compliance/compliance').then((m) => m.Compliance)
            },
            {
                path: 'exceptions',
                title: 'titles.exceptions',
                loadComponent: () => import('./app/pages/exceptions/exceptions').then((m) => m.Exceptions)
            },
            {
                path: 'remediation-delays',
                title: 'titles.remediation_delays',
                loadComponent: () =>
                    import('./app/pages/remediation-delays/remediation-delays').then((m) => m.RemediationDelays)
            },
            {
                path: 'certified-scope',
                title: 'titles.certified_scope',
                canActivate: [requires('governance-read')],
                loadComponent: () => import('./app/pages/certified-scope/certified-scope').then((m) => m.CertifiedScope)
            },
            {
                path: 'compliance-history',
                title: 'titles.compliance_history',
                canActivate: [requires('governance-read')],
                loadComponent: () =>
                    import('./app/pages/compliance-history/compliance-history').then((m) => m.ComplianceHistoryPage)
            },
            {
                path: 'soa',
                title: 'titles.soa',
                canActivate: [requires('governance-read')],
                loadComponent: () => import('./app/pages/soa/soa').then((m) => m.Soa)
            },
            {
                path: 'gate-verdicts',
                title: 'titles.gate_verdicts',
                canActivate: [requires('governance-read')],
                loadComponent: () => import('./app/pages/gate-verdicts/gate-verdicts').then((m) => m.GateVerdicts)
            },
            {
                path: 'epss',
                title: 'titles.epss',
                loadComponent: () => import('./app/pages/epss/epss').then((m) => m.Epss)
            },
            {
                path: 'blast-radius',
                title: 'titles.blast_radius',
                loadComponent: () => import('./app/pages/blast-radius/blast-radius').then((m) => m.BlastRadius)
            },
            {
                path: 'notifications',
                title: 'titles.notifications',
                loadComponent: () => import('./app/pages/notifications/notifications').then((m) => m.Notifications)
            },
            {
                path: 'licenses',
                title: 'titles.licenses',
                loadComponent: () => import('./app/pages/licenses/licenses').then((m) => m.Licenses)
            },
            {
                path: 'attack-surface',
                title: 'titles.attack_surface',
                loadComponent: () => import('./app/pages/attack-surface/attack-surface').then((m) => m.AttackSurface)
            },
            {
                path: 'attack-paths',
                title: 'titles.attack_paths',
                loadComponent: () => import('./app/pages/attack-paths/attack-paths').then((m) => m.AttackPaths)
            },
            {
                path: 'quality',
                title: 'titles.quality',
                loadComponent: () => import('./app/pages/quality/quality').then((m) => m.Quality)
            },
            {
                path: 'remediation',
                title: 'titles.remediation',
                loadComponent: () => import('./app/pages/remediation/remediation').then((m) => m.Remediation)
            },
            {
                path: 'attestation',
                title: 'titles.attestation',
                canActivate: [requires('governance-read')],
                loadComponent: () => import('./app/pages/attestation/attestation').then((m) => m.Attestation)
            },
            {
                path: 'account',
                title: 'titles.account',
                loadComponent: () => import('./app/pages/account/account').then((m) => m.Account)
            },
            {
                path: 'forbidden',
                title: 'titles.forbidden',
                loadComponent: () => import('./app/pages/forbidden/forbidden').then((m) => m.Forbidden)
            }
        ]
    },
    {
        path: 'change-password',
        title: 'titles.change_password',
        canActivate: [hasSession],
        loadComponent: () => import('./app/pages/auth/change-password').then((m) => m.ChangePassword)
    },
    {
        path: 'login',
        title: 'titles.login',
        loadComponent: () => import('./app/pages/auth/login').then((m) => m.Login)
    },
    {
        path: 'error',
        title: 'titles.error',
        loadComponent: () => import('./app/pages/auth/error').then((m) => m.Error)
    },
    {
        path: 'notfound',
        title: 'titles.notfound',
        loadComponent: () => import('./app/pages/notfound/notfound').then((m) => m.Notfound)
    },
    { path: '**', redirectTo: '/notfound' }
];
