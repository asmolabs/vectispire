import { Component, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MenuItem } from '@openng/optimus-ui/api';
import { AppMenuitem } from './app.menuitem';
import { SessionStore } from '../../core/session.store';

@Component({
    selector: 'app-menu',
    standalone: true,
    imports: [CommonModule, AppMenuitem, RouterModule],
    template: `<ul class="layout-menu">
        @for (item of model(); track item.label) {
            @if (!item.separator) {
                <li app-menuitem [item]="item" [root]="true"></li>
            } @else {
                <li class="menu-separator"></li>
            }
        }
    </ul>`
})
export class AppMenu {
    /**
     * The Administration section is for administrators. The predicate comes from the session
     * store and is not restated here: with no session it answers `false`, so the section stays
     * hidden by default — erring in that direction shows nothing it should not, and erring the
     * other way does.
     */
    private readonly session = inject(SessionStore);

    readonly model = computed<MenuItem[]>(() => {
        const sections: MenuItem[] = [
            {
                label: 'Dashboard',
                items: [{ label: 'Dashboard', icon: 'pi pi-fw pi-home', routerLink: ['/dashboard'] }]
            },
            {
                // What is watched, apart from what the watching found. Repositories and
                // containers sat under Security, where they read as findings rather than as
                // the list of things somebody has to declare before anything is found at all.
                label: 'Configuration',
                items: [
                    { label: 'Repositories', icon: 'pi pi-fw pi-sitemap', routerLink: ['/repositories'] },
                    { label: 'Containers', icon: 'pi pi-fw pi-box', routerLink: ['/containers'] }
                ]
            },
            {
                label: 'Security',
                items: [
                    { label: 'Security', icon: 'pi pi-fw pi-shield', routerLink: ['/security'] },
                    { label: 'Issues', icon: 'pi pi-fw pi-exclamation-triangle', routerLink: ['/issues'] },
                    { label: 'History', icon: 'pi pi-fw pi-history', routerLink: ['/history'] },
                    { label: 'Component search', icon: 'pi pi-fw pi-search', routerLink: ['/inventory'] },
                    { label: 'OWASP report', icon: 'pi pi-fw pi-sparkles', routerLink: ['/owasp'] }
                ]
            },
            {
                label: 'Operations',
                items: [{ label: 'SSH keys', icon: 'pi pi-fw pi-key', routerLink: ['/ssh-keys'] }]
            }
        ];

        // Hiding the section is not what protects anything: every endpoint carries its own
        // guard on the server. This is reading comfort, and saying so has to stay in the file
        // so that nobody comes to rely on it.
        if (this.session.isAdmin()) {
            sections.push({
                label: 'Administration',
                items: [
                    { label: 'API keys', icon: 'pi pi-fw pi-verified', routerLink: ['/api-keys'] },
                    { label: 'Agents', icon: 'pi pi-fw pi-server', routerLink: ['/agents'] },
                    { label: 'Users', icon: 'pi pi-fw pi-users', routerLink: ['/users'] },
                    { label: 'Audit log', icon: 'pi pi-fw pi-history', routerLink: ['/audit-log'] },
                    { label: 'Semgrep rules', icon: 'pi pi-fw pi-shield', routerLink: ['/rule-sets'] },
                    { label: 'Settings', icon: 'pi pi-fw pi-cog', routerLink: ['/settings'] }
                ]
            });
        }

        return sections;
    });
}
