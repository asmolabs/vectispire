import { Component, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MenuItem } from '@openng/optimus-ui/api';
import { AppMenuitem } from './app.menuitem';
import { SessionStore } from '../../core/session.store';
import { I18nService } from '../../core/i18n/i18n.service';

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
    private readonly i18n = inject(I18nService);

    readonly model = computed<MenuItem[]>(() => {
        // Read the signal so the computed signal re-evaluates when language changes
        this.i18n.translations();

        const securityItems = [
            { label: this.i18n.t('menu.security'), icon: 'pi pi-fw pi-shield', routerLink: ['/security'] },
            { label: this.i18n.t('menu.issues'), icon: 'pi pi-fw pi-exclamation-triangle', routerLink: ['/issues'] },
            { label: this.i18n.t('menu.history'), icon: 'pi pi-fw pi-history', routerLink: ['/history'] },
            { label: this.i18n.t('menu.component_search'), icon: 'pi pi-fw pi-search', routerLink: ['/inventory'] },
            { label: this.i18n.t('menu.epss'), icon: 'pi pi-fw pi-bolt', routerLink: ['/epss'] },
            { label: this.i18n.t('menu.blast_radius'), icon: 'pi pi-fw pi-sitemap', routerLink: ['/blast-radius'] },
            { label: this.i18n.t('menu.licenses'), icon: 'pi pi-fw pi-book', routerLink: ['/licenses'] },
            { label: this.i18n.t('menu.attack_surface'), icon: 'pi pi-fw pi-compass', routerLink: ['/attack-surface'] },
            { label: this.i18n.t('menu.owasp_report'), icon: 'pi pi-fw pi-sparkles', routerLink: ['/owasp'] },
            { label: this.i18n.t('menu.compliance'), icon: 'pi pi-fw pi-check-circle', routerLink: ['/compliance'] }
        ];

        const sections: MenuItem[] = [
            {
                label: this.i18n.t('menu.dashboard'),
                items: [{ label: this.i18n.t('menu.dashboard'), icon: 'pi pi-fw pi-home', routerLink: ['/dashboard'] }]
            },
            {
                label: this.i18n.t('menu.configuration'),
                items: [
                    { label: this.i18n.t('menu.repositories'), icon: 'pi pi-fw pi-sitemap', routerLink: ['/repositories'] },
                    { label: this.i18n.t('menu.containers'), icon: 'pi pi-fw pi-box', routerLink: ['/containers'] }
                ]
            },
            {
                label: this.i18n.t('menu.security'),
                items: securityItems
            },
            {
                label: this.i18n.t('menu.operations'),
                items: [
                    { label: this.i18n.t('menu.notifications'), icon: 'pi pi-fw pi-bell', routerLink: ['/notifications'] },
                    { label: this.i18n.t('menu.ssh_keys'), icon: 'pi pi-fw pi-key', routerLink: ['/ssh-keys'] }
                ]
            }
        ];

        if (this.session.isAdmin() || this.session.isSecurityLead()) {
            const adminItems: MenuItem[] = [];

            if (this.session.isSecurityLead()) {
                adminItems.push(
                    { label: this.i18n.t('menu.gate_policies'), icon: 'pi pi-fw pi-flag', routerLink: ['/gate-policies'] },
                    { label: this.i18n.t('menu.semgrep_rules'), icon: 'pi pi-fw pi-shield', routerLink: ['/rule-sets'] },
                    { label: this.i18n.t('menu.audit_log'), icon: 'pi pi-fw pi-history', routerLink: ['/audit-log'] }
                );
            }

            if (this.session.isAdmin()) {
                adminItems.push(
                    { label: this.i18n.t('menu.api_keys'), icon: 'pi pi-fw pi-verified', routerLink: ['/api-keys'] },
                    { label: this.i18n.t('menu.agents'), icon: 'pi pi-fw pi-server', routerLink: ['/agents'] },
                    { label: this.i18n.t('menu.users'), icon: 'pi pi-fw pi-users', routerLink: ['/users'] },
                    { label: this.i18n.t('menu.teams'), icon: 'pi pi-fw pi-sitemap', routerLink: ['/teams'] },
                    { label: this.i18n.t('menu.settings_general'), icon: 'pi pi-fw pi-cog', routerLink: ['/settings'] },
                    { label: this.i18n.t('menu.settings_scanners'), icon: 'pi pi-fw pi-sliders-h', routerLink: ['/settings'], queryParams: { tab: 'scanners' } },
                    { label: this.i18n.t('menu.settings_ai'), icon: 'pi pi-fw pi-sparkles', routerLink: ['/settings'], queryParams: { tab: 'ai' } },
                    { label: this.i18n.t('menu.settings_integrations'), icon: 'pi pi-fw pi-link', routerLink: ['/settings'], queryParams: { tab: 'integrations' } },
                    { label: this.i18n.t('menu.settings_threat_intel'), icon: 'pi pi-fw pi-globe', routerLink: ['/settings'], queryParams: { tab: 'threat-intel' } }
                );
            }

            sections.push({
                label: this.i18n.t('menu.administration'),
                items: adminItems
            });
        }

        return sections;
    });
}
