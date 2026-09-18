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

        /**
         * **The estate's state: what is wrong, and what is being done about it.**
         *
         * Sixteen entries had piled up here, seven of which spoke not about the estate but about
         * what can be shown of it. A section you scan with your eyes to find your screen has
         * stopped being a menu; the two questions are now two sections.
         */
        const securityItems = [
            { label: this.i18n.t('menu.posture'), icon: 'pi pi-fw pi-shield', routerLink: ['/security'] },
            { label: this.i18n.t('menu.issues'), icon: 'pi pi-fw pi-exclamation-triangle', routerLink: ['/issues'] },

            // **Directly after the list of findings, and nowhere else.** One says what is wrong,
            // the other what is being done about it; separating them in the menu separated the
            // question from its answer.
            { label: this.i18n.t('menu.remediation'), icon: 'pi pi-fw pi-wrench', routerLink: ['/remediation'] },

            // **Directly after the work order, because it is its measurement.** One says where to
            // start, the other whether the deadlines we set ourselves were met.
            { label: this.i18n.t('menu.delays'), icon: 'pi pi-fw pi-clock', routerLink: ['/remediation-delays'] },
            { label: this.i18n.t('menu.history'), icon: 'pi pi-fw pi-history', routerLink: ['/history'] },
            { label: this.i18n.t('menu.inventory'), icon: 'pi pi-fw pi-box', routerLink: ['/inventory'] },
            { label: this.i18n.t('menu.epss'), icon: 'pi pi-fw pi-bolt', routerLink: ['/epss'] },
            { label: this.i18n.t('menu.blast_radius'), icon: 'pi pi-fw pi-sitemap', routerLink: ['/blast-radius'] },
            { label: this.i18n.t('menu.licenses'), icon: 'pi pi-fw pi-book', routerLink: ['/licenses'] },
            { label: this.i18n.t('menu.attack_surface'), icon: 'pi pi-fw pi-compass', routerLink: ['/attack-surface'] },
            { label: this.i18n.t('menu.attack_paths'), icon: 'pi pi-fw pi-share-alt', routerLink: ['/attack-paths'] }
        ];

        /**
         * **What can be shown, and to whom.**
         *
         * <p>These screens used to be read in two distant sections: the matrix, the exceptions, the
         * statement and the scope filed with the estate's state; the attestation, the verdicts and
         * the audit log filed with administration. Yet they answer a single question, and an
         * assessor opens them one after another. Separating them forced a reader to know the
         * product in order to find the continuation of their own reading.
         *
         * <p><b>Every entry carries its own condition, never the section.</b> Four of these routes
         * require governance read access; offering them to everybody would be offering a link that
         * leads to a refusal — the defect the deployment keys already had here. An ordinary account
         * sees the first three, an auditor all eight.
         */
        const evidenceItems = [
            { label: this.i18n.t('menu.compliance'), icon: 'pi pi-fw pi-check-circle', routerLink: ['/compliance'] },
            { label: this.i18n.t('menu.owasp_report'), icon: 'pi pi-fw pi-sparkles', routerLink: ['/owasp'] },

            // **Under compliance, because it is the question an assessor asks directly
            // afterwards.** The compliance screen says where things stand; this one says what was
            // waived to get there.
            { label: this.i18n.t('menu.exceptions'), icon: 'pi pi-fw pi-file-edit', routerLink: ['/exceptions'] },

            ...(this.session.canReadGovernance()
                ? [
                      // **The ISO 27001 document, and it opens on its divergences.** What is
                      // declared and what is measured are read together or not at all.
                      // **Next to the matrix, not filed elsewhere.** The matrix says where things
                      // stand, this one says whether they are improving — that is clause 9.3's
                      // question, and the two are read one after the other.
                      { label: this.i18n.t('menu.compliance_history'), icon: 'pi pi-fw pi-chart-line', routerLink: ['/compliance-history'] },

                      { label: this.i18n.t('menu.soa'), icon: 'pi pi-fw pi-book', routerLink: ['/soa'] },

                      // The scope is what the controls apply to, but nobody comes looking for it:
                      // one arrives here because a number in the statement will not add up.
                      { label: this.i18n.t('menu.scope'), icon: 'pi pi-fw pi-map', routerLink: ['/certified-scope'] },

                      // **What the gate answered.** Its policy is a setting and stays on the
                      // administration side; its refusals are evidence and are here.
                      { label: this.i18n.t('menu.gate_verdicts'), icon: 'pi pi-fw pi-ban', routerLink: ['/gate-verdicts'] },
                      { label: this.i18n.t('menu.attestation'), icon: 'pi pi-verified', routerLink: ['/attestation'] },
                      { label: this.i18n.t('menu.audit_log'), icon: 'pi pi-fw pi-history', routerLink: ['/audit-log'] }
                  ]
                : [])
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
                label: this.i18n.t('menu.evidence'),
                items: evidenceItems
            },
            {
                label: this.i18n.t('menu.operations'),
                items: [
                    { label: this.i18n.t('menu.notifications'), icon: 'pi pi-fw pi-bell', routerLink: ['/notifications'] },

                    // **Restricted, like the route and like the server.** A deployment key is
                    // administrative: `/ssh-keys` carries `requires('administrator')` and the
                    // controller `@RequiresAdministrator`. The menu, however, offered it to
                    // everybody — the one place in the sidebar offering a link that leads to a
                    // refusal, and therefore the only way of reaching `/forbidden` by clicking.
                    ...(this.session.isAdmin()
                        ? [{ label: this.i18n.t('menu.ssh_keys'), icon: 'pi pi-fw pi-key', routerLink: ['/ssh-keys'] }]
                        : [])
                ]
            }
        ];

        if (this.session.isAdmin() || this.session.canReadGovernance()) {
            const adminItems: MenuItem[] = [];

            // **Read, not write.** These three pages show the posture; the routes behind them are
            // `@RequiresGovernanceRead`, so an auditor reaches them. Gating the menu on
            // `isSecurityLead` would have left that account an empty sidebar in front of pages
            // that answer 200 — a permission granted on the server and withheld by the client.
            if (this.session.canReadGovernance()) {
                // **What *sets* a control stays here; what it *produces* has moved to the
                // evidence.** The gate policy says what would be refused, the rule sets what would
                // be looked for: two settings. The verdicts, the attestation and the audit log are
                // what gets shown, and are read following the rest of the evidence.
                adminItems.push(
                    { label: this.i18n.t('menu.gate_policies'), icon: 'pi pi-fw pi-flag', routerLink: ['/gate-policies'] },
                    { label: this.i18n.t('menu.semgrep_rules'), icon: 'pi pi-fw pi-shield', routerLink: ['/rule-sets'] }
                );
            }

            if (this.session.isAdmin()) {
                adminItems.push(
                    { label: this.i18n.t('menu.api_keys'), icon: 'pi pi-fw pi-verified', routerLink: ['/api-keys'] },
                    { label: this.i18n.t('menu.agents'), icon: 'pi pi-fw pi-server', routerLink: ['/agents'] },
                    { label: this.i18n.t('menu.users'), icon: 'pi pi-fw pi-users', routerLink: ['/users'] },
                    { label: this.i18n.t('menu.teams'), icon: 'pi pi-fw pi-sitemap', routerLink: ['/teams'] },
                );
            }

            // **The settings follow the server's rule, which is `@RequiresSecurityLead`.** They
            // were filed with the administration entries, so a CISO could write a setting — the
            // route allows it — without ever seeing the link to get there. The mismatch was visible
            // from neither side: the server said yes, the menu offered nothing, and nobody
            // complains about a door they cannot see.
            if (this.session.isSecurityLead()) {
                adminItems.push(
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
