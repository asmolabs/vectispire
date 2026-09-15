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
         * **L'état du parc : ce qui ne va pas, et ce qu'on en fait.**
         *
         * Seize entrées s'y étaient accumulées, dont sept qui ne parlaient pas du parc mais de ce
         * qu'on peut en montrer. Une section qu'on parcourt des yeux pour trouver son écran a
         * cessé d'être un menu ; les deux questions sont maintenant deux sections.
         */
        const securityItems = [
            { label: this.i18n.t('menu.posture'), icon: 'pi pi-fw pi-shield', routerLink: ['/security'] },
            { label: this.i18n.t('menu.issues'), icon: 'pi pi-fw pi-exclamation-triangle', routerLink: ['/issues'] },

            // **Juste après la liste des constats, et pas ailleurs.** L'une dit ce qui ne va pas,
            // l'autre ce qu'on en fait ; les séparer dans le menu séparait la question de sa
            // réponse.
            { label: this.i18n.t('menu.remediation'), icon: 'pi pi-fw pi-wrench', routerLink: ['/remediation'] },

            // **Juste après l'ordre de travail, parce que c'est sa mesure.** L'un dit par quoi
            // commencer, l'autre si on a tenu les délais qu'on s'est donnés.
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
         * **Ce qu'on peut montrer, et à qui.**
         *
         * <p>Ces écrans se lisaient dans deux sections éloignées : la matrice, les exceptions, la
         * déclaration et le périmètre rangés avec l'état du parc, l'attestation, les verdicts et
         * le journal d'audit rangés avec l'administration. Or ils répondent à une seule question,
         * et un évaluateur les ouvre l'un après l'autre. Les séparer obligeait à connaître le
         * produit pour trouver la suite de sa propre lecture.
         *
         * <p><b>Chaque entrée porte sa propre condition, jamais la section.</b> Quatre de ces
         * routes exigent la lecture de gouvernance ; les proposer à tout le monde serait offrir un
         * lien qui mène à un refus — le défaut que les clés de déploiement ont déjà eu ici. Un
         * compte ordinaire voit les trois premières, un auditeur les huit.
         */
        const evidenceItems = [
            { label: this.i18n.t('menu.compliance'), icon: 'pi pi-fw pi-check-circle', routerLink: ['/compliance'] },
            { label: this.i18n.t('menu.owasp_report'), icon: 'pi pi-fw pi-sparkles', routerLink: ['/owasp'] },

            // **Sous la conformité, parce que c'est la question qu'un évaluateur pose juste
            // après.** L'écran de conformité dit où on en est ; celui-ci dit ce qu'on a écarté
            // pour y arriver.
            { label: this.i18n.t('menu.exceptions'), icon: 'pi pi-fw pi-file-edit', routerLink: ['/exceptions'] },

            ...(this.session.canReadGovernance()
                ? [
                      // **Le document ISO 27001, et il ouvre sur ses écarts.** Ce qu'on déclare et
                      // ce qu'on mesure se lisent ensemble ou pas du tout.
                      { label: this.i18n.t('menu.soa'), icon: 'pi pi-fw pi-book', routerLink: ['/soa'] },

                      // Le périmètre est ce à quoi les contrôles s'appliquent, mais personne ne
                      // vient le chercher : on y arrive parce qu'un chiffre de la déclaration ne
                      // s'explique pas.
                      { label: this.i18n.t('menu.scope'), icon: 'pi pi-fw pi-map', routerLink: ['/certified-scope'] },

                      // **Ce que la barrière a répondu.** Sa politique est un réglage et reste
                      // côté administration ; ses refus sont une preuve et sont ici.
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

                    // **Réservé, comme la route et comme le serveur.** Une clé de déploiement est
                    // administrative : `/ssh-keys` porte `requires('administrator')` et le
                    // contrôleur `@RequiresAdministrator`. Le menu, lui, la proposait à tout le
                    // monde — c'était le seul endroit de la barre latérale à offrir un lien qui
                    // mène à un refus, et donc la seule façon d'atteindre `/forbidden` en cliquant.
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
                // **Ce qui *règle* un contrôle reste ici ; ce qu'il *produit* est passé dans les
                // preuves.** La politique de barrière dit ce qui serait refusé, les jeux de règles
                // ce qui serait cherché : deux réglages. Les verdicts, l'attestation et le journal
                // d'audit sont ce qu'on montre, et se lisent à la suite du reste des preuves.
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

            // **Les réglages suivent la règle du serveur, qui est `@RequiresSecurityLead`.**
            // Ils étaient rangés avec les entrées d'administration, si bien qu'un CISO pouvait
            // écrire un réglage — la route l'autorise — sans jamais voir le lien pour y aller.
            // Le décalage n'était visible d'aucun côté : le serveur disait oui, le menu ne
            // proposait rien, et personne ne se plaint d'une porte qu'il ne voit pas.
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
