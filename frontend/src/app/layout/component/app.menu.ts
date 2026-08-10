import { Component, computed, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MenuItem } from '@openng/optimus-ui/api';
import { AppMenuitem } from './app.menuitem';

/** Les rôles auxquels la rubrique Administration est réservée. */
export const ADMIN_ROLES = ['SUPERUSER', 'ADMIN'];

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
     * Le rôle de l'utilisateur connecté. Alimenté par le service de session au lot 1 ;
     * en attendant, la rubrique Administration est masquée par défaut — se tromper
     * dans ce sens ne montre rien de trop, l'inverse si.
     */
    readonly userRole = signal<string>('');

    readonly model = computed<MenuItem[]>(() => {
        const sections: MenuItem[] = [
            {
                label: 'Tableau de bord',
                items: [{ label: 'Tableau de bord', icon: 'pi pi-fw pi-home', routerLink: ['/dashboard'] }]
            },
            {
                label: 'Sécurité',
                items: [
                    { label: 'Sécurité', icon: 'pi pi-fw pi-shield', routerLink: ['/securite'] },
                    { label: 'Problèmes', icon: 'pi pi-fw pi-exclamation-triangle', routerLink: ['/issues'] },
                    { label: 'Dépôts & Scans', icon: 'pi pi-fw pi-sitemap', routerLink: ['/depots'] },
                    { label: 'Conteneurs', icon: 'pi pi-fw pi-box', routerLink: ['/containers'] }
                ]
            },
            {
                label: 'Qualité',
                items: [{ label: 'Qualité', icon: 'pi pi-fw pi-sparkles', routerLink: ['/qualite'] }]
            },
            {
                label: 'Exploitation',
                items: [{ label: 'Clés SSH', icon: 'pi pi-fw pi-key', routerLink: ['/ssh-keys'] }]
            }
        ];

        // Masquer la rubrique n'est pas ce qui protège quoi que ce soit : chaque
        // endpoint porte sa propre garde côté serveur. C'est du confort de lecture,
        // et il faut que ça reste énoncé pour que personne ne s'y fie.
        if (ADMIN_ROLES.includes(this.userRole())) {
            sections.push({
                label: 'Administration',
                items: [
                    { label: 'Clés API', icon: 'pi pi-fw pi-verified', routerLink: ['/api-keys'] },
                    { label: 'Agents', icon: 'pi pi-fw pi-server', routerLink: ['/agents'] },
                    { label: 'Utilisateurs', icon: 'pi pi-fw pi-users', routerLink: ['/users'] },
                    { label: "Journal d'audit", icon: 'pi pi-fw pi-history', routerLink: ['/audit-log'] },
                    { label: 'Paramètres', icon: 'pi pi-fw pi-cog', routerLink: ['/settings'] }
                ]
            });
        }

        return sections;
    });
}
