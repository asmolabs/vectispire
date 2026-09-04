import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '@/app/core/api.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { HighImpactFix, SecurityDebtReport } from '@/app/core/api.models';

/**
 * Ce qu'il faut faire, dans l'ordre — et non ce qui ne va pas.
 *
 * <p><b>Le calcul existait, l'écran n'existait pas.</b> {@code /api/v1/remediation/high-impact-fixes}
 * classe les mises à jour par ce qu'elles ferment sur ce qu'elles coûtent, et
 * {@code getHighImpactFixes} attendait dans le service front sans qu'aucun composant ne l'appelle.
 * Le produit savait donc répondre à « par quoi je commence » et ne le disait à personne : le
 * tableau de bord en montrait un extrait dans une carte, entre huit autres.
 *
 * <p><b>Une action par ligne, et non une vulnérabilité par ligne.</b> C'est la différence avec la
 * liste des constats. Quatorze constats de la même bibliothèque sur six dépôts ne sont pas
 * quatorze décisions : c'est une montée de version. La liste des constats répond « qu'est-ce qui
 * ne va pas », celle-ci répond « qu'est-ce que je fais lundi matin », et une équipe qui n'a que la
 * première trie du bruit au lieu de réduire du risque.
 *
 * <p><b>La dette est en tête parce qu'elle donne l'échelle.</b> Un ordre de travail sans total se
 * lit comme une liste infinie ; savoir que les dix premières lignes ferment la moitié du parc est
 * ce qui fait commencer.
 */
@Component({
    selector: 'app-remediation',
    standalone: true,
    imports: [CommonModule, RouterLink, ButtonModule, MessageModule, TagModule, TranslatePipe],
    templateUrl: './remediation.html'
})
export class Remediation {
    private readonly api = inject(ApiService);

    readonly fixes = signal<HighImpactFix[]>([]);
    readonly debt = signal<SecurityDebtReport | null>(null);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);
    readonly expanded = signal<string | null>(null);

    /**
     * Ce que les lignes affichées ferment, additionné.
     *
     * <p>Un même CVE peut apparaître sous deux paquets ; ce total compte donc des constats et non
     * des vulnérabilités distinctes, et le libellé le dit.
     */
    readonly closedByTheList = computed(() =>
        this.fixes().reduce((sum, fix) => sum + fix.cveCountResolved, 0));

    readonly hoursOfTheList = computed(() =>
        Math.round(this.fixes().reduce((sum, fix) => sum + fix.estimatedHours, 0) * 10) / 10);

    constructor() {
        this.api.getHighImpactFixes().subscribe({
            next: (fixes) => { this.fixes.set(fixes); this.loading.set(false); },
            error: () => {
                this.error.set('Le plan de remédiation n\'a pas pu être calculé.');
                this.loading.set(false);
            }
        });

        // Séparément : une dette indisponible ne doit pas effacer un ordre de travail qui, lui,
        // est arrivé. C'est le contexte de la page, pas son sujet.
        this.api.getSecurityDebt().subscribe({ next: (debt) => this.debt.set(debt), error: () => {} });
    }

    toggle(fix: HighImpactFix): void {
        this.expanded.set(this.expanded() === fix.packageName ? null : fix.packageName);
    }

    isExpanded(fix: HighImpactFix): boolean {
        return this.expanded() === fix.packageName;
    }

    /**
     * La sévérité qui commande la ligne, pour la teinte.
     *
     * <p>Une seule critique décide de la couleur : c'est elle qui décide de l'urgence, et une
     * moyenne l'aurait diluée dans le nombre.
     */
    severityOf(fix: HighImpactFix): 'danger' | 'warn' | 'info' {
        if (fix.criticalCveCount > 0) return 'danger';
        if (fix.highCveCount > 0) return 'warn';
        return 'info';
    }
}
