import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '@/app/core/api-error';
import { ApiService } from '@/app/core/api.service';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { ComplianceMovement, ComplianceSeries, ComplianceStep } from '@/app/core/api.models';

/**
 * La progression de chaque cadre, mois par mois.
 *
 * <p><b>Une ligne seule tromperait.</b> La note baisse quand on enregistre un dépôt de plus, et
 * quand on allume un détecteur : dans les deux cas parce qu'on surveille plus large. Un graphique
 * tracé sans ça rapporte « on a régressé » le mois où quelqu'un a commencé à mieux surveiller, et
 * l'équipe qui le lit apprend à surveiller moins.
 *
 * <p>Chaque mois porte donc sa cause plausible, et une série dont le parc a changé est annoncée
 * <em>non comparable</em> plutôt que tracée comme une tendance.
 *
 * <p>Six cadres, six séries. Pas de note globale : un chiffre agrégé se fait piloter — on
 * l'améliore en ajoutant un cadre facile, et un chiffre qu'on peut améliorer sans toucher au parc
 * est un chiffre que quelqu'un finit par améliorer ainsi.
 */
@Component({
    selector: 'zs-compliance-history',
    standalone: true,
    imports: [CommonModule, MessageModule, TranslatePipe],
    templateUrl: './compliance-history.html'
})
export class ComplianceHistoryPage {
    private readonly api = inject(ApiService);
    private readonly i18n = inject(I18nService);

    readonly series = signal<ComplianceSeries[]>([]);
    readonly error = signal<string | null>(null);

    constructor() {
        this.api.complianceHistory().subscribe({
            next: (data) => this.series.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('history_compliance.load_failed')))
        });
    }

    /**
     * La hauteur d'une barre, en pourcentage de la plus haute du graphique.
     *
     * <p>Rapportée à cent et non au maximum de la série : une échelle qui s'ajuste ferait passer
     * une progression de deux points pour une envolée, et c'est la note qu'on lit, pas sa forme.
     */
    height(step: ComplianceStep): number {
        return Math.max(2, step.snapshot.score);
    }

    /** Un mouvement qui n'est pas le travail ne se peint pas comme le travail. */
    colourOf(movement: ComplianceMovement): string {
        switch (movement) {
            case 'IMPROVED':
                return 'bg-emerald-500';
            case 'DECLINED':
                return 'bg-red-500';
            case 'ESTATE_GREW':
            case 'ESTATE_SHRANK':
            case 'RULES_CHANGED':
                return 'bg-amber-400';
            default:
                return 'bg-surface-400';
        }
    }

    signed(delta: number): string {
        return delta > 0 ? `+${delta}` : String(delta);
    }
}
