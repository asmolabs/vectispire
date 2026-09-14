import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '@/app/core/api-error';
import { ApiService } from '@/app/core/api.service';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { RemediationBySeverity, RemediationDistribution } from '@/app/core/api.models';

/**
 * Les délais de correction, par la queue de distribution et non par la moyenne.
 *
 * **Une moyenne est tirée par le volume des correctifs faciles.** Ce qui décrit un processus,
 * c'est la part qui a tenu son délai, le 90e centile, et l'âge du plus ancien élément encore
 * ouvert — les trois que cet écran met au même niveau.
 *
 * **Le plus ancien élément ouvert est en haut, pas dans une colonne.** C'est la ligne qu'aucune
 * moyenne ne peut montrer et la première qu'un évaluateur demande ; la ranger dans le tableau
 * en ferait une donnée parmi neuf.
 *
 * Une gravité sans délai fixé n'affiche pas de pourcentage. Un taux calculé contre une règle
 * absente n'en est pas un, et il serait cité.
 */
@Component({
    selector: 'zs-remediation-delays',
    standalone: true,
    imports: [CommonModule, MessageModule, TranslatePipe],
    templateUrl: './remediation-delays.html'
})
export class RemediationDelays {
    private readonly api = inject(ApiService);
    private readonly i18n = inject(I18nService);

    readonly distribution = signal<RemediationDistribution | null>(null);
    readonly error = signal<string | null>(null);

    readonly rows = computed<RemediationBySeverity[]>(() => this.distribution()?.bySeverity ?? []);

    constructor() {
        this.api.remediationDistribution(90).subscribe({
            next: (data) => this.distribution.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('delays.load_failed')))
        });
    }

    /** Vert au-dessus de quatre-vingt-dix, ambre au-dessus de soixante-quinze, rouge sinon. */
    barColour(row: RemediationBySeverity): string {
        const share = row.percentageWithinSla ?? 0;
        return share >= 90 ? '#059669' : share >= 75 ? '#d97706' : '#b91c1c';
    }

    /** Une gravité que personne n'a dotée d'un délai n'a rien à tenir. */
    hasDeadline(row: RemediationBySeverity): boolean {
        return row.windowDays > 0 && row.percentageWithinSla !== null;
    }
}
