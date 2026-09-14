import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '@/app/core/api-error';
import { ApiService } from '@/app/core/api.service';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { RegisteredVerdict, VerdictRegister } from '@/app/core/api.models';

/**
 * Ce que la barrière a répondu, du plus récent au plus ancien.
 *
 * **Un refus est la seule preuve qu'un contrôle s'exécute.** « Toutes les cibles passent » ne
 * distingue pas un parc propre d'une barrière qui n'a jamais rien bloqué, et c'est la
 * distinction que cet écran existe pour faire. D'où le filtre « refus seulement » : c'est la
 * vue qu'on ouvre devant un auditeur, pas une commodité.
 *
 * **Le nombre d'issues examinées est affiché à côté du verdict, toujours.** Un passage après
 * examen de quatre cents issues et un passage après examen de zéro sont la même ligne sans
 * lui, et seul le premier prouve quelque chose.
 */
@Component({
    selector: 'zs-gate-verdicts',
    standalone: true,
    imports: [CommonModule, FormsModule, MessageModule, TagModule, TranslatePipe],
    templateUrl: './gate-verdicts.html'
})
export class GateVerdicts {
    private readonly api = inject(ApiService);
    private readonly i18n = inject(I18nService);

    readonly register = signal<VerdictRegister | null>(null);
    readonly error = signal<string | null>(null);
    readonly refusalsOnly = signal(false);

    /**
     * Le taux de refus, ou rien.
     *
     * Zéro verdict ne fait pas zéro pour cent : il ne fait pas de pourcentage du tout, et en
     * afficher un sur une instance neuve donnerait à lire « la barrière ne refuse rien » là où
     * la phrase est « la barrière n'a pas encore répondu ».
     */
    readonly refusalRate = computed(() => {
        const data = this.register();
        if (!data) {
            return null;
        }
        const total = data.passed + data.refused;
        return total === 0 ? null : Math.round((data.refused / total) * 1000) / 10;
    });

    readonly shown = computed<RegisteredVerdict[]>(() => {
        const rows = this.register()?.verdicts ?? [];
        return this.refusalsOnly() ? rows.filter((row) => !row.passed) : rows;
    });

    constructor() {
        this.api.gateVerdicts(200).subscribe({
            next: (data) => this.register.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('gate_verdicts.load_failed')))
        });
    }

    /** Les gravités dans l'ordre du pire au moins pire, et seulement celles qui portent un compte. */
    counts(row: RegisteredVerdict): { severity: string; count: number }[] {
        return ['critical', 'high', 'medium', 'low']
            .map((severity) => ({ severity, count: row.counts_by_severity?.[severity] ?? 0 }))
            .filter((entry) => entry.count > 0);
    }
}
