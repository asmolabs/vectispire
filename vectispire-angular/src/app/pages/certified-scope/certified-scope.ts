import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '@/app/core/api-error';
import { ApiService } from '@/app/core/api.service';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { MonitoredContainer, MonitoredRepository, ScopeView } from '@/app/core/api.models';

/**
 * Ce que le périmètre certifié couvre, et combien de lui porte une preuve courante.
 *
 * **Un outil qui mesure sa propre couverture annonce toujours cent pour cent.** Tous les autres
 * écrans répondent à une question sur les cibles que quelqu'un a enregistrées ; un système de
 * management a un périmètre déclaré dans un document, et les deux ne sont pas le même
 * ensemble. Un parc entièrement scanné fait de la moitié des actifs certifiés se lit comme un
 * résultat propre, et aucune requête ne peut s'en apercevoir.
 *
 * **D'où le chiffre en haut de l'écran, qui porte sur ce qui manque.** « Votre périmètre nomme
 * quarante actifs, cette instance en détient trente et un » est la phrase par laquelle un audit
 * commence, et elle ne se dérive pas : le nombre déclaré est recopié du document de périmètre.
 *
 * **Rien n'est dans le périmètre par défaut.** Un périmètre que personne n'a tracé est un
 * périmètre non tracé, pas le parc entier — et l'écran dit « non déclaré » plutôt que de
 * produire un pourcentage contre un dénominateur inconnu.
 */
@Component({
    selector: 'zs-certified-scope',
    standalone: true,
    imports: [CommonModule, FormsModule, MessageModule, TranslatePipe],
    templateUrl: './certified-scope.html'
})
export class CertifiedScope {
    private readonly api = inject(ApiService);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);

    readonly scope = signal<ScopeView | null>(null);
    readonly repositories = signal<MonitoredRepository[]>([]);
    readonly containers = signal<MonitoredContainer[]>([]);
    readonly error = signal<string | null>(null);

    readonly canEdit = computed(() => this.session.isSecurityLead());

    readonly declared = computed(() => (this.scope()?.coverage.declaredAssets ?? 0) > 0);

    /**
     * Les actifs que la déclaration revendique et dont l'instance n'a aucune ligne.
     *
     * Zéro quand personne n'a déclaré de nombre — *pas* quand la couverture est complète. Les
     * deux se distinguent par {@link declared}, et les confondre est tout le piège : un
     * périmètre non déclaré ne rapporte aucun écart pour la même raison qu'une pièce vide ne
     * rapporte aucun bruit.
     */
    readonly unaccountedFor = computed(() => {
        const coverage = this.scope()?.coverage;
        if (!coverage || coverage.declaredAssets <= 0) {
            return 0;
        }
        return Math.max(0, coverage.declaredAssets - coverage.inScope);
    });

    /**
     * La part du périmètre *déclaré* qui porte une preuve fraîche, ou rien.
     *
     * Contre le nombre déclaré et non contre ce que l'instance détient : diviser par ce qu'on a
     * est exactement la façon dont un outil annonce cent pour cent sur un dixième d'un parc.
     */
    readonly freshShare = computed<number | null>(() => {
        const coverage = this.scope()?.coverage;
        if (!coverage || coverage.declaredAssets <= 0) {
            return null;
        }
        return Math.round((100 * coverage.scannedRecently) / coverage.declaredAssets);
    });

    constructor() {
        this.api.certifiedScope().subscribe({
            next: (data) => this.scope.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('scope.load_failed')))
        });
        this.api.repositories().subscribe({ next: (rows) => this.repositories.set(rows), error: () => undefined });
        this.api.containers().subscribe({ next: (rows) => this.containers.set(rows), error: () => undefined });
    }

    inScope(kind: string, id: number): boolean {
        return (this.scope()?.targets ?? []).some((target) => target.kind === kind && target.id === id);
    }

    toggleRepository(id: number, next: boolean): void {
        this.api.setRepositoryInScope(id, next).subscribe({
            next: (data) => this.scope.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('scope.update_failed')))
        });
    }

    toggleContainer(id: number, next: boolean): void {
        this.api.setContainerInScope(id, next).subscribe({
            next: (data) => this.scope.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('scope.update_failed')))
        });
    }
}
