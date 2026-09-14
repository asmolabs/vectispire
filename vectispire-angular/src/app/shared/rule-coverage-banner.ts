import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { ApiService } from '@/app/core/api.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { RuleCoverageAssessment } from '@/app/core/api.models';

/**
 * Dit quand une absence de constat est une absence de recherche.
 *
 * **Sans lui, une instance sans règle pour ses langages affiche « 0 » en vert.** Le produit
 * embarque une seule règle Semgrep, en Python — les jeux publics ne sont pas
 * redistribuables — donc un parc en Java et TypeScript rapporte zéro constat de code et le
 * lit comme une bonne nouvelle. C'est toute la différence que ce composant introduit.
 *
 * **Il nomme la conséquence, jamais le réglage.** « L'analyse de code ne couvre qu'un motif,
 * en Python » se comprend sans savoir ce qu'est un jeu de règles ; « aucun jeu actif » ne se
 * comprend qu'en le sachant déjà.
 *
 * **Rien quand la couverture est complète.** Un avertissement affiché quand tout va bien perd
 * son sens en quelques jours, et alors celui qui compte devient invisible aussi. C'est la
 * raison pour laquelle l'état `COVERED` ne rend rien du tout.
 */
@Component({
    selector: 'zs-rule-coverage-banner',
    standalone: true,
    imports: [CommonModule, ButtonModule, RouterLink, TranslatePipe],
    templateUrl: './rule-coverage-banner.html'
})
export class RuleCoverageBanner {
    private readonly api = inject(ApiService);

    readonly coverage = signal<RuleCoverageAssessment | null>(null);

    /**
     * Rien tant que la réponse n'est pas là, et rien si elle n'arrive pas.
     *
     * Un bandeau d'erreur sur un écran qui a par ailleurs chargé dirait « quelque chose ne va
     * pas » sans dire quoi, au-dessus de données valides. L'écran hôte porte ses propres
     * erreurs ; celui-ci se tait.
     */
    readonly visible = computed(() => {
        const state = this.coverage()?.state;
        return state === 'UNCONFIGURED' || state === 'PARTIAL';
    });

    readonly uncovered = computed(() => this.coverage()?.uncovered ?? []);

    constructor() {
        this.api.ruleCoverage().subscribe({
            next: (data) => this.coverage.set(data),
            error: () => this.coverage.set(null)
        });
    }
}
