import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { ApiService } from '@/app/core/api.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { OwaspGrid, OwaspCoverageLine, OwaspState } from '@/app/core/api.models';

/**
 * Les dix catégories, répondues par règle plutôt que par un modèle.
 *
 * <p><b>Quatre états et non deux, parce que deux mentiraient.</b> Une catégorie sans constat et
 * une catégorie que rien ne regarde produisent le même vert. Sept des dix ne sont couvertes par
 * aucun scanner ici, et le dire est la chose la plus utile que cette grille fasse.
 *
 * <p>Posée au-dessus du rapport écrit par le modèle, pas à sa place : le rapport produit la prose
 * qu'aucun moteur de règles n'écrit, et il ne sert pas de preuve. Les lire dans cet ordre est
 * l'ordre dans lequel ils valent quelque chose.
 */
@Component({
    selector: 'zs-owasp-grid',
    standalone: true,
    imports: [CommonModule, TranslatePipe],
    templateUrl: './owasp-grid.html'
})
export class OwaspGridComponent {
    private readonly api = inject(ApiService);

    readonly grid = signal<OwaspGrid | null>(null);

    /**
     * L'ordre du standard, toujours.
     *
     * <p>Trier par gravité mettrait les catégories actionnables en haut, ce qui est le bon réflexe
     * d'un tableau de bord et le mauvais ici : un questionnaire d'audit pose A01 puis A02, et une
     * grille réordonnée oblige à chercher chaque ligne.
     */
    readonly lines = computed<OwaspCoverageLine[]>(() => this.grid()?.lines ?? []);

    constructor() {
        this.api.owaspCoverage().subscribe({
            next: (data) => this.grid.set(data),
            error: () => this.grid.set(null)
        });
    }

    /**
     * Un zéro qui va bien se peint en vert, pas en alarme.
     *
     * <p>« 0 couverte mais non mesurée » en orange était une bonne nouvelle affichée comme un
     * problème. Un tableau où les bonnes nouvelles sont oranges apprend à ignorer l'orange.
     */
    alarming(count: number, tone: 'danger' | 'warn'): string {
        if (count === 0) {
            return 'text-emerald-700';
        }
        return tone === 'danger' ? 'text-red-700' : 'text-orange-700';
    }

    /** Le gris de « non couvert » n'est pas le vert de « rien trouvé », et c'est tout le sujet. */
    colourOf(state: OwaspState): string {
        switch (state) {
            case 'FINDINGS':
                return 'text-red-700';
            case 'NOT_MEASURED':
                return 'text-orange-700';
            case 'NOT_COVERED':
                return 'text-muted-color';
            default:
                return 'text-emerald-700';
        }
    }
}
