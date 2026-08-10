import { Component } from '@angular/core';

/**
 * Emplacement du tableau de bord. Le contenu réel — les six cartes de statistiques,
 * le donut de sévérité et l'activité de scan sur 14 jours — arrive au lot 5, une
 * fois que l'API d'administration a de quoi les alimenter.
 */
@Component({
    selector: 'zs-dashboard',
    standalone: true,
    template: `
        <div class="card">
            <div class="font-semibold text-xl mb-4">Tableau de bord</div>
            <p class="text-surface-500 dark:text-surface-400">Écran à construire (lot 5).</p>
        </div>
    `
})
export class Dashboard {}
