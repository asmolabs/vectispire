import { Component, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { ApiService } from '@/app/core/api.service';
import { QualityOverview, Tally } from '@/app/core/api.models';

/**
 * La qualité du code, agrégée.
 *
 * **Si cette page n'était que le backlog filtré, elle ne mériterait pas d'exister.**
 * Elle agrège donc sur des axes que le backlog n'offre pas — règles, fichiers, dépôts —
 * parce que devant un backlog de qualité à quatre chiffres, « huit règles font
 * soixante-dix pour cent de la dette » est le seul cadrage actionnable.
 *
 * Le bandeau dit explicitement que ces constats ne font jamais échouer une compilation.
 * Sans cette phrase, l'utilisateur suppose le contraire — et c'est cette supposition qui
 * fait désactiver un gate.
 */
@Component({
    selector: 'zs-qualite',
    standalone: true,
    imports: [ButtonModule, MessageModule, RouterLink],
    template: `
        <div class="card">
            <div class="font-semibold text-xl mb-1">Qualité</div>
            <p class="text-muted-color mb-4">Ce que l'analyse du code source signale sur la façon dont il est écrit, plutôt que sur sa sûreté.</p>

            <p-message severity="info" styleClass="w-full mb-4"
                text="Ces constats ne font jamais échouer une compilation. Ils sont visibles, exportables, et n'ont pas de voix au chapitre dans la barrière d'intégration continue." />

            @if (overview(); as data) {
                <div class="flex flex-wrap gap-6 mb-6">
                    <div><span class="text-2xl font-medium">{{ data.openCount }}</span><span class="text-muted-color ml-2">constats ouverts</span></div>
                    <div><span class="text-2xl font-medium">{{ data.ruleCount }}</span><span class="text-muted-color ml-2">règles distinctes</span></div>
                    <div><span class="text-2xl font-medium">{{ data.fileCount }}</span><span class="text-muted-color ml-2">fichiers touchés</span></div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    @for (group of groups(data); track group.title) {
                        <div>
                            <div class="font-medium mb-3">{{ group.title }}</div>
                            @for (row of group.rows; track row.label) {
                                <div class="mb-3">
                                    <div class="flex justify-between text-sm mb-1">
                                        <span class="truncate pr-2">{{ row.label ?? '—' }}</span>
                                        <span class="text-muted-color">{{ row.count }}</span>
                                    </div>
                                    <div class="bg-surface-200 dark:bg-surface-700 rounded" style="height: 6px">
                                        <div class="bg-primary rounded" style="height: 6px" [style.width.%]="share(row, group.rows)"></div>
                                    </div>
                                </div>
                            } @empty {
                                <div class="text-muted-color text-sm">Aucun constat.</div>
                            }
                        </div>
                    }
                </div>

                <div class="mt-6">
                    <p-button label="Voir tous les constats de qualité" [text]="true" [routerLink]="['/issues']" [queryParams]="{ type: 'quality' }" />
                </div>
            } @else if (error()) {
                <p-message severity="error" [text]="error()!" styleClass="w-full" />
            }
        </div>
    `
})
export class Qualite {
    private readonly api = inject(ApiService);
    readonly overview = signal<QualityOverview | null>(null);
    readonly error = signal<string | null>(null);

    constructor() {
        this.api.qualityOverview().subscribe({
            next: (data) => this.overview.set(data),
            error: () => this.error.set('Impossible de charger la vue qualité.')
        });
    }

    groups(data: QualityOverview) {
        return [
            { title: 'Règles les plus fréquentes', rows: data.topRules },
            { title: 'Fichiers les plus touchés', rows: data.topFiles },
            { title: 'Dépôts les plus denses', rows: data.topTargets }
        ];
    }

    /** Une part relative au plus gros du groupe : c'est la comparaison qui intéresse,
     *  pas la proportion du total. */
    share(row: Tally, rows: Tally[]): number {
        const largest = Math.max(...rows.map((item) => item.count), 1);
        return Math.round((row.count / largest) * 100);
    }
}
