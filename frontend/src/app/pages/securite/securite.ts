import { Component, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '@/app/core/api.service';
import { SecurityOverview, TargetPosture } from '@/app/core/api.models';

/**
 * La posture de sécurité — le verdict du gate, enfin affiché.
 *
 * Il était calculé depuis toujours pour `POST /api/v1/gate` et montré nulle part :
 * une équipe ne pouvait apprendre si son dépôt passait qu'en lançant une compilation
 * contre lui.
 *
 * **La colonne qui compte le plus n'est pas le verdict, c'est l'observation.** Un
 * backlog vide passe toutes les politiques ; une cible que personne n'a scannée avec
 * succès affiche donc « conforme » sans que cela veuille rien dire. Le badge
 * « non observée » est ce qui empêche cet écran d'être trompeur, et le bandeau le
 * répète en tête.
 */
@Component({
    selector: 'zs-securite',
    standalone: true,
    imports: [TableModule, TagModule, ButtonModule, MessageModule, RouterLink],
    template: `
        <div class="card">
            <div class="font-semibold text-xl mb-1">Sécurité</div>
            <p class="text-muted-color mb-4">Le verdict que rendrait la barrière d'intégration continue pour chaque cible, avec la politique qui l'a produit.</p>

            @if (overview(); as data) {
                <div class="flex flex-wrap gap-6 mb-4">
                    <div>
                        <span class="text-2xl font-medium" [class.text-red-500]="data.failingCount > 0">{{ data.failingCount }}</span>
                        <span class="text-muted-color ml-2">/ {{ data.totalCount }} non conformes</span>
                    </div>
                    <div><span class="text-2xl font-medium">{{ data.kevCount }}</span><span class="text-muted-color ml-2">KEV ouverts</span></div>
                    <div><span class="text-2xl font-medium">{{ data.neverScannedCount }}</span><span class="text-muted-color ml-2">jamais scannées</span></div>
                    <div><span class="text-2xl font-medium">{{ data.lastScanFailedCount }}</span><span class="text-muted-color ml-2">dernier scan en échec</span></div>
                </div>

                @if (data.neverScannedCount + data.lastScanFailedCount > 0) {
                    <p-message severity="warn" styleClass="w-full mb-4"
                        text="Certaines cibles n'ont pas été observées. Un backlog vide passe toutes les politiques : leur verdict ne dit rien tant qu'un scan n'a pas abouti." />
                }

                <p-table [value]="data.targets" [tableStyle]="{ 'min-width': '50rem' }">
                    <ng-template #header>
                        <tr>
                            <th>Cible</th>
                            <th>Verdict</th>
                            <th>Évalués</th>
                            <th>Politique</th>
                            <th>Dernier scan</th>
                            <th></th>
                        </tr>
                    </ng-template>
                    <ng-template #body let-target>
                        <tr>
                            <td>
                                <span class="font-medium">{{ target.name }}</span>
                                <div class="text-muted-color text-sm">{{ target.kind === 'repository' ? 'Dépôt' : 'Conteneur' }}</div>
                            </td>
                            <td>
                                <p-tag [severity]="target.passed ? 'success' : 'danger'" [value]="target.passed ? 'Conforme' : 'Non conforme'" />
                                @if (!target.observed) {
                                    <p-tag severity="warn" [value]="observationLabel(target)" styleClass="ml-2" />
                                }
                                @if (target.verdict.violations.length) {
                                    <div class="text-muted-color text-sm mt-1">{{ target.verdict.violations[0].reason }}</div>
                                }
                            </td>
                            <td>{{ target.verdict.evaluated }}</td>
                            <td class="text-muted-color">{{ target.policy.source === 'built-in' ? 'défaut' : target.policy.source + ' v' + target.policy.version }}</td>
                            <td class="text-muted-color">{{ formatDate(target.lastScanAt) }}</td>
                            <td>
                                <p-button label="Problèmes" size="small" [text]="true" [routerLink]="['/issues']" [queryParams]="issueFilter(target)" />
                            </td>
                        </tr>
                    </ng-template>
                    <ng-template #emptymessage>
                        <tr><td colspan="6" class="text-center text-muted-color py-6">Aucune cible surveillée.</td></tr>
                    </ng-template>
                </p-table>
            } @else if (error()) {
                <p-message severity="error" [text]="error()!" styleClass="w-full" />
            }
        </div>
    `
})
export class Securite {
    private readonly api = inject(ApiService);

    readonly overview = signal<SecurityOverview | null>(null);
    readonly error = signal<string | null>(null);

    constructor() {
        this.api.securityOverview().subscribe({
            next: (data) => this.overview.set(data),
            error: () => this.error.set('Impossible de charger la posture de sécurité.')
        });
    }

    /**
     * L'horodatage rendu lisible.
     *
     * L'API rend le texte que la base contient — `2026-08-10 18:45:18.408868` —, ce qui
     * est la bonne chose à transporter (la microseconde survit, aucun fuseau n'est
     * appliqué au passage) et la mauvaise chose à afficher. La conversion se fait donc
     * ici, au dernier moment, et nulle part avant.
     */
    formatDate(value: string | null): string {
        if (!value) return '—';
        // Suffixe `Z` explicite : la valeur est de l'UTC sans fuseau, et sans lui le
        // navigateur la lirait comme une heure locale — donc l'afficherait décalée.
        const at = new Date(`${value.replace(' ', 'T')}Z`);
        return Number.isNaN(at.getTime()) ? value : at.toLocaleString('fr-BE', { dateStyle: 'short', timeStyle: 'short' });
    }

    observationLabel(target: TargetPosture): string {
        if (target.observation === 'never_scanned') return 'Jamais scannée';
        if (target.observation === 'last_scan_failed') return 'Dernier scan en échec';
        return 'Scan en cours';
    }

    /**
     * Le lien vers le backlog filtré sur cette cible.
     *
     * Ces paramètres étaient déjà produits par la version Reflex — et **jamais lus** par
     * son écran Problèmes, qui n'utilisait les paramètres d'URL nulle part. Ici le
     * routeur Angular les transmet, et le contrôleur les honore.
     */
    issueFilter(target: TargetPosture): Record<string, number> {
        return target.kind === 'repository' ? { repository_id: target.targetId } : { container_id: target.targetId };
    }
}
