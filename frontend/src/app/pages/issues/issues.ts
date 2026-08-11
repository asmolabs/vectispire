import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { IconFieldModule } from '@openng/optimus-ui/iconfield';
import { InputIconModule } from '@openng/optimus-ui/inputicon';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { ApiService } from '@/app/core/api.service';
import { Issue, IssueFilters } from '@/app/core/api.models';

/** Les justifications VEX d'une déclaration `not_affected`, telles que la norme les nomme. */
const VEX_JUSTIFICATIONS = [
    { value: 'component_not_present', label: 'Composant absent' },
    { value: 'vulnerable_code_not_present', label: 'Code vulnérable absent' },
    { value: 'vulnerable_code_not_in_execute_path', label: "Code vulnérable hors du chemin d'exécution" },
    { value: 'vulnerable_code_cannot_be_controlled_by_adversary', label: 'Non contrôlable par un adversaire' },
    { value: 'inline_mitigations_already_exist', label: 'Mesures de contournement déjà en place' }
];

/**
 * Le backlog, et le triage.
 *
 * **La pagination est côté serveur**, pas côté table. Un backlog mûr se compte en
 * milliers de lignes : les charger toutes pour en afficher cinquante ferait transiter
 * des mégaoctets et figerait le navigateur, et c'est précisément l'écran où cela
 * arriverait en premier.
 *
 * Le dialogue de triage reprend les règles VEX telles que l'API les applique — une
 * justification est **exigée** pour « non affecté », sans quoi la déclaration ne porte
 * aucune information et le document VEX exporté serait invalide. Le champ n'apparaît
 * donc que pour ce statut, et le bouton reste inactif tant qu'il est vide : mieux vaut
 * empêcher l'envoi que d'expliquer un refus après coup.
 */
@Component({
    selector: 'zs-issues',
    standalone: true,
    imports: [FormsModule, TableModule, TagModule, ButtonModule, SelectModule, InputTextModule, IconFieldModule, InputIconModule, DialogModule, TextareaModule, MessageModule],
    template: `
        <div class="card">
            <div class="font-semibold text-xl mb-1">Problèmes</div>
            <p class="text-muted-color mb-4">Ce que les scans ont trouvé, suivi d'un scan à l'autre. Un problème garde son historique et sa décision de triage.</p>

            <div class="flex flex-wrap gap-3 mb-4">
                <p-select [(ngModel)]="state" [options]="states" optionLabel="label" optionValue="value" (onChange)="reload(0)" placeholder="État" />
                <p-select [(ngModel)]="severity" [options]="severities" optionLabel="label" optionValue="value" (onChange)="reload(0)" placeholder="Sévérité" [showClear]="true" />
                <p-select [(ngModel)]="type" [options]="types" optionLabel="label" optionValue="value" (onChange)="reload(0)" placeholder="Type" [showClear]="true" />
                <p-iconfield>
                    <p-inputicon class="pi pi-search" />
                    <input pInputText [(ngModel)]="search" (keyup.enter)="reload(0)" placeholder="Identifiant, paquet, fichier" />
                </p-iconfield>
            </div>

            <p-table [value]="issues()" [tableStyle]="{ 'min-width': '60rem' }" [loading]="loading()">
                <ng-template #header>
                    <tr>
                        <th>Problème</th>
                        <th>Sévérité</th>
                        <th>Composant</th>
                        <th>Historique</th>
                        <th>Triage</th>
                        <th></th>
                    </tr>
                </ng-template>
                <ng-template #body let-issue>
                    <tr>
                        <td>
                            <span class="font-medium">{{ issue.identifier ?? '—' }}</span>
                            @if (issue.isKev) { <p-tag severity="danger" value="KEV" styleClass="ml-2" /> }
                            <div class="text-muted-color text-sm">{{ issue.filePath ?? issue.type }}</div>
                        </td>
                        <td><p-tag [severity]="severityColour(issue.severity)" [value]="issue.severity ?? 'unknown'" /></td>
                        <td>
                            <span>{{ issue.packageName ?? '—' }}</span>
                            @if (issue.packageVersion) { <span class="text-muted-color"> {{ issue.packageVersion }}</span> }
                        </td>
                        <td class="text-muted-color">vu {{ issue.timesSeen }}×</td>
                        <td>
                            <p-tag [severity]="triageColour(issue.triageStatus)" [value]="triageLabel(issue.triageStatus)" />
                            @if (issue.triagedBy) { <div class="text-muted-color text-sm">par {{ issue.triagedBy }}</div> }
                        </td>
                        <td><p-button label="Trier" size="small" [text]="true" (onClick)="openTriage(issue)" /></td>
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td colspan="6" class="text-center text-muted-color py-6">Aucun problème ne correspond à ces filtres.</td></tr>
                </ng-template>
            </p-table>

            <div class="flex items-center justify-between mt-4">
                <span class="text-muted-color">{{ pageLabel() }}</span>
                <div class="flex gap-2">
                    <p-button label="Précédent" size="small" [outlined]="true" [disabled]="offset() === 0" (onClick)="reload(offset() - limit)" />
                    <p-button label="Suivant" size="small" [outlined]="true" [disabled]="offset() + limit >= total()" (onClick)="reload(offset() + limit)" />
                </div>
            </div>
        </div>

        <p-dialog header="Trier ce problème" [(visible)]="triageOpen" [modal]="true" [style]="{ width: '32rem' }">
            <div class="flex flex-col gap-4">
                <div>
                    <label class="block font-medium mb-2">Décision</label>
                    <p-select [(ngModel)]="triageStatus" [options]="triageOptions" optionLabel="label" optionValue="value" styleClass="w-full" />
                </div>

                @if (triageStatus === 'not_affected') {
                    <div>
                        <label class="block font-medium mb-2">Justification <span class="text-red-500">*</span></label>
                        <p-select [(ngModel)]="triageJustification" [options]="justifications" optionLabel="label" optionValue="value" styleClass="w-full" placeholder="Choisir" />
                        <small class="text-muted-color">Exigée par la norme VEX : sans elle, la déclaration exportée ne porterait aucune information.</small>
                    </div>
                }

                <div>
                    <label class="block font-medium mb-2">Commentaire</label>
                    <textarea pTextarea [(ngModel)]="triageComment" rows="3" class="w-full"></textarea>
                </div>

                @if (triageStatus !== 'under_review') {
                    <div>
                        <label class="block font-medium mb-2">Réexaminer dans (jours)</label>
                        <input pInputText type="number" [(ngModel)]="triageExpiresInDays" class="w-full" />
                        <small class="text-muted-color">Une décision est un énoncé sur un contexte, et les contextes changent. Laisser vide pour ne pas programmer de réexamen.</small>
                    </div>
                }

                @if (triageError()) { <p-message severity="error" [text]="triageError()!" styleClass="w-full" /> }
            </div>

            <ng-template #footer>
                <p-button label="Annuler" [text]="true" (onClick)="triageOpen = false" />
                <p-button label="Enregistrer" [disabled]="!canSubmitTriage()" (onClick)="submitTriage()" />
            </ng-template>
        </p-dialog>
    `
})
export class Issues {
    private readonly api = inject(ApiService);
    private readonly route = inject(ActivatedRoute);

    readonly limit = 50;
    readonly issues = signal<Issue[]>([]);
    readonly total = signal(0);
    readonly offset = signal(0);
    readonly loading = signal(false);

    state = 'open';
    severity: string | null = null;
    type: string | null = null;
    search = '';

    readonly states = [
        { label: 'Ouverts', value: 'open' },
        { label: 'Résolus', value: 'resolved' },
        { label: 'Tous', value: 'all' }
    ];
    readonly severities = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'].map((value) => ({ label: value, value }));
    readonly types = [
        { label: 'Vulnérabilité', value: 'vulnerability' },
        { label: 'Secret exposé', value: 'secret' },
        { label: "Configuration d'infrastructure", value: 'iac' },
        { label: 'Licence', value: 'license' },
        { label: 'Fin de vie', value: 'eol' },
        { label: 'Code vulnérable', value: 'sast' },
        { label: 'Qualité du code', value: 'quality' }
    ];

    triageOpen = false;
    triageStatus = 'under_review';
    triageJustification: string | null = null;
    triageComment = '';
    triageExpiresInDays: number | null = null;
    readonly triageError = signal<string | null>(null);
    private triaged: Issue | null = null;

    readonly justifications = VEX_JUSTIFICATIONS;
    readonly triageOptions = [
        { label: 'À examiner', value: 'under_review' },
        { label: 'Affecté', value: 'affected' },
        { label: 'Non affecté', value: 'not_affected' },
        { label: 'Corrigé', value: 'fixed' }
    ];

    /** Les filtres de cible viennent de l'URL — c'est ce qui fait marcher les liens
     *  de l'écran Sécurité, que la version Reflex produisait sans jamais les lire. */
    private readonly targetFilters: IssueFilters = {};

    constructor() {
        const params = this.route.snapshot.queryParamMap;
        const repositoryId = params.get('repository_id');
        const containerId = params.get('container_id');
        if (repositoryId) this.targetFilters.repository_id = Number(repositoryId);
        if (containerId) this.targetFilters.container_id = Number(containerId);
        if (params.get('type')) this.type = params.get('type');
        this.reload(0);
    }

    reload(offset: number): void {
        this.loading.set(true);
        this.offset.set(Math.max(0, offset));
        this.api
            .issues({
                ...this.targetFilters,
                state: this.state,
                severity: this.severity ?? undefined,
                type: this.type ?? undefined,
                search: this.search || undefined,
                limit: this.limit,
                offset: this.offset()
            })
            .subscribe({
                next: (page) => {
                    this.issues.set(page.items);
                    this.total.set(page.total);
                    this.loading.set(false);
                },
                error: () => this.loading.set(false)
            });
    }

    pageLabel(): string {
        if (this.total() === 0) return 'Aucun résultat';
        return `${this.offset() + 1}–${Math.min(this.offset() + this.limit, this.total())} sur ${this.total()}`;
    }

    severityColour(severity: string | null): 'danger' | 'warn' | 'info' | 'secondary' {
        if (severity === 'critical' || severity === 'high') return 'danger';
        if (severity === 'medium') return 'warn';
        if (severity === 'low') return 'info';
        return 'secondary';
    }

    triageColour(status: string): 'success' | 'danger' | 'warn' | 'secondary' {
        if (status === 'not_affected' || status === 'fixed') return 'success';
        if (status === 'affected') return 'danger';
        return 'secondary';
    }

    triageLabel(status: string): string {
        return this.triageOptions.find((option) => option.value === status)?.label ?? status;
    }

    openTriage(issue: Issue): void {
        this.triaged = issue;
        this.triageStatus = issue.triageStatus;
        this.triageJustification = issue.triageJustification;
        this.triageComment = issue.triageComment ?? '';
        this.triageExpiresInDays = null;
        this.triageError.set(null);
        this.triageOpen = true;
    }

    /** Empêcher l'envoi vaut mieux qu'expliquer un refus après coup. */
    canSubmitTriage(): boolean {
        return this.triageStatus !== 'not_affected' || !!this.triageJustification;
    }

    submitTriage(): void {
        if (!this.triaged || !this.canSubmitTriage()) return;
        this.api
            .triage(this.triaged.id, {
                status: this.triageStatus,
                justification: this.triageJustification,
                comment: this.triageComment || null,
                expires_in_days: this.triageExpiresInDays || null
            })
            .subscribe({
                next: () => {
                    this.triageOpen = false;
                    this.reload(this.offset());
                },
                error: (response: { error?: { message?: string } }) => this.triageError.set(response.error?.message ?? 'Le triage a été refusé.')
            });
    }
}
