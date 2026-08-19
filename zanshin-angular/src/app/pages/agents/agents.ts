import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import type { AgentSummary, UnroutableLabel } from '../../core/api.models';

const CREDENTIALS = [
    { label: 'Clés locales', value: 'local', hint: "L'agent utilise ses propres identifiants git. Zanshin ne lui envoie aucune clé." },
    {
        label: 'Clés déléguées',
        value: 'delegated',
        hint: "Zanshin envoie la clé de déploiement du dépôt. Exige une liaison chiffrée — l'agent est refusé sinon."
    }
];

@Component({
    selector: 'app-agents',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, TableModule, TagModule],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">Agents</h1>
                <p class="text-muted-color mt-1 mb-0">Les travailleurs distants qui exécutent les scans.</p>
            </div>
            <p-button label="Déclarer un agent" icon="pi pi-plus" (onClick)="openForm()" />
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <!--
            **L'attente serait muette sans cela.** Une cible étiquetée « client » alors
            qu'aucun agent activé ne porte cette étiquette met ses scans en file, où ils
            restent indéfiniment : la page Dépôts dit « en attente », ce qui est vrai et
            n'explique rien. Ici, la cause est nommée et le correctif est à un champ près.
        -->
        @for (blocked of unroutable(); track blocked.label) {
            <p-message severity="warn" [closable]="false" styleClass="mb-4 w-full">
                {{ blocked.queued }} scan(s) exigent l'étiquette « {{ blocked.label }} », qu'aucun agent activé ne porte.
                Ils attendront tant que personne ne la déclare.
            </p-message>
        }

        <p-card>
            <p-table [value]="agents()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Agent</th>
                        <th>État</th>
                        <th>Machine</th>
                        <th>Étiquettes</th>
                        <th>Identifiants</th>
                        <th class="text-right">Scans</th>
                        <th class="w-1"></th>
                    </tr>
                </ng-template>
                <ng-template #body let-agent>
                    <tr>
                        <td>
                            <div class="font-medium">{{ agent.name }}</div>
                            @if (agent.description) {
                                <div class="text-sm text-muted-color">{{ agent.description }}</div>
                            }
                        </td>
                        <td>
                            <!--
                                « En ligne » veut dire vu récemment, pas activé. Un agent
                                activé mais muet depuis une heure est le cas qui compte : la
                                file se remplit, personne ne la vide, et rien d'autre à
                                l'écran ne le dirait.
                            -->
                            @if (!agent.enabled) {
                                <p-tag value="Désactivé" severity="secondary" />
                            } @else if (agent.online) {
                                <p-tag value="En ligne" severity="success" />
                            } @else {
                                <p-tag value="Muet" severity="warn" />
                            }
                            @if (agent.lastSeenAt) {
                                <div class="text-sm text-muted-color mt-1">Vu {{ agent.lastSeenAt | date: 'dd/MM HH:mm' }}</div>
                            } @else {
                                <div class="text-sm text-muted-color mt-1">Jamais annoncé</div>
                            }
                        </td>
                        <td>
                            @if (agent.hostname) {
                                <div class="text-sm">{{ agent.hostname }}</div>
                                <div class="text-sm text-muted-color">{{ agent.platform }} · {{ agent.version }}</div>
                            } @else {
                                <span class="text-muted-color">—</span>
                            }
                        </td>
                        <td>
                            @if (agent.labels) {
                                @for (label of agent.labels.split(','); track label) {
                                    <p-tag [value]="label" severity="info" styleClass="mr-1" />
                                }
                            } @else {
                                <!-- Sans étiquette, il ne prend que les cibles qui n'en exigent aucune. -->
                                <span class="text-muted-color text-sm">Cibles libres</span>
                            }
                        </td>
                        <td>
                            <span class="text-sm">{{ agent.credentialsMode === 'delegated' ? 'Déléguées' : 'Locales' }}</span>
                            <!--
                                Affiché seulement pour les identifiants délégués : c'est le seul cas où
                                une clé part. Un opérateur qui croit sceller alors que son agent est
                                d'une version antérieure n'aurait aucun autre moyen de s'en apercevoir,
                                et la clé traverserait son proxy inverse en clair.
                            -->
                            @if (agent.credentialsMode === 'delegated') {
                                <div class="text-sm" [class.text-muted-color]="agent.sealsCredentials">
                                    {{ agent.sealsCredentials ? 'Scellées de bout en bout' : 'En clair sous TLS' }}
                                </div>
                            }
                        </td>
                        <td class="text-right">{{ agent.runningScans }}</td>
                        <td class="text-right whitespace-nowrap">
                            <p-button [icon]="agent.enabled ? 'pi pi-ban' : 'pi pi-check'" [text]="true" [rounded]="true"
                                      [ariaLabel]="(agent.enabled ? 'Désactiver ' : 'Réactiver ') + agent.name"
                                      [disabled]="busy() === agent.id" (onClick)="toggle(agent)" />
                            <p-button icon="pi pi-trash" severity="danger" [text]="true" [rounded]="true"
                                      [ariaLabel]="'Supprimer ' + agent.name" (onClick)="askDelete(agent)" />
                        </td>
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr><td colspan="6" class="text-center text-muted-color py-6">Aucun agent déclaré. Les scans sont exécutés par le travailleur intégré.</td></tr>
                </ng-template>
            </p-table>
        </p-card>

        <p-dialog header="Déclarer un agent" [(visible)]="formVisible" [modal]="true" [style]="{ width: '34rem' }">
            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="name" class="font-medium">Nom</label>
                    <input pInputText id="name" [(ngModel)]="form.name" placeholder="runner-bruxelles-1" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="description" class="font-medium">Description <span class="text-muted-color font-normal">(facultatif)</span></label>
                    <input pInputText id="description" [(ngModel)]="form.description" />
                </div>
                <div class="flex flex-col gap-2">
                    <label for="mode" class="font-medium">Identifiants git</label>
                    <p-select id="mode" [options]="credentials" optionLabel="label" optionValue="value" [(ngModel)]="form.credentialsMode" styleClass="w-full" />
                    <small class="text-muted-color">{{ hintFor(form.credentialsMode) }}</small>
                </div>
                <div class="flex flex-col gap-2">
                    <label for="labels" class="font-medium">Étiquettes</label>
                    <input pInputText id="labels" [(ngModel)]="form.labels" placeholder="production, réseau-client" />
                    <small class="text-muted-color">
                        Ce que cet agent sait atteindre. Un dépôt ou une image peut exiger une étiquette :
                        seuls les agents qui la portent recevront ses scans — et sa clé de déploiement.
                        Sans étiquette, cet agent ne prend que les cibles qui n'en exigent aucune.
                    </small>
                </div>
                <div class="flex flex-col gap-2">
                    <label for="concurrent" class="font-medium">Scans en parallèle</label>
                    <p-inputnumber inputId="concurrent" [(ngModel)]="form.maxConcurrent" [min]="1" [max]="16" styleClass="w-full" />
                </div>
                @if (formError(); as message) {
                    <p-message severity="error" [closable]="false">{{ message }}</p-message>
                }
            </div>
            <ng-template #footer>
                <p-button label="Annuler" [text]="true" (onClick)="formVisible.set(false)" />
                <p-button label="Déclarer" [loading]="saving()" (onClick)="submit()" />
            </ng-template>
        </p-dialog>

        <!-- La clé n'existe qu'ici, comme pour les clés d'API. -->
        <p-dialog header="Agent déclaré" [(visible)]="secretVisible" [modal]="true" [closable]="false" [style]="{ width: '36rem' }">
            <p-message severity="warn" [closable]="false" styleClass="mb-4 w-full">
                Copiez cette clé maintenant : elle n'est stockée que sous forme d'empreinte et ne pourra pas être réaffichée.
                Donnez-la à l'agent par la variable <span class="font-mono">ZANSHIN_API_KEY</span>.
            </p-message>
            <div class="font-mono text-sm p-3 border rounded break-all select-all" style="border-color: var(--surface-border)">{{ issuedSecret() }}</div>
            <ng-template #footer>
                <p-button label="J'ai copié la clé" (onClick)="dismissSecret()" />
            </ng-template>
        </p-dialog>

        <p-dialog header="Supprimer cet agent ?" [(visible)]="deleteVisible" [modal]="true" [style]="{ width: '30rem' }">
            @if (pendingDelete(); as agent) {
                <p class="m-0">
                    <span class="font-medium">{{ agent.name }}</span> et sa clé d'API seront supprimés. L'agent ne pourra plus réclamer de scan.
                </p>
            }
            <ng-template #footer>
                <p-button label="Annuler" [text]="true" (onClick)="deleteVisible.set(false)" />
                <p-button label="Supprimer" severity="danger" [loading]="saving()" (onClick)="confirmDelete()" />
            </ng-template>
        </p-dialog>
    `
})
export class Agents {
    private readonly api = inject(ApiService);
    readonly credentials = CREDENTIALS;

    readonly agents = signal<AgentSummary[]>([]);
    readonly unroutable = signal<UnroutableLabel[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly busy = signal<string | null>(null);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    readonly secretVisible = signal(false);
    readonly issuedSecret = signal<string | null>(null);
    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<AgentSummary | null>(null);

    form = { name: '', description: '', credentialsMode: 'local', labels: '', maxConcurrent: 1 };

    constructor() {
        this.reload();
    }

    hintFor(mode: string): string {
        return CREDENTIALS.find((entry) => entry.value === mode)?.hint ?? '';
    }

    reload(preserveError = false): void {
        this.loading.set(true);
        // **Rechargées ensemble, et l'échec de la seconde ne masque pas la première.** Un
        // avertissement absent est moins grave qu'un écran vide, et la liste des agents est
        // ce que l'opérateur vient chercher.
        this.api.unroutableLabels().subscribe({
            next: (blocked) => this.unroutable.set(blocked),
            error: () => this.unroutable.set([])
        });

        this.api.agents().subscribe({
            next: (agents) => {
                this.agents.set(agents);
                if (!preserveError) this.error.set(null);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Impossible de charger la liste des agents.');
                this.loading.set(false);
            }
        });
    }

    toggle(agent: AgentSummary): void {
        this.busy.set(agent.id);
        this.error.set(null);
        this.api.setAgentEnabled(agent.id, !agent.enabled).subscribe({
            next: () => {
                this.busy.set(null);
                this.reload();
            },
            error: (response) => {
                this.busy.set(null);
                this.error.set(response?.error?.message ?? "L'opération a échoué.");
                this.reload(true);
            }
        });
    }

    openForm(): void {
        this.form = { name: '', description: '', credentialsMode: 'local', labels: '', maxConcurrent: 1 };
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        this.saving.set(true);
        this.api
            .createAgent({
                name: this.form.name.trim(),
                description: this.form.description.trim() || undefined,
                credentials_mode: this.form.credentialsMode,
                labels: this.form.labels.trim() || undefined,
                max_concurrent: this.form.maxConcurrent
            })
            .subscribe({
                next: (issued) => {
                    this.saving.set(false);
                    this.formVisible.set(false);
                    this.issuedSecret.set(issued.secret);
                    this.secretVisible.set(true);
                    this.reload();
                },
                error: (response) => {
                    this.saving.set(false);
                    this.formError.set(response?.error?.message ?? 'Impossible de déclarer cet agent.');
                }
            });
    }

    dismissSecret(): void {
        // Effacée du modèle en même temps que de l'écran : la garder laisserait la valeur
        // accessible dans l'onglet ouvert.
        this.issuedSecret.set(null);
        this.secretVisible.set(false);
    }

    askDelete(agent: AgentSummary): void {
        this.pendingDelete.set(agent);
        this.deleteVisible.set(true);
    }

    confirmDelete(): void {
        const agent = this.pendingDelete();
        if (!agent) return;
        this.saving.set(true);
        this.api.deleteAgent(agent.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.deleteVisible.set(false);
                // Notamment « cet agent exécute N scans » : le refus porte le nombre.
                this.error.set(response?.error?.message ?? 'La suppression a échoué.');
                this.reload(true);
            }
        });
    }
}
