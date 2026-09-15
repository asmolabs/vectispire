import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { SelectModule } from '@openng/optimus-ui/select';
import { ApiService } from '../../core/api.service';
import { I18nService } from '../../core/i18n/i18n.service';
import type { InventoryOccurrence, MonitoredContainer, MonitoredRepository, SbomDiffReport } from '../../core/api.models';
import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-inventory',
    standalone: true,
    imports: [CommonModule, FormsModule, CardModule, SelectModule, TableModule, TagModule, MessageModule, ButtonModule, InputTextModule, TranslatePipe],
    templateUrl: './inventory.html'
})
export class Inventory {
    private readonly api = inject(ApiService);
    private readonly i18n = inject(I18nService);

    name = '';
    version = '';

    readonly occurrences = signal<InventoryOccurrence[]>([]);
    readonly truncated = signal(false);
    readonly loading = signal(false);
    readonly searched = signal(false);
    readonly error = signal<string | null>(null);

    readonly activeTab = signal<'search' | 'diff'>('search');

    /**
     * Le différentiel entre deux inventaires.
     *
     * <p><b>Il fallait taper deux numéros de scan à la main.</b> « ex: 10 », « ex: 12 » — deux
     * identifiants internes qu'aucun écran n'affiche en évidence, pour une question qui se pose
     * presque toujours ainsi : « qu'est-ce qui a changé dans ce dépôt depuis la dernière fois ».
     * `getLatestSbomDiff` répondait déjà exactement à celle-là, et aucun composant ne l'appelait.
     *
     * <p>La comparaison de deux scans nommés reste, parce qu'elle répond à une autre question —
     * « entre la version qu'on a livrée et celle d'avant » — que la dernière paire ne couvre pas.
     */
    fromScanId: number | null = null;
    toScanId: number | null = null;
    readonly diffReport = signal<SbomDiffReport | null>(null);
    readonly diffLoading = signal(false);
    readonly diffError = signal<string | null>(null);

    /** Les cibles comparables, dépôts et images ensemble : la question ne se pose pas autrement. */
    readonly targets = signal<{ label: string; value: string }[]>([]);
    diffTarget = '';

    constructor() {
        // Chargées à part : ne pas pouvoir les lister laisse la comparaison par numéros, qui
        // était jusqu'ici le seul chemin.
        this.api.repositories().subscribe({
            next: (repositories: MonitoredRepository[]) => this.addTargets(
                repositories.map((repository) => ({
                    label: repository.name ?? repository.url,
                    value: `repo:${repository.id}`
                }))),
            error: () => {}
        });
        this.api.containers().subscribe({
            next: (containers: MonitoredContainer[]) => this.addTargets(
                containers.map((container) => ({
                    label: `${container.imageName}:${container.tag}`,
                    value: `container:${container.id}`
                }))),
            error: () => {}
        });
    }

    private addTargets(more: { label: string; value: string }[]): void {
        this.targets.update((current) => [...current, ...more]);
    }

    search(): void {
        if (!this.name.trim()) {
            return;
        }
        this.loading.set(true);
        this.error.set(null);

        this.api.searchComponents(this.name.trim(), this.version.trim()).subscribe({
            next: (results) => {
                this.occurrences.set(results.occurrences);
                this.truncated.set(results.truncated);
                this.searched.set(true);
                this.loading.set(false);
            },
            error: () => {
                this.loading.set(false);
                this.error.set('The search could not be run.');
            }
        });
    }

    /**
     * Ce qui a changé sur une cible depuis son avant-dernier scan.
     *
     * <p>Le refus porte sa cause : une cible scannée une seule fois n'a rien à comparer, et c'est
     * une phrase différente de « le calcul a échoué ». Sans elle, l'écran renvoie la même erreur
     * pour un dépôt neuf et pour un serveur en panne.
     */
    runLatestDiff(): void {
        if (!this.diffTarget) return;

        const [kind, id] = this.diffTarget.split(':');
        this.diffLoading.set(true);
        this.diffError.set(null);
        this.diffReport.set(null);

        this.api.getLatestSbomDiff(
                kind === 'repo' ? Number(id) : undefined,
                kind === 'container' ? Number(id) : undefined)
            .subscribe({
                next: (report) => {
                    this.diffReport.set(report);
                    this.diffLoading.set(false);
                },
                error: (response: { status?: number }) => {
                    this.diffLoading.set(false);
                    this.diffError.set(this.i18n.t(
                        response?.status === 404 ? 'inventory.diff_needs_two_scans' : 'inventory.diff_failed'));
                }
            });
    }

    runDiff(): void {
        if (!this.fromScanId || !this.toScanId) {
            this.diffError.set(this.i18n.t('inventory.diff_needs_two_ids'));
            return;
        }
        this.diffLoading.set(true);
        this.diffError.set(null);
        this.api.getSbomDiff(this.fromScanId, this.toScanId).subscribe({
            next: (report) => {
                this.diffReport.set(report);
                this.diffLoading.set(false);
            },
            error: () => {
                this.diffError.set(this.i18n.t('inventory.diff_failed'));
                this.diffLoading.set(false);
            }
        });
    }
}
