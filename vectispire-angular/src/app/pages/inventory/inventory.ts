import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { ApiService } from '../../core/api.service';
import type { InventoryOccurrence, SbomDiffReport } from '../../core/api.models';
import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-inventory',
    standalone: true,
    imports: [CommonModule, FormsModule, CardModule, DialogModule, TableModule, TagModule, MessageModule, ButtonModule, InputTextModule, TranslatePipe],
    templateUrl: './inventory.html'
})
export class Inventory {
    private readonly api = inject(ApiService);

    name = '';
    version = '';

    readonly occurrences = signal<InventoryOccurrence[]>([]);
    readonly truncated = signal(false);
    readonly loading = signal(false);
    readonly searched = signal(false);
    readonly error = signal<string | null>(null);

    readonly activeTab = signal<'search' | 'diff'>('search');

    // SBOM Diff Viewer
    readonly diffOpen = signal(false);
    fromScanId: number | null = null;
    toScanId: number | null = null;
    readonly diffReport = signal<SbomDiffReport | null>(null);
    readonly diffLoading = signal(false);
    readonly diffError = signal<string | null>(null);

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

    openDiffModal(): void {
        this.diffOpen.set(true);
        this.diffError.set(null);
    }

    runDiff(): void {
        if (!this.fromScanId || !this.toScanId) {
            this.diffError.set('Veuillez spécifier les identifiants des deux scans à comparer.');
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
                this.diffError.set('Impossible de charger le différentiel SBOM pour ces scans.');
                this.diffLoading.set(false);
            }
        });
    }
}
