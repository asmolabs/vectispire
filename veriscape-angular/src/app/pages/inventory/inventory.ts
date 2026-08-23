import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import type { InventoryOccurrence } from '../../core/api.models';

/**
 * "Do we ship this library, and in which release of ours?"
 *
 * **Not a filter over the backlog.** An issue exists only where something is wrong, so the
 * backlog is silent on exactly the component being asked about on the day a vulnerability is
 * published and no scanner knows it yet. This searches the inventory — every component a scan
 * catalogued, flagged or not.
 *
 * The project version travels beside the component version, and the two are labelled apart:
 * confusing them is the one mistake that makes the answer useless.
 */
import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-inventory',
    standalone: true,
    imports: [CommonModule, FormsModule, CardModule, TableModule, TagModule, MessageModule, ButtonModule, InputTextModule, TranslatePipe],
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
}
