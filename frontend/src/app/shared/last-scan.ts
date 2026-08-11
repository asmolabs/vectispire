import { CommonModule } from '@angular/common';
import { Component, input } from '@angular/core';
import { TagModule } from '@openng/optimus-ui/tag';
import type { LastScan } from '../core/api.models';

/**
 * L'état du dernier scan d'une cible, dépôt ou conteneur.
 *
 * Extrait parce que la distinction qu'il porte est trop facile à perdre en la recopiant :
 * **« jamais scanné » n'est pas « aucun problème »**, c'est une absence d'observation. Un
 * écran qui affiche une case vide dans ce cas ment par omission.
 */
const STATUS_LABELS: Record<string, { label: string; severity: 'success' | 'warn' | 'danger' | 'info' }> = {
    completed: { label: 'Terminé', severity: 'success' },
    running: { label: 'En cours', severity: 'info' },
    queued: { label: 'En file', severity: 'info' },
    failed: { label: 'Échoué', severity: 'danger' },
    cancelled: { label: 'Annulé', severity: 'warn' }
};

@Component({
    selector: 'app-last-scan',
    standalone: true,
    imports: [CommonModule, TagModule],
    template: `
        @if (scan(); as value) {
            <p-tag [value]="label(value.status)" [severity]="severity(value.status)" />
            <div class="text-sm text-muted-color mt-1">{{ value.createdAt | date: 'dd/MM/yyyy HH:mm' }}</div>
            @if (value.error) {
                <div class="text-sm text-red-500 mt-1">{{ value.error }}</div>
            }
        } @else {
            <span class="text-muted-color">Jamais scanné</span>
        }
    `
})
export class LastScanTag {
    readonly scan = input.required<LastScan | null>();

    /** Table fermée : un statut hors vocabulaire s'affiche brut plutôt que d'être masqué
     *  par un libellé rassurant. */
    label(status: string): string {
        return STATUS_LABELS[status]?.label ?? status;
    }

    severity(status: string): 'success' | 'warn' | 'danger' | 'info' {
        return STATUS_LABELS[status]?.severity ?? 'info';
    }
}
