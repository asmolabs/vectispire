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
/**
 * Les clés sont celles de la base, pas celles qu'on attendrait.
 *
 * `pending` et `scanning` — et non `queued` et `running` — parce que ce sont les valeurs
 * que la colonne contient. La première version employait les noms attendus, et l'écran
 * affichait « pending » en brut : la table fermée avait bien fait son travail en montrant
 * la valeur inconnue plutôt qu'en la masquant derrière un libellé rassurant, mais elle n'a
 * rien traduit. Vu à l'écran, pas à la relecture.
 */
const STATUS_LABELS: Record<string, { label: string; severity: 'success' | 'warn' | 'danger' | 'info' }> = {
    pending: { label: 'En file', severity: 'info' },
    scanning: { label: 'En cours', severity: 'info' },
    completed: { label: 'Terminé', severity: 'success' },
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
