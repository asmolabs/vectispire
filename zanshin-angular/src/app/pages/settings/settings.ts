import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { ApiService } from '../../core/api.service';
import type { SettingDefinition } from '../../core/api.models';

const SEVERITIES = [
    { label: 'Critique', value: 'critical' },
    { label: 'Élevée', value: 'high' },
    { label: 'Moyenne', value: 'medium' },
    { label: 'Faible', value: 'low' }
];

@Component({
    selector: 'app-settings',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, ToggleSwitchModule],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">Paramètres</h1>
                <p class="text-muted-color mt-1 mb-0">
                    Ce que Zanshin regarde, ce qu'il conserve, et ce qu'il annonce.
                </p>
            </div>
            <p-button label="Enregistrer" icon="pi pi-check" [loading]="saving()" [disabled]="!dirty()" (onClick)="save()" />
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }
        @if (saved()) {
            <p-message severity="success" [closable]="true" styleClass="mb-4 w-full">Réglages enregistrés.</p-message>
        }

        <!--
            Rendu depuis le catalogue du serveur, sections comprises : ajouter un réglage
            côté serveur le fait apparaître ici sans toucher à ce fichier, et l'écran ne
            peut pas proposer une clé qu'aucun service ne lit.
        -->
        @for (section of sections(); track section.name) {
            <p-card styleClass="mb-4">
                <ng-template #title>{{ section.name }}</ng-template>

                <div class="flex flex-col gap-5">
                    @for (setting of section.settings; track setting.key) {
                        <div class="flex flex-col gap-2">
                            <div class="flex items-start justify-between gap-6">
                                <label [for]="setting.key" class="font-medium">{{ setting.label }}</label>

                                @switch (setting.type) {
                                    @case ('boolean') {
                                        <p-toggleswitch [inputId]="setting.key" [ngModel]="values()[setting.key] === 'true'"
                                                        (ngModelChange)="set(setting.key, $event ? 'true' : 'false')" />
                                    }
                                    @case ('integer') {
                                        <p-inputnumber [inputId]="setting.key" [min]="0" [ngModel]="asNumber(values()[setting.key])"
                                                       (ngModelChange)="set(setting.key, numberToText($event))" styleClass="w-32" />
                                    }
                                    @case ('severity') {
                                        <p-select [inputId]="setting.key" [options]="severities" optionLabel="label" optionValue="value"
                                                  [ngModel]="values()[setting.key]" (ngModelChange)="set(setting.key, $event)"
                                                  styleClass="w-48" />
                                    }
                                    @default {
                                        <input pInputText [id]="setting.key" class="w-96" [ngModel]="values()[setting.key]"
                                               (ngModelChange)="set(setting.key, $event)" />
                                    }
                                }
                            </div>

                            <!-- L'explication dit surtout ce que le réglage *ne* fait pas :
                                 c'est la partie qu'un opérateur ne peut pas deviner. -->
                            <small class="text-muted-color max-w-3xl">{{ setting.help }}</small>

                            @if (!setting.configured) {
                                <small class="text-muted-color italic">Valeur par défaut — jamais réglée.</small>
                            }
                        </div>
                    }
                </div>
            </p-card>
        }

        <!--
            Le jeton a sa propre carte, hors du catalogue : il est chiffré au repos et ne
            peut pas être relu. L'écran ne peut donc dire que « configuré » ou « absent »,
            et le mêler aux autres champs laisserait croire qu'un champ vide veut dire
            « pas de jeton » alors qu'il veut dire « on ne peut pas vous le montrer ».
        -->
        @if (sections().length > 0) {
            <p-card styleClass="mb-4">
                <ng-template #title>Jeton du gestionnaire de tickets</ng-template>
                <div class="flex flex-col gap-2">
                    <div class="flex items-start justify-between gap-6">
                        <label for="ticket-token" class="font-medium">
                            Jeton
                            @if (tokenConfigured()) {
                                <span class="text-green-600 text-sm font-normal">— enregistré</span>
                            } @else {
                                <span class="text-muted-color text-sm font-normal">— aucun</span>
                            }
                        </label>
                        <div class="flex gap-2">
                            <input pInputText id="ticket-token" type="password" class="w-96" [(ngModel)]="tokenInput"
                                   placeholder="Laisser vide pour ne pas changer" autocomplete="off" />
                            <p-button label="Enregistrer" [loading]="savingToken()" (onClick)="saveToken()" />
                        </div>
                    </div>
                    <small class="text-muted-color max-w-3xl">
                        Chiffré au repos, comme une clé SSH : il donne un accès en écriture au gestionnaire, ce qui est une
                        autre classe de secret qu'une URL. Il ne peut pas être réaffiché — enregistrer une valeur vide
                        l'efface.
                    </small>
                </div>
            </p-card>
        }

        @if (sections().length === 0 && !error()) {
            <p class="text-muted-color">Chargement…</p>
        }
    `
})
export class Settings {
    private readonly api = inject(ApiService);
    readonly severities = SEVERITIES;

    readonly catalog = signal<SettingDefinition[]>([]);
    readonly values = signal<Record<string, string>>({});
    readonly error = signal<string | null>(null);
    readonly saving = signal(false);
    readonly saved = signal(false);

    readonly tokenConfigured = signal(false);
    readonly savingToken = signal(false);
    tokenInput = '';

    /** Ce qui a changé depuis le chargement. Sert au bouton, et à n'envoyer que le delta. */
    private original: Record<string, string> = {};

    readonly dirty = computed(() => Object.entries(this.values()).some(([key, value]) => this.original[key] !== value));

    readonly sections = computed(() => {
        const groups = new Map<string, SettingDefinition[]>();
        for (const setting of this.catalog()) {
            const existing = groups.get(setting.section) ?? [];
            existing.push(setting);
            groups.set(setting.section, existing);
        }
        return [...groups].map(([name, settings]) => ({ name, settings }));
    });

    constructor() {
        this.reload();
    }

    set(key: string, value: string): void {
        this.values.update((current) => ({ ...current, [key]: value }));
        this.saved.set(false);
    }

    asNumber(value: string): number {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : 0;
    }

    /** `p-inputnumber` rend `null` quand le champ est vidé ; le serveur refuse le vide. */
    numberToText(value: number | null): string {
        return value === null || value === undefined ? '0' : String(value);
    }

    save(): void {
        // Seulement ce qui a changé : envoyer tout le catalogue écrirait des lignes pour
        // des réglages jamais touchés, et l'écran ne pourrait plus dire lesquels sont
        // restés au défaut.
        const changed = Object.fromEntries(Object.entries(this.values()).filter(([key, value]) => this.original[key] !== value));
        if (Object.keys(changed).length === 0) return;

        this.saving.set(true);
        this.error.set(null);
        this.api.updateSettings(changed).subscribe({
            next: () => {
                this.saving.set(false);
                this.saved.set(true);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                // Le message du serveur porte le libellé du réglage fautif et la valeur
                // attendue ; le remplacer par un texte générique le perdrait.
                this.error.set(response?.error?.message ?? "L'enregistrement a échoué.");
            }
        });
    }

    saveToken(): void {
        this.savingToken.set(true);
        this.error.set(null);
        this.api.setTicketToken(this.tokenInput).subscribe({
            next: ({ configured }) => {
                this.savingToken.set(false);
                this.tokenConfigured.set(configured);
                // Effacé du modèle en même temps que du champ : le garder laisserait la
                // valeur accessible dans l'onglet ouvert, comme pour une clé d'API.
                this.tokenInput = '';
                this.saved.set(true);
            },
            error: (response) => {
                this.savingToken.set(false);
                this.error.set(response?.error?.message ?? "L'enregistrement du jeton a échoué.");
            }
        });
    }

    private reload(): void {
        this.api.ticketTokenState().subscribe({
            next: ({ configured }) => this.tokenConfigured.set(configured),
            error: () => this.tokenConfigured.set(false)
        });

        this.api.settings().subscribe({
            next: ({ settings }) => {
                this.catalog.set(settings);
                const values = Object.fromEntries(settings.map((setting) => [setting.key, setting.value]));
                this.values.set(values);
                this.original = { ...values };
            },
            error: () => this.error.set('Impossible de charger les réglages.')
        });
    }
}
