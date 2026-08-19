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
    { label: 'Critical', value: 'critical' },
    { label: 'High', value: 'high' },
    { label: 'Medium', value: 'medium' },
    { label: 'Low', value: 'low' }
];

@Component({
    selector: 'app-settings',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, ToggleSwitchModule],
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div>
                <h1 class="text-2xl font-semibold m-0">Settings</h1>
                <p class="text-muted-color mt-1 mb-0">
                    What Zanshin looks at, what it keeps, and what it announces.
                </p>
            </div>
            <p-button label="Save" icon="pi pi-check" [loading]="saving()" [disabled]="!dirty()" (onClick)="save()" />
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }
        @if (saved()) {
            <p-message severity="success" [closable]="true" styleClass="mb-4 w-full">Settings saved.</p-message>
        }

        <!--
            Rendered from the server's catalogue, sections included: adding a setting on the
            server makes it appear here without touching this file, and the screen cannot offer
            a key that no service reads.
        -->
        @for (section of sections(); track section.name) {
            <p-card styleClass="mb-4">
                <ng-template #title>{{ section.name }}</ng-template>

                <div class="flex flex-col gap-5">
                    @for (setting of section.settings; track setting.key) {
                        <div class="flex flex-col gap-2">
                            <!--
                                flex-wrap and min-w-0 on the label: without both, a flex item will
                                not go below the width of its content, so a long label and a
                                fixed-width field neither shrink nor wrap — they overflow the card.
                            -->
                            <div class="flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
                                <label [for]="setting.key" class="font-medium min-w-0 flex-1">{{ setting.label }}</label>

                                <div class="shrink-0 w-full sm:w-auto">
                                    @switch (setting.type) {
                                        @case ('boolean') {
                                            <p-toggleswitch [inputId]="setting.key" [ngModel]="values()[setting.key] === 'true'"
                                                            (ngModelChange)="set(setting.key, $event ? 'true' : 'false')" />
                                        }
                                        @case ('integer') {
                                            <!-- styleClass dresses the host, inputStyleClass the field itself:
                                                 without the second, the field keeps its own width and leaves the box. -->
                                            <p-inputnumber [inputId]="setting.key" [min]="0" [ngModel]="asNumber(values()[setting.key])"
                                                           (ngModelChange)="set(setting.key, numberToText($event))"
                                                           styleClass="w-32" inputStyleClass="w-full" />
                                        }
                                        @case ('severity') {
                                            <p-select [inputId]="setting.key" [options]="severities" optionLabel="label" optionValue="value"
                                                      [ngModel]="values()[setting.key]" (ngModelChange)="set(setting.key, $event)"
                                                      [fluid]="true" styleClass="w-full sm:w-48" />
                                        }
                                        @default {
                                            <input pInputText [id]="setting.key" class="w-full sm:w-96 max-w-full"
                                                   [ngModel]="values()[setting.key]"
                                                   (ngModelChange)="set(setting.key, $event)" />
                                        }
                                    }
                                </div>
                            </div>

                            <!-- The explanation says above all what the setting does *not* do:
                                 that is the part an operator cannot guess. -->
                            <small class="text-muted-color max-w-3xl">{{ setting.help }}</small>

                            @if (!setting.configured) {
                                <small class="text-muted-color italic">Default value — never set.</small>
                            }
                        </div>
                    }
                </div>
            </p-card>
        }

        <!--
            The token has a card of its own, outside the catalogue: it is encrypted at rest and
            cannot be read back. The screen can therefore only say "configured" or "absent", and
            mixing it in with the other fields would suggest that an empty field means
            "no token" when it means "we cannot show it to you".
        -->
        @if (sections().length > 0) {
            <p-card styleClass="mb-4">
                <ng-template #title>Ticket tracker token</ng-template>
                <div class="flex flex-col gap-2">
                    <div class="flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
                        <label for="ticket-token" class="font-medium min-w-0 flex-1">
                            Token
                            @if (tokenConfigured()) {
                                <span class="text-green-600 text-sm font-normal">— saved</span>
                            } @else {
                                <span class="text-muted-color text-sm font-normal">— none</span>
                            }
                        </label>
                        <!-- Field *and* button: this is the widest row on the screen, and so the
                             first to leave the card when the window narrows. -->
                        <div class="flex flex-wrap gap-2 shrink-0 w-full sm:w-auto">
                            <input pInputText id="ticket-token" type="password" class="w-full sm:w-96 max-w-full"
                                   [(ngModel)]="tokenInput"
                                   placeholder="Leave empty to keep it unchanged" autocomplete="off" />
                            <p-button label="Save" [loading]="savingToken()" (onClick)="saveToken()" />
                        </div>
                    </div>
                    <small class="text-muted-color max-w-3xl">
                        Encrypted at rest, like an SSH key: it grants write access to the tracker, which
                        is another class of secret than a URL. It cannot be shown again — saving an empty
                        value erases it.
                    </small>
                </div>
            </p-card>
        }

        @if (sections().length === 0 && !error()) {
            <p class="text-muted-color">Loading…</p>
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

    /** What changed since loading. Drives the button, and sends only the delta. */
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

    /** `p-inputnumber` yields `null` when the field is cleared; the server refuses empty. */
    numberToText(value: number | null): string {
        return value === null || value === undefined ? '0' : String(value);
    }

    save(): void {
        // Only what changed: sending the whole catalogue would write rows for settings nobody
        // ever touched, and the screen could no longer say which ones stayed at their
        // default.
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
                // The server's message carries the offending setting's label and the expected
                // value; replacing it with generic text would lose that.
                this.error.set(response?.error?.message ?? 'Saving failed.');
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
                // Cleared from the model at the same time as from the field: keeping it would
                // leave the value reachable in the open tab, as for an API key.
                this.tokenInput = '';
                this.saved.set(true);
            },
            error: (response) => {
                this.savingToken.set(false);
                this.error.set(response?.error?.message ?? 'Saving the token failed.');
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
            error: () => this.error.set('Could not load the settings.')
        });
    }
}
