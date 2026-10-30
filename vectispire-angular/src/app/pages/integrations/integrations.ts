import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { IntegrationsApi } from '../../core/api/integrations.api';
import type { Integration } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { keyFor } from '../../core/i18n/literal-keys';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SessionStore } from '../../core/session.store';
import {
    INTEGRATION_FAMILIES,
    INTEGRATION_SUSPENDS_KEYS,
    familyLabel,
    integrationLabel
} from '../../shared/integrations';

interface FamilyGroup {
    family: string;
    title: string;
    entries: Integration[];
}

/** A refused switch, kept beside the integration it names. */
interface Refusal {
    key: string;
    message: string;
}

/**
 * *Administration → Integrations* (decision 0040): the outside systems this installation may talk to, by
 * family, and the platform governor's switch for each.
 *
 * **Read by every account, switched by one role.** The list is what the forms filter with, so it is no
 * secret; the switch is `@RequiresPlatformGovernor` on the server, and offered to that role only — any other
 * reader sees the state and the last change, and the sentence that says who switches.
 *
 * **Switching off asks first, switching on does not.** Off suspends what uses the integration — a forge's
 * connections, a tracker's tickets — and the dialog says what stops and that nothing is deleted. On only
 * resumes it; a confirmation in front of the harmless direction teaches people to dismiss the other.
 *
 * **A refusal is shown by its cause, through `messageOf`**: `integration-in-use` (the SIEM export sends
 * over it), `integration-not-switchable` (its adapters do not ask the registry yet) and whatever cause a
 * newer server adds, read by the problem's `code` and never by its status alone.
 */
@Component({
    selector: 'app-integrations',
    imports: [DatePipe, ButtonModule, CardModule, DialogModule, MessageModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './integrations.html'
})
export class Integrations {
    private readonly api = inject(IntegrationsApi);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);

    readonly governs = this.session.governsPlatform;

    readonly entries = signal<Integration[]>([]);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);
    readonly notice = signal<string | null>(null);
    readonly refusal = signal<Refusal | null>(null);
    readonly busy = signal<string | null>(null);
    readonly confirming = signal<Integration | null>(null);

    /**
     * The families in the order the decision lists them, then any family a newer server adds, as sent — a
     * family missing from the list would put its switches nowhere.
     */
    readonly groups = computed<FamilyGroup[]>(() => {
        this.i18n.translations();
        const byFamily = new Map<string, Integration[]>();
        for (const entry of this.entries()) {
            byFamily.set(entry.family, [...(byFamily.get(entry.family) ?? []), entry]);
        }
        const known: readonly string[] = INTEGRATION_FAMILIES;
        const order = [...known, ...[...byFamily.keys()].filter((family) => !known.includes(family))];
        return order
            .filter((family) => byFamily.has(family))
            .map((family) => ({ family, title: familyLabel(this.i18n, family), entries: byFamily.get(family)! }));
    });

    constructor() {
        this.reload();
    }

    reload(): void {
        this.loading.set(true);
        this.api.listIntegrations().subscribe({
            next: (entries) => {
                this.entries.set(entries);
                this.error.set(null);
                this.loading.set(false);
            },
            error: (failure) => {
                this.error.set(messageOf(failure, this.i18n.t('integrations.error_load')));
                this.loading.set(false);
            }
        });
    }

    label(key: string): string {
        this.i18n.translations();
        return integrationLabel(this.i18n, key);
    }

    /** What switching this one off stops, in its family's words; a family this client does not know says the rule alone. */
    suspends(entry: Integration): string {
        this.i18n.translations();
        const key = keyFor(INTEGRATION_SUSPENDS_KEYS, entry.family);
        return key ? this.i18n.t(key) : '';
    }

    switchOff(entry: Integration): void {
        this.refusal.set(null);
        this.notice.set(null);
        this.confirming.set(entry);
    }

    confirmSwitchOff(): void {
        const entry = this.confirming();
        this.confirming.set(null);
        if (entry) this.apply(entry, false);
    }

    switchOn(entry: Integration): void {
        this.refusal.set(null);
        this.notice.set(null);
        this.apply(entry, true);
    }

    private apply(entry: Integration, enabled: boolean): void {
        this.busy.set(entry.key);
        this.api.setIntegrationEnabled(entry.key, enabled).subscribe({
            next: (saved) => {
                this.entries.update((all) => all.map((one) => (one.key === saved.key ? saved : one)));
                this.busy.set(null);
                const name = this.label(entry.key);
                this.notice.set(
                    this.i18n.t(enabled ? 'integrations.switched_on' : 'integrations.switched_off', { name })
                );
            },
            error: (failure) => {
                this.busy.set(null);
                const name = this.label(entry.key);
                const reason = messageOf(failure, this.i18n.t('integrations.error_switch'));
                this.refusal.set({
                    key: entry.key,
                    message: this.i18n.t(enabled ? 'integrations.refused_on' : 'integrations.refused_off', {
                        name,
                        reason
                    })
                });
            }
        });
    }
}
