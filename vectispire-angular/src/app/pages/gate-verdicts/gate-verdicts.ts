import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '@/app/core/api-error';
import { GateApi } from '@/app/core/api/gate.api';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { RegisteredVerdict, VerdictRegister } from '@/app/core/api.models';

/**
 * What the gate answered, newest first.
 *
 * **A refusal is the only proof that a control runs.** "Every target passes" does not distinguish
 * a clean estate from a gate that has never blocked anything, and that is the distinction this
 * screen exists to make. Hence the "refusals only" filter: it is the view one opens in front of
 * an auditor, not a convenience.
 *
 * **The number of issues examined is shown beside the verdict, always.** A pass after examining
 * four hundred issues and a pass after examining zero are the same row without it, and only the
 * first proves anything.
 */
@Component({
    selector: 'zs-gate-verdicts',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, MessageModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './gate-verdicts.html'
})
export class GateVerdicts {
    private readonly gateApi = inject(GateApi);
    private readonly i18n = inject(I18nService);

    readonly register = signal<VerdictRegister | null>(null);
    readonly error = signal<string | null>(null);
    readonly refusalsOnly = signal(false);
    readonly loadingMore = signal(false);

    /**
     * The rows already loaded, accumulated page by page.
     *
     * <p><b>Kept apart from the register because the counters do not accumulate.</b> The server
     * counts what it returned on *this* page; adding the pages up would give a total that grows as
     * one reads, which is the total of nothing.
     */
    readonly loaded = signal<RegisteredVerdict[]>([]);

    /**
     * There are rows left to ask for.
     *
     * <p><b>A cursor can arrive with an empty page, and that is intended.</b> Visibility is applied
     * after the read: a whole window can belong to other people only. Hiding the button because the
     * page is empty would make the restricted reader stop just before their own rows.
     */
    readonly hasMore = computed(() => this.register()?.next_cursor != null);

    /**
     * The refusal rate, or nothing.
     *
     * Zero verdicts do not make zero per cent: they make no percentage at all, and showing one on
     * a fresh instance would read as "the gate refuses nothing" where the sentence is "the gate has
     * not answered yet".
     */
    readonly refusalRate = computed(() => {
        const data = this.register();
        if (!data) {
            return null;
        }
        const rows = this.loaded();
        return rows.length === 0
            ? null
            : Math.round((rows.filter((row) => !row.passed).length / rows.length) * 1000) / 10;
    });

    readonly shown = computed<RegisteredVerdict[]>(() => {
        const rows = this.loaded();
        return this.refusalsOnly() ? rows.filter((row) => !row.passed) : rows;
    });

    constructor() {
        this.fetch(null);
    }

    more(): void {
        const cursor = this.register()?.next_cursor;
        if (cursor) {
            this.fetch(cursor);
        }
    }

    private fetch(cursor: string | null): void {
        this.loadingMore.set(true);
        this.gateApi.gateVerdicts(200, cursor).subscribe({
            next: (data) => {
                this.register.set(data);
                this.loaded.update((rows) => (cursor ? [...rows, ...data.verdicts] : data.verdicts));
                this.loadingMore.set(false);
            },
            error: (failure) => {
                this.error.set(messageOf(failure, this.i18n.t('gate_verdicts.load_failed')));
                this.loadingMore.set(false);
            }
        });
    }

    /** The severities from worst to least bad, and only those carrying a count. */
    counts(row: RegisteredVerdict): { severity: string; count: number }[] {
        return ['critical', 'high', 'medium', 'low']
            .map((severity) => ({ severity, count: row.counts_by_severity?.[severity] ?? 0 }))
            .filter((entry) => entry.count > 0);
    }
}
