import { DatePipe } from '@angular/common';
import {
    ChangeDetectionStrategy,
    Component,
    DestroyRef,
    computed,
    effect,
    inject,
    input,
    signal,
    untracked
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ForgesApi, type ForgeChange } from '../../core/api/forges.api';
import type { ForgeConnection, ForgeDiscovery, ForgeImportResult, ForgeRepository } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '../../core/latest-request';
import { DISCOVERY_REASON_KEYS, DISCOVERY_STATE_KEYS, forgeConflict } from '../../shared/forge-words';
import { ForgeImportStep, type ImportDone } from './forge-import';
import { ForgeSelectionTable } from './forge-selection';

/** The first wait between two reads of a running discovery, and the longest the back-off reaches. */
export const POLL_FIRST_MS = 2_000;
export const POLL_MAX_MS = 30_000;

/** A page of the comparison's lists. */
const COMPARISON_LIMIT = 50;

export type DiscoveryStep = 'discovery' | 'selection' | 'import';

function moving(discovery: ForgeDiscovery | null): boolean {
    return discovery?.state === 'pending' || discovery?.state === 'running';
}

/**
 * One forge connection's discovery, selection and import (decision 0037 §3–§5), as one page in three steps:
 * discover and compare, choose, place and import.
 *
 * **Polled, with a back-off, and only while a run moves.** A discovery takes seconds on a small estate and
 * minutes on three thousand repositories; the page reads it again after two seconds, then waits twice as
 * long each time nothing moved — back to two seconds as soon as a counter does — up to thirty, and stops
 * when the run ends or the page is left. An interval that outlives its screen calls the server for nobody.
 *
 * **The selection is held here**, between the table that changes it and the import that sends it, because
 * the server keeps none: leaving the table for the preview and coming back must not lose the ticks.
 */
@Component({
    selector: 'app-forge-discovery',
    imports: [
        DatePipe,
        RouterLink,
        ButtonModule,
        CardModule,
        MessageModule,
        TagModule,
        TranslatePipe,
        ForgeSelectionTable,
        ForgeImportStep
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './forge-discovery.html'
})
export class ForgeDiscoveryPage {
    private readonly api = inject(ForgesApi);
    private readonly i18n = inject(I18nService);

    private readonly connectionRequest = new LatestRequest();
    private readonly historyRequest = new LatestRequest();
    private readonly pollRequest = new LatestRequest();
    private readonly comparisonRequest = new LatestRequest();

    readonly stateKeys = DISCOVERY_STATE_KEYS;
    readonly reasonKeys = DISCOVERY_REASON_KEYS;

    /** The route's `:connectionId`, bound by `withComponentInputBinding`. */
    readonly connectionId = input.required<string>();

    readonly connection = signal<ForgeConnection | null>(null);
    readonly notFound = signal(false);
    readonly error = signal<string | null>(null);
    readonly history = signal<ForgeDiscovery[]>([]);

    /** The discovery shown: the one just requested, the one followed, or the latest. */
    readonly discovery = signal<ForgeDiscovery | null>(null);
    readonly requesting = signal(false);
    readonly requestError = signal<string | null>(null);
    /** A discovery already running when another was asked for: the one to follow. */
    readonly inProgressId = signal<number | null>(null);
    readonly unsupported = signal(false);
    readonly pollError = signal<string | null>(null);

    readonly change = signal<ForgeChange | null>(null);
    readonly changed = signal<ForgeRepository[]>([]);
    readonly changedTotal = signal(0);
    readonly changedOffset = signal(0);
    readonly changedError = signal<string | null>(null);
    readonly comparisonLimit = COMPARISON_LIMIT;

    readonly step = signal<DiscoveryStep>('discovery');
    readonly selected = signal<string[]>([]);
    /** Set by the selection when the server names a newer discovery to select from. */
    readonly selectionDiscoveryId = signal<number | null>(null);
    readonly imported = signal<ForgeImportResult | null>(null);

    readonly running = computed(() => moving(this.discovery()));
    readonly ended = computed(() => {
        const state = this.discovery()?.state;
        return state === 'completed' || state === 'partial' || state === 'failed';
    });

    /**
     * What the selection reads: the connection's latest discovery that ended completed or partial. A run
     * still going does not supersede it, and a failed one offers nothing to choose from.
     */
    readonly selectable = computed<ForgeDiscovery | null>(() => {
        const followed = this.discovery();
        const candidates = [followed, ...this.history()].filter(
            (run): run is ForgeDiscovery => run !== null && (run.state === 'completed' || run.state === 'partial')
        );
        return candidates.reduce<ForgeDiscovery | null>(
            (latest, run) => (latest === null || run.id > latest.id ? run : latest),
            null
        );
    });
    readonly selectionDiscovery = computed(() => this.selectionDiscoveryId() ?? this.selectable()?.id ?? null);

    private pollTimer: ReturnType<typeof setTimeout> | null = null;
    private pollDelay = POLL_FIRST_MS;

    constructor() {
        inject(DestroyRef).onDestroy(() => this.stopPolling());
        effect(() => {
            const id = this.connectionId();
            untracked(() => this.load(id));
        });
    }

    private load(id: string): void {
        this.stopPolling();
        this.notFound.set(false);
        this.error.set(null);
        this.connectionRequest.run(this.api.forgeConnection(id), {
            next: (connection) => {
                this.connection.set(connection);
                if (!this.discovery() && connection.lastDiscovery) this.show(connection.lastDiscovery);
            },
            error: (response: { status?: number }) => {
                if (response?.status === 404) this.notFound.set(true);
                else this.error.set(messageOf(response, this.i18n.t('forges.discovery.error_load')));
            }
        });
        this.loadHistory();
    }

    private loadHistory(): void {
        this.historyRequest.run(this.api.forgeDiscoveries(this.connectionId()), {
            next: (runs) => this.history.set(runs),
            error: () => this.history.set([])
        });
    }

    /** Shows a discovery, and follows it while it moves. */
    show(discovery: ForgeDiscovery): void {
        this.discovery.set(discovery);
        this.change.set(null);
        this.changed.set([]);
        if (moving(discovery)) {
            this.pollDelay = POLL_FIRST_MS;
            this.schedulePoll();
        } else {
            this.stopPolling();
        }
    }

    discover(): void {
        this.requesting.set(true);
        this.requestError.set(null);
        this.inProgressId.set(null);
        this.unsupported.set(false);
        this.api.requestForgeDiscovery(this.connectionId()).subscribe({
            next: (run) => {
                this.requesting.set(false);
                this.selectionDiscoveryId.set(null);
                this.show(run);
                this.loadHistory();
            },
            error: (response) => {
                this.requesting.set(false);
                const conflict = forgeConflict(response);
                if (conflict?.cause === 'forge-discovery-in-progress' && conflict.discoveryId !== null) {
                    this.inProgressId.set(conflict.discoveryId);
                } else if (conflict?.cause === 'forge-discovery-unsupported') {
                    this.unsupported.set(true);
                } else {
                    this.requestError.set(messageOf(response, this.i18n.t('forges.discovery.error_request')));
                }
            }
        });
    }

    /** Follows the discovery a 409 named: the one already running. */
    follow(discoveryId: number): void {
        this.inProgressId.set(null);
        this.pollRequest.run(this.api.forgeDiscovery(this.connectionId(), discoveryId), {
            next: (run) => this.show(run),
            error: (response) => this.pollError.set(messageOf(response, this.i18n.t('forges.discovery.error_poll')))
        });
    }

    private schedulePoll(): void {
        this.clearTimer();
        this.pollTimer = setTimeout(() => this.poll(), this.pollDelay);
    }

    private poll(): void {
        this.pollTimer = null;
        const current = this.discovery();
        if (!current || !moving(current)) return;
        this.pollRequest.run(this.api.forgeDiscovery(this.connectionId(), current.id), {
            next: (run) => {
                this.pollError.set(null);
                const progressed =
                    run.state !== current.state ||
                    run.repositoriesSeen !== current.repositoriesSeen ||
                    run.requestsMade !== current.requestsMade;
                this.pollDelay = progressed ? POLL_FIRST_MS : Math.min(this.pollDelay * 2, POLL_MAX_MS);
                this.discovery.set(run);
                if (moving(run)) {
                    this.schedulePoll();
                } else {
                    // Ended: the history and the connection's figures moved with it.
                    this.loadHistory();
                    this.refreshConnection();
                }
            },
            error: (response) => {
                // A read that failed is not a run that failed: say so, and try again later rather than
                // stopping on what may be one lost request.
                this.pollError.set(messageOf(response, this.i18n.t('forges.discovery.error_poll')));
                this.pollDelay = Math.min(this.pollDelay * 2, POLL_MAX_MS);
                this.schedulePoll();
            }
        });
    }

    private refreshConnection(): void {
        this.connectionRequest.run(this.api.forgeConnection(this.connectionId()), {
            next: (connection) => this.connection.set(connection),
            error: () => undefined
        });
    }

    private clearTimer(): void {
        if (this.pollTimer !== null) {
            clearTimeout(this.pollTimer);
            this.pollTimer = null;
        }
    }

    private stopPolling(): void {
        this.clearTimer();
        this.pollRequest.cancel();
    }

    /** Opens the list a figure counts: the figure and the list must agree, so the list is filtered by it. */
    openChange(change: ForgeChange, offset = 0): void {
        const run = this.discovery();
        if (!run) return;
        this.change.set(change);
        this.changedOffset.set(offset);
        this.changedError.set(null);
        this.comparisonRequest.run(
            this.api.discoveredRepositories(this.connectionId(), run.id, change, COMPARISON_LIMIT, offset),
            {
                next: (page) => {
                    this.changed.set(page.items);
                    this.changedTotal.set(page.total);
                },
                error: (response) => {
                    this.changed.set([]);
                    this.changedError.set(messageOf(response, this.i18n.t('forges.discovery.error_changes')));
                }
            }
        );
    }

    closeChange(): void {
        this.comparisonRequest.cancel();
        this.change.set(null);
        this.changed.set([]);
    }

    goTo(step: DiscoveryStep): void {
        this.step.set(step);
    }

    /** The selection named a newer discovery: the snapshot is now that one's, and the ticks are void. */
    onSuperseded(latestDiscoveryId: number): void {
        this.selected.set([]);
        this.selectionDiscoveryId.set(latestDiscoveryId);
    }

    /**
     * An import ran: what it sent leaves the selection — created or skipped, it is no longer to choose — and
     * what lay past the thousand of one import stays ticked for the next.
     */
    onImported(done: ImportDone): void {
        const sent = new Set(done.batch);
        this.imported.set(done.result);
        this.selected.set(this.selected().filter((id) => !sent.has(id)));
        this.refreshConnection();
    }

    /** Back from the import, or from its result, to choose again. */
    backToSelection(): void {
        this.imported.set(null);
        this.step.set('selection');
    }
}
