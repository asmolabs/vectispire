import { DatePipe } from '@angular/common';
import {
    ChangeDetectionStrategy,
    Component,
    computed,
    effect,
    inject,
    input,
    model,
    output,
    signal,
    untracked
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ForgesApi, type ForgeSelectionOperation } from '../../core/api/forges.api';
import type { ForgeCandidate, ForgeCandidatePage, ForgeSelectionFilters } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { keyFor } from '../../core/i18n/literal-keys';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '../../core/latest-request';
import { SKIP_REASON_KEYS, UNJUDGED_KEYS, forgeConflict } from '../../shared/forge-words';

const PAGE = 50;

/** The table's filters as the form holds them: the server's defaults hide archived repositories and forks. */
export interface SelectionForm {
    archived: 'hide' | 'show' | 'only';
    forks: 'hide' | 'show' | 'only';
    inactiveDays: number | null;
    language: string;
    visibility: '' | 'public' | 'internal' | 'private';
    namespace: string;
    path: string;
    personal: 'show' | 'hide' | 'only';
    present: 'show' | 'hide' | 'only';
}

export function defaultFilters(): SelectionForm {
    return {
        archived: 'hide',
        forks: 'hide',
        inactiveDays: null,
        language: '',
        visibility: '',
        namespace: '',
        path: '',
        personal: 'show',
        present: 'show'
    };
}

/**
 * The selection table (decision 0037 §4): a discovery's repositories, filtered and paged by the server, ticked
 * by a person.
 *
 * **What is imported is what was ticked, never what a filter matches**: the filters decide what is shown, and
 * `all`, `none`, `invert` and `proposed` apply to what they match at the moment of the click — the answer is a
 * set of ids the page keeps. A row the server will not let anyone tick (already a target, an empty repository)
 * is shown greyed with why, and an id it drops is named rather than silently lost.
 *
 * **Personal namespaces start unticked**: the first selection is the server's `proposed`, which leaves them out.
 */
@Component({
    selector: 'app-forge-selection',
    imports: [
        DatePipe,
        FormsModule,
        ButtonModule,
        CardModule,
        InputTextModule,
        MessageModule,
        TagModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './forge-selection.html'
})
export class ForgeSelectionTable {
    private readonly api = inject(ForgesApi);
    private readonly i18n = inject(I18nService);
    private readonly pageRequest = new LatestRequest();
    private readonly selectionRequest = new LatestRequest();

    readonly connectionId = input.required<string>();
    readonly discoveryId = input.required<number>();
    readonly selected = model<string[]>([]);
    readonly superseded = output<number>();
    readonly proceed = output<void>();

    readonly limit = PAGE;
    readonly page = signal<ForgeCandidatePage | null>(null);
    readonly offset = signal(0);
    readonly loading = signal(false);
    readonly changing = signal(false);
    readonly error = signal<string | null>(null);
    readonly blocked = signal<string | null>(null);
    readonly dropped = signal<string[]>([]);

    /** The filters typed, and the ones applied — the operations use what the table shows, not a draft. */
    form: SelectionForm = defaultFilters();
    private readonly applied = signal<SelectionForm>(defaultFilters());
    byIds = '';

    readonly selectedSet = computed(() => new Set(this.selected()));
    readonly unjudged = computed(() =>
        Object.entries(this.page()?.unjudged ?? {})
            .filter(([, count]) => count > 0)
            .map(([filter, count]) => {
                const key = keyFor(UNJUDGED_KEYS, filter);
                return key ? this.i18n.t(key, { count }) : `${filter}: ${count}`;
            })
    );

    constructor() {
        effect(() => {
            const discoveryId = this.discoveryId();
            untracked(() => {
                this.offset.set(0);
                this.load();
                // The first selection is the proposal — personal namespaces, archived repositories and forks
                // left out — unless the person already ticked something and came back.
                if (this.selected().length === 0) this.apply('proposed');
                void discoveryId;
            });
        });
    }

    private filters(form: SelectionForm = this.applied()): ForgeSelectionFilters {
        return {
            archived: form.archived,
            forks: form.forks,
            inactiveDays: form.inactiveDays ?? undefined,
            language: form.language.trim() || undefined,
            visibility: form.visibility || undefined,
            namespace: form.namespace.trim() || undefined,
            path: form.path.trim() || undefined,
            personal: form.personal,
            present: form.present
        };
    }

    load(): void {
        this.loading.set(true);
        this.error.set(null);
        this.pageRequest.run(
            this.api.importCandidates(this.connectionId(), this.discoveryId(), this.filters(), PAGE, this.offset()),
            {
                next: (page) => {
                    this.page.set(page);
                    this.blocked.set(null);
                    this.loading.set(false);
                },
                error: (response) => {
                    this.loading.set(false);
                    this.page.set(null);
                    this.refused(response);
                }
            }
        );
    }

    /** A 409 says the discovery cannot be selected from: a newer one supersedes it, or it never ended well. */
    private refused(response: unknown): void {
        const conflict = forgeConflict(response);
        if (conflict?.cause === 'forge-discovery-superseded' && conflict.latestDiscoveryId !== null) {
            this.blocked.set(this.i18n.t('forges.selection.superseded', { id: conflict.latestDiscoveryId }));
            this.superseded.emit(conflict.latestDiscoveryId);
        } else if (conflict?.cause === 'forge-discovery-not-selectable') {
            this.blocked.set(this.i18n.t('forges.selection.not_selectable'));
        } else {
            this.error.set(messageOf(response, this.i18n.t('forges.selection.error_load')));
        }
    }

    applyFilters(): void {
        this.applied.set({ ...this.form });
        this.offset.set(0);
        this.load();
    }

    resetFilters(): void {
        this.form = defaultFilters();
        this.applyFilters();
    }

    goToPage(offset: number): void {
        this.offset.set(offset);
        this.load();
    }

    apply(operation: ForgeSelectionOperation, forgeIds: readonly string[] = []): void {
        this.changing.set(true);
        this.selectionRequest.run(
            this.api.changeImportSelection(
                this.connectionId(),
                this.discoveryId(),
                operation,
                this.selected(),
                this.filters(),
                forgeIds
            ),
            {
                next: (selection) => {
                    this.changing.set(false);
                    this.selected.set(selection.selected);
                    this.dropped.set(selection.dropped ?? []);
                },
                error: (response) => {
                    this.changing.set(false);
                    this.refused(response);
                }
            }
        );
    }

    toggle(candidate: ForgeCandidate, ticked: boolean): void {
        this.apply(ticked ? 'add' : 'remove', [candidate.repository.forgeId]);
    }

    /** Ids pasted as a list — commas, spaces or lines between them. */
    private pastedIds(): string[] {
        return [
            ...new Set(
                this.byIds
                    .split(/[\s,;]+/)
                    .map((id) => id.trim())
                    .filter((id) => id.length > 0)
            )
        ];
    }

    addByIds(): void {
        const ids = this.pastedIds();
        if (ids.length > 0) this.apply('add', ids);
    }

    removeByIds(): void {
        const ids = this.pastedIds();
        if (ids.length > 0) this.apply('remove', ids);
    }

    skipKey(candidate: ForgeCandidate): string | undefined {
        return keyFor(SKIP_REASON_KEYS, candidate.notSelectable);
    }
}
