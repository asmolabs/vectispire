import { CommonModule } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { AccountsApi } from '../../core/api/accounts.api';
import { SarifApi } from '../../core/api/sarif.api';
import { SolutionsApi } from '../../core/api/solutions.api';
import { TargetsApi } from '../../core/api/targets.api';
import type {
    ApiKeySummary,
    MonitoredRepository,
    SarifSource,
    SarifSourceDeclaration,
    SolutionTree
} from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SessionStore } from '../../core/session.store';

/** A source's one scope: a project or a repository, never both, never the estate. */
type ScopeKind = 'project' | 'repository';

interface Draft {
    slug: string;
    name: string;
    apiKeyId: string | null;
    scopeKind: ScopeKind;
    scopeId: number | null;
    tools: string;
}

/**
 * The declared internal sources of SARIF (decision 0017 §7).
 *
 * **External means outside the organisation.** A report from a tool that already had the code — an
 * on-premise SonarQube, the team's own CI — is imported; one from a hosted service to which the code
 * would have been handed is not. Nothing in a file proves where it was made, so the rule is enforced
 * by declaring each producer: one key, exactly one scope, the tools it may deliver. Declaring is the
 * platform governor's act, audited; reading the declarations is governance.
 *
 * The key is chosen from the keys holding `sarif_import`, which only an administrator's session can
 * list; the governor is one. A governance reader who is not sees the key's id.
 */
@Component({
    selector: 'app-sarif-sources',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        CardModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        SelectModule,
        TableModule,
        TagModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './sarif-sources.html'
})
export class SarifSources {
    private readonly api = inject(SarifApi);
    private readonly accountsApi = inject(AccountsApi);
    private readonly solutionsApi = inject(SolutionsApi);
    private readonly targetsApi = inject(TargetsApi);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);

    readonly governs = this.session.governsPlatform;

    readonly sources = signal<SarifSource[]>([]);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);
    readonly notice = signal<string | null>(null);
    readonly busy = signal<number | null>(null);

    private readonly tree = signal<SolutionTree | null>(null);
    private readonly repositories = signal<MonitoredRepository[]>([]);
    private readonly keys = signal<ApiKeySummary[]>([]);

    readonly projectOptions = computed(() =>
        (this.tree()?.solutions ?? []).flatMap((solution) =>
            (solution.projects ?? []).map((project) => ({
                label: `${solution.name} / ${project.name}`,
                value: project.id
            }))
        )
    );
    readonly repositoryOptions = computed(() =>
        this.repositories().map((repository) => ({ label: repository.displayName, value: repository.id }))
    );
    /**
     * Only keys that hold the scope and have not expired: the server refuses any other, and offering
     * one would be offering a declaration that cannot work.
     */
    readonly keyOptions = computed(() =>
        this.keys()
            .filter((key) => key.scopes.includes('sarif_import') && !key.isExpired)
            .map((key) => ({ label: `${key.name} (${key.prefix ?? key.id.slice(0, 8)}…)`, value: key.id }))
    );
    readonly scopeKinds = computed(() => {
        this.i18n.translations();
        return [
            { label: this.i18n.t('sarif_sources.scope_project'), value: 'project' },
            { label: this.i18n.t('sarif_sources.scope_repository'), value: 'repository' }
        ];
    });

    readonly formVisible = signal(false);
    readonly saving = signal(false);
    readonly formError = signal<string | null>(null);
    draft: Draft = blank();

    readonly pendingRemove = signal<SarifSource | null>(null);
    readonly removeVisible = signal(false);

    constructor() {
        this.reload();
        // For the names only; a failure leaves ids, which are still the right answer.
        this.solutionsApi.solutionTree().subscribe({ next: (tree) => this.tree.set(tree), error: () => undefined });
        this.targetsApi.repositories().subscribe({
            next: (repositories) => this.repositories.set(repositories),
            error: () => undefined
        });
        if (this.session.isAdmin()) {
            this.accountsApi.apiKeys().subscribe({ next: (keys) => this.keys.set(keys), error: () => undefined });
        }
    }

    reload(): void {
        this.loading.set(true);
        this.api.sarifSources().subscribe({
            next: (sources) => {
                this.sources.set(sources);
                this.loading.set(false);
            },
            error: (failure) => {
                this.error.set(messageOf(failure, this.i18n.t('sarif_sources.error_load')));
                this.loading.set(false);
            }
        });
    }

    scopeLabel(source: SarifSource): string {
        this.i18n.translations();
        if (source.projectId !== null) {
            const project = this.projectOptions().find((option) => option.value === source.projectId);
            return this.i18n.t('sarif_sources.scope_project_named', { name: project?.label ?? `#${source.projectId}` });
        }
        const repository = this.repositoryOptions().find((option) => option.value === source.repositoryId);
        return this.i18n.t('sarif_sources.scope_repository_named', {
            name: repository?.label ?? `#${source.repositoryId}`
        });
    }

    keyLabel(source: SarifSource): string {
        const key = this.keys().find((candidate) => candidate.id === source.apiKeyId);
        return key ? key.name : `${source.apiKeyId.slice(0, 8)}…`;
    }

    openDeclare(): void {
        this.draft = blank();
        this.formError.set(null);
        this.formVisible.set(true);
    }

    /** The scope's target is cleared when its kind changes: a project id is not a repository id. */
    setScopeKind(kind: ScopeKind): void {
        this.draft.scopeKind = kind;
        this.draft.scopeId = null;
    }

    canDeclare(): boolean {
        return (
            !!this.draft.slug.trim() &&
            !!this.draft.name.trim() &&
            this.draft.apiKeyId !== null &&
            this.draft.scopeId !== null &&
            toolsOf(this.draft.tools).length > 0
        );
    }

    declare(): void {
        if (!this.canDeclare()) return;
        this.saving.set(true);
        this.formError.set(null);
        this.api.declareSarifSource(declarationOf(this.draft)).subscribe({
            next: (source) => {
                this.saving.set(false);
                this.formVisible.set(false);
                this.notice.set(this.i18n.t('sarif_sources.declared_notice', { slug: source.slug }));
                this.reload();
            },
            error: (failure) => {
                this.saving.set(false);
                this.formError.set(messageOf(failure, this.i18n.t('sarif_sources.error_declare')));
            }
        });
    }

    setEnabled(source: SarifSource, enabled: boolean): void {
        this.busy.set(source.id);
        this.error.set(null);
        this.api.setSarifSourceEnabled(source.id, enabled).subscribe({
            next: (updated) => {
                this.busy.set(null);
                this.sources.update((sources) => sources.map((one) => (one.id === updated.id ? updated : one)));
            },
            error: (failure) => {
                this.busy.set(null);
                this.error.set(messageOf(failure, this.i18n.t('sarif_sources.error_change')));
            }
        });
    }

    askRemove(source: SarifSource): void {
        this.pendingRemove.set(source);
        this.removeVisible.set(true);
    }

    confirmRemove(): void {
        const source = this.pendingRemove();
        if (!source) return;
        this.busy.set(source.id);
        this.api.removeSarifSource(source.id).subscribe({
            next: () => {
                this.busy.set(null);
                this.removeVisible.set(false);
                this.notice.set(this.i18n.t('sarif_sources.removed_notice', { slug: source.slug }));
                this.reload();
            },
            error: (failure) => {
                this.busy.set(null);
                this.removeVisible.set(false);
                this.error.set(messageOf(failure, this.i18n.t('sarif_sources.error_change')));
            }
        });
    }
}

function blank(): Draft {
    return { slug: '', name: '', apiKeyId: null, scopeKind: 'project', scopeId: null, tools: '' };
}

/** One tool per line or per comma, as each run's `tool.driver.name` will be compared, without case. */
export function toolsOf(text: string): string[] {
    return [
        ...new Set(
            text
                .split(/[\n,]+/)
                .map((tool) => tool.trim())
                .filter((tool) => tool.length > 0)
        )
    ];
}

/** Exactly one of the two scope fields: the other is left out rather than sent empty. */
export function declarationOf(draft: Draft): SarifSourceDeclaration {
    const scope = draft.scopeKind === 'project' ? { project_id: draft.scopeId! } : { repository_id: draft.scopeId! };
    return {
        slug: draft.slug.trim(),
        name: draft.name.trim(),
        api_key_id: draft.apiKeyId!,
        ...scope,
        tools: toolsOf(draft.tools)
    };
}
