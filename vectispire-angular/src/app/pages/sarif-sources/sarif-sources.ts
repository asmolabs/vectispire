import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
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
import {
    SOURCE_KINDS,
    type ApiKeySummary,
    type MonitoredRepository,
    type SarifSource,
    type SarifSourceDeclaration,
    type SolutionTree,
    type SourceKind
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
    kinds: SourceKind[];
    tools: string;
}

/** Literal keys, so the i18n check sees each one and a new kind cannot ship as a raw key (decision 0019). */
const KIND_KEYS: Record<
    SourceKind,
    'sarif_sources.kind_sarif' | 'sarif_sources.kind_coverage' | 'sarif_sources.kind_test_report'
> = {
    sarif: 'sarif_sources.kind_sarif',
    coverage: 'sarif_sources.kind_coverage',
    test_report: 'sarif_sources.kind_test_report'
};

/** The scope an integration key must hold for a source to deliver each kind — the server's rule. */
const KIND_SCOPES: Record<SourceKind, 'sarif_import' | 'report_import'> = {
    sarif: 'sarif_import',
    coverage: 'report_import',
    test_report: 'report_import'
};

/**
 * The declared internal sources (decisions 0017 §7, 0032 §7): SARIF, coverage and test reports.
 *
 * **External means outside the organisation.** A report from a tool that already had the code — an
 * on-premise SonarQube, the team's own CI — is imported; one from a hosted service to which the code
 * would have been handed is not. Nothing in a file proves where it was made, so the rule is enforced
 * by declaring each producer: one key, exactly one scope, the kinds of report it may deliver and, for
 * SARIF, the tools. Declaring is the platform governor's act, audited; reading the declarations is
 * governance. The route keeps its `/sarif-sources` name: bookmarks and the audit trail predate kinds.
 *
 * The key is chosen from the keys holding the scope every chosen kind needs — `sarif_import` for
 * SARIF, `report_import` for the others — which only an administrator's session can list; the
 * governor is one. The table names each source's key from the source itself (`apiKeyName`), so a
 * CISO or an auditor, who cannot open the keys screen, reads the same name the governor does.
 */
@Component({
    selector: 'app-sarif-sources',
    imports: [
        DatePipe,
        FormsModule,
        ButtonModule,
        CardModule,
        CheckboxModule,
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
     * Only keys that hold the scope of every chosen kind and have not expired: the server refuses any
     * other, and offering one would be offering a declaration that cannot work. A method rather than a
     * `computed`: it follows `draft.kinds`, a plain field the template's events rewrite.
     */
    keyOptions(): { label: string; value: string }[] {
        const needed = [...new Set(this.draft.kinds.map((kind) => KIND_SCOPES[kind]))];
        return this.keys()
            .filter((key) => !key.isExpired && needed.every((scope) => key.scopes.includes(scope)))
            .map((key) => ({ label: `${key.name} (${key.prefix ?? key.id.slice(0, 8)}…)`, value: key.id }));
    }

    readonly kindOptions = computed(() => {
        this.i18n.translations();
        return SOURCE_KINDS.map((kind) => ({ value: kind, label: this.i18n.t(KIND_KEYS[kind]) }));
    });
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

    /** An unknown kind — a server newer than this screen — reads as itself rather than as a raw key. */
    kindLabel(kind: string): string {
        this.i18n.translations();
        const key = (KIND_KEYS as Record<string, string | undefined>)[kind];
        return key ? this.i18n.t(key) : kind;
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

    /**
     * A kind unticked drops a chosen key that no longer fits: a key holding `sarif_import` alone,
     * chosen for SARIF, cannot deliver coverage, and the server would refuse the declaration.
     */
    setKind(kind: SourceKind, checked: boolean): void {
        const kinds = checked ? [...this.draft.kinds, kind] : this.draft.kinds.filter((one) => one !== kind);
        this.draft.kinds = SOURCE_KINDS.filter((one) => kinds.includes(one));
        if (this.draft.apiKeyId !== null && !this.keyOptions().some((option) => option.value === this.draft.apiKeyId)) {
            this.draft.apiKeyId = null;
        }
    }

    /** Tools are SARIF's: asked for when SARIF is among the kinds, and not otherwise. */
    deliversSarif(): boolean {
        return this.draft.kinds.includes('sarif');
    }

    canDeclare(): boolean {
        return (
            !!this.draft.slug.trim() &&
            !!this.draft.name.trim() &&
            this.draft.apiKeyId !== null &&
            this.draft.scopeId !== null &&
            this.draft.kinds.length > 0 &&
            (!this.deliversSarif() || toolsOf(this.draft.tools).length > 0)
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
    return { slug: '', name: '', apiKeyId: null, scopeKind: 'project', scopeId: null, kinds: ['sarif'], tools: '' };
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

/**
 * Exactly one of the two scope fields: the other is left out rather than sent empty. The kinds are
 * always sent — absent would mean SARIF alone — and tools typed before SARIF was unticked are not:
 * the server refuses tools on a source that delivers no SARIF.
 */
export function declarationOf(draft: Draft): SarifSourceDeclaration {
    const scope = draft.scopeKind === 'project' ? { project_id: draft.scopeId! } : { repository_id: draft.scopeId! };
    return {
        slug: draft.slug.trim(),
        name: draft.name.trim(),
        api_key_id: draft.apiKeyId!,
        ...scope,
        kinds: [...draft.kinds],
        tools: draft.kinds.includes('sarif') ? toolsOf(draft.tools) : []
    };
}
