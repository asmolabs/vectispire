import { DatePipe } from '@angular/common';
import {
    ChangeDetectionStrategy,
    Component,
    computed,
    effect,
    inject,
    input,
    output,
    signal,
    untracked
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ForgesApi } from '../../core/api/forges.api';
import { SolutionsApi } from '../../core/api/solutions.api';
import { TargetsApi } from '../../core/api/targets.api';
import type {
    ForgeCredentialView,
    ForgeHostCredential,
    ForgeImportPreview,
    ForgeImportRequest,
    ForgeImportResult,
    ForgePlannedTarget,
    ForgeSkippedImport,
    GitTokenSummary,
    Schema,
    SshKeySummary
} from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { keyFor } from '../../core/i18n/literal-keys';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '../../core/latest-request';
import { CLONE_CREDENTIAL_KEYS, SKIP_REASON_KEYS, forgeConflict } from '../../shared/forge-words';

/** Decision 0037, answer 8: an import holds at most a thousand repositories, in one transaction. */
export const MAX_IMPORT = 1_000;
/** Answer 4: first scans sixty seconds apart by default, between ten seconds and ten minutes. */
export const DEFAULT_SPACING = 60;
export const MIN_SPACING = 10;
export const MAX_SPACING = 600;

type MappingRule = Schema<'ForgeMappingRule'>;

/** One editable placement: a namespace — everything below it — or one repository. */
export interface Placement {
    key: string;
    namespacePath: string | null;
    forgeId: string | null;
    label: string;
    solution: string;
    project: string;
    noProject: boolean;
    repositories: number;
}

export interface ImportDone {
    result: ForgeImportResult;
    batch: string[];
}

/** The namespace a full path sits in: everything before its last segment. */
function namespaceOf(fullPath: string): string {
    const at = fullPath.lastIndexOf('/');
    return at < 0 ? '' : fullPath.slice(0, at);
}

const same = (a: string | null | undefined, b: string | null | undefined) =>
    (a ?? '').toLowerCase() === (b ?? '').toLowerCase();

/**
 * Where the selected repositories are filed, how they are cloned, and the import itself (decision 0037 §4–§5).
 *
 * **What was previewed is what is imported.** Every change — a placement, a credential, the first scans —
 * makes the preview stale, and the import waits for a fresh one: the body sent is the one the preview was
 * computed for, never a draft the person has not seen the consequences of.
 *
 * **The proposal is shown, never applied unseen.** A namespace's solution and project come from the preview;
 * editing one writes a mapping rule for that namespace (and everything below it) or for one repository, field
 * by field, so that renaming a solution keeps every subgroup's project.
 */
@Component({
    selector: 'app-forge-import',
    imports: [
        DatePipe,
        FormsModule,
        RouterLink,
        ButtonModule,
        CardModule,
        InputTextModule,
        MessageModule,
        TagModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './forge-import.html'
})
export class ForgeImportStep {
    private readonly api = inject(ForgesApi);
    private readonly targetsApi = inject(TargetsApi);
    private readonly solutionsApi = inject(SolutionsApi);
    private readonly i18n = inject(I18nService);
    private readonly previewRequest = new LatestRequest();

    readonly connectionId = input.required<string>();
    readonly discoveryId = input.required<number>();
    readonly forgeIds = input.required<string[]>();
    readonly result = input<ForgeImportResult | null>(null);
    readonly imported = output<ImportDone>();
    readonly back = output<void>();

    readonly maxImport = MAX_IMPORT;
    readonly minSpacing = MIN_SPACING;
    readonly maxSpacing = MAX_SPACING;

    readonly batch = computed(() => this.forgeIds().slice(0, MAX_IMPORT));
    readonly preview = signal<ForgeImportPreview | null>(null);
    readonly previewing = signal(false);
    readonly previewError = signal<string | null>(null);
    readonly stale = signal(false);
    readonly importing = signal(false);
    readonly importError = signal<string | null>(null);

    readonly sshKeys = signal<SshKeySummary[]>([]);
    readonly gitTokens = signal<GitTokenSummary[]>([]);
    readonly solutionNames = signal<string[]>([]);
    readonly projectNames = signal<string[]>([]);

    /** The rules written so far, by namespace (`ns:…`) or repository (`id:…`). */
    private readonly rules = signal<ReadonlyMap<string, MappingRule>>(new Map());
    /** The credential chosen per host: `none`, `ssh:<id>` or `https:<id>`; a host absent takes the proposal. */
    readonly choices = signal<ReadonlyMap<string, string>>(new Map());
    readonly perRepository = signal(false);

    firstScan = false;
    spacingSeconds = DEFAULT_SPACING;
    requiredAgentLabel = '';

    readonly spacingValid = signal(true);

    /** The namespaces of the plan, each with the placement the preview shows for its first repository. */
    readonly namespaces = computed<Placement[]>(() => {
        const out = new Map<string, Placement>();
        for (const target of this.placed()) {
            const ns = namespaceOf(target.fullPath);
            const existing = out.get(ns);
            if (existing) {
                existing.repositories += 1;
                continue;
            }
            out.set(ns, {
                key: `ns:${ns}`,
                namespacePath: ns,
                forgeId: null,
                label: ns,
                solution: target.solution ?? '',
                project: target.project ?? '',
                noProject: !target.project,
                repositories: 1
            });
        }
        return [...out.values()].sort((a, b) => a.label.localeCompare(b.label));
    });

    readonly repositories = computed<Placement[]>(() =>
        this.placed().map((target) => ({
            key: `id:${target.forgeId}`,
            namespacePath: null,
            forgeId: target.forgeId,
            label: target.fullPath,
            solution: target.solution ?? '',
            project: target.project ?? '',
            noProject: !target.project,
            repositories: 1
        }))
    );

    /** Targets and refusals both carry a placement worth editing: a refusal is often a placement to fix. */
    private readonly placed = computed(() => {
        const preview = this.preview();
        if (!preview) return [];
        const refused = preview.refused.map((refusal) => ({
            forgeId: refusal.forgeId,
            fullPath: refusal.fullPath,
            solution: null as string | null,
            project: null as string | null
        }));
        return [...preview.targets, ...refused];
    });

    readonly canImport = computed(
        () =>
            this.preview() !== null &&
            !this.stale() &&
            !this.previewing() &&
            !this.importing() &&
            this.spacingValid() &&
            (this.preview()?.refused.length ?? 0) === 0 &&
            (this.preview()?.targets.length ?? 0) > 0
    );

    constructor() {
        this.targetsApi.sshKeys().subscribe({ next: (keys) => this.sshKeys.set(keys), error: () => undefined });
        this.targetsApi.gitTokens().subscribe({ next: (tokens) => this.gitTokens.set(tokens), error: () => undefined });
        // Offered as suggestions, so that "choose an existing one" is typing its name; the server reuses a
        // solution or project of the same name, case aside, and the preview says which it found.
        this.solutionsApi.solutionTree().subscribe({
            next: (tree) => {
                this.solutionNames.set(tree.solutions.map((solution) => solution.name));
                this.projectNames.set([
                    ...new Set(tree.solutions.flatMap((solution) => solution.projects.map((project) => project.name)))
                ]);
            },
            error: () => undefined
        });
        effect(() => {
            const ids = this.batch();
            const done = this.result();
            untracked(() => {
                if (done === null && ids.length > 0) this.runPreview();
            });
        });
    }

    request(): ForgeImportRequest {
        const credentials: Schema<'ForgeCredentialChoice'>[] = [...this.choices()].map(([host, choice]) => {
            if (choice.startsWith('ssh:')) return { host, sshKeyId: choice.slice(4) };
            if (choice.startsWith('https:')) return { host, httpsTokenId: choice.slice(6) };
            return { host };
        });
        return {
            discoveryId: this.discoveryId(),
            forgeIds: this.batch(),
            mapping: [...this.rules().values()],
            credentials,
            firstScan: this.firstScan,
            spacingSeconds: this.spacingSeconds,
            requiredAgentLabel: this.requiredAgentLabel.trim() || undefined
        };
    }

    runPreview(): void {
        if (!this.checkSpacing()) return;
        this.previewing.set(true);
        this.previewError.set(null);
        this.importError.set(null);
        this.previewRequest.run(this.api.previewForgeImport(this.connectionId(), this.request()), {
            next: (preview) => {
                this.preview.set(preview);
                this.stale.set(false);
                this.previewing.set(false);
            },
            error: (response) => {
                this.previewing.set(false);
                this.previewError.set(this.refusal(response, 'forges.import.error_preview'));
            }
        });
    }

    private refusal(response: unknown, fallback: string): string {
        const conflict = forgeConflict(response);
        if (conflict?.cause === 'forge-discovery-superseded') {
            return this.i18n.t('forges.selection.superseded', { id: conflict.latestDiscoveryId ?? '' });
        }
        if (conflict?.cause === 'forge-discovery-not-selectable') return this.i18n.t('forges.selection.not_selectable');
        return messageOf(response, this.i18n.t(fallback));
    }

    checkSpacing(): boolean {
        const value = Number(this.spacingSeconds);
        const valid = !this.firstScan || (Number.isInteger(value) && value >= MIN_SPACING && value <= MAX_SPACING);
        this.spacingValid.set(valid);
        return valid;
    }

    /** A placement field changed: written as a rule for that namespace or repository, field by field. */
    place(placement: Placement, field: 'solution' | 'project' | 'noProject', value: string | boolean): void {
        const rules = new Map(this.rules());
        const rule: MappingRule = {
            ...(rules.get(placement.key) ??
                (placement.forgeId ? { forgeId: placement.forgeId } : { namespacePath: placement.namespacePath ?? '' }))
        };
        if (field === 'noProject') {
            if (value === true) {
                rule.noProject = true;
                delete rule.project;
            } else {
                delete rule.noProject;
            }
        } else {
            const text = String(value).trim();
            if (text) rule[field] = text;
            else delete rule[field];
        }
        rules.set(placement.key, rule);
        this.rules.set(rules);
        this.stale.set(true);
    }

    /** The rules written for a placement, to show which proposals the person changed. */
    edited(placement: Placement): boolean {
        return this.rules().has(placement.key);
    }

    forget(placement: Placement): void {
        const rules = new Map(this.rules());
        rules.delete(placement.key);
        this.rules.set(rules);
        this.stale.set(true);
    }

    tokensFor(host: string): GitTokenSummary[] {
        return this.gitTokens().filter((token) => same(token.host, host));
    }

    /** The select's value for a host: what was chosen, or what the preview proposes. */
    choiceFor(host: ForgeHostCredential): string {
        const chosen = this.choices().get(host.host);
        if (chosen) return chosen;
        return this.valueOf(host.credential);
    }

    private valueOf(credential: ForgeCredentialView): string {
        if (credential.kind === 'ssh_key' && credential.id) return `ssh:${credential.id}`;
        if (credential.kind === 'https_token' && credential.id) return `https:${credential.id}`;
        return 'none';
    }

    choose(host: string, value: string): void {
        const choices = new Map(this.choices());
        choices.set(host, value);
        this.choices.set(choices);
        this.stale.set(true);
    }

    optionsChanged(): void {
        this.checkSpacing();
        this.stale.set(true);
    }

    credential(credential: ForgeCredentialView): string {
        const key = keyFor(CLONE_CREDENTIAL_KEYS, credential.kind);
        const kind = key ? this.i18n.t(key) : credential.kind;
        return credential.name ? `${kind} — ${credential.name}` : kind;
    }

    skipReason(skip: ForgeSkippedImport): string {
        const key = keyFor(SKIP_REASON_KEYS, skip.reason);
        return key ? this.i18n.t(key) : skip.reason;
    }

    /**
     * Who will see a target, in the reader's language. The server says it in an English sentence
     * (`visibleTo`); the facts behind it are all in the preview — the installation's visibility mode and the
     * grants on each reused project — so the screen says it from them.
     */
    visibleTo(target: ForgePlannedTarget): string {
        const preview = this.preview();
        if (preview?.visibilityMode === 'everyone') return this.i18n.t('forges.import.visible_everyone');
        if (!target.project) return this.i18n.t('forges.import.visible_unfiled');
        const project = `${target.solution ?? ''} / ${target.project}`;
        const plan = preview?.projects.find(
            (planned) => same(planned.solution, target.solution) && same(planned.name, target.project)
        );
        if (!plan || plan.existingId === null) return this.i18n.t('forges.import.visible_new_project', { project });
        if (plan.accounts === 0 && plan.teams === 0) {
            return this.i18n.t('forges.import.visible_no_grant', { project });
        }
        return this.i18n.t('forges.import.visible_granted', { project, accounts: plan.accounts, teams: plan.teams });
    }

    doImport(): void {
        if (!this.canImport()) return;
        const request = this.request();
        this.importing.set(true);
        this.importError.set(null);
        this.api.importForgeRepositories(this.connectionId(), request).subscribe({
            next: (result) => {
                this.importing.set(false);
                this.preview.set(null);
                this.imported.emit({ result, batch: request.forgeIds ?? [] });
            },
            error: (response) => {
                this.importing.set(false);
                // Nothing was written — the import is one transaction — and the preview may no longer say
                // what would happen: read it again rather than leave a plan the server just disagreed with.
                this.importError.set(this.refusal(response, 'forges.import.error_import'));
                this.stale.set(true);
            }
        });
    }
}
