import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import type { GatePolicy, GatePolicies as GatePoliciesResponse } from '../../core/api.models';

/** What a save is about: the global policy, or one target's override. */
interface Scope {
    kind: 'global' | 'repository' | 'container';
    id: number | null;
}

/** The form's own shape, so a half-typed policy is never a `GatePolicy`. */
interface Draft {
    failOnSeverity: string;
    failOnKev: boolean;
    fixableOnly: boolean;
    includeTriaged: boolean;
    includeAiReview: boolean;
    note: string;
}

/**
 * The rules a build is judged against.
 *
 * **This screen is the half that was missing.** `t_gate_policy` was read from the first release
 * — resolution target-over-global-over-built-in, versioning, the unique index that keeps one
 * active row per scope — and written by nothing at all. Every install therefore ran on
 * `GatePolicy.BUILT_IN`, the per-target scope was unreachable, and no test could see it: each
 * half was correct on its own.
 *
 * **Three things it has to say out loud**, because getting any of them wrong is silent:
 *
 * - *Inheriting is not agreeing.* A target with no policy follows the global one and keeps
 *   following it when it changes. An override that happens to hold the same values does not.
 * - *No threshold is not "unknown".* An empty severity means the rule is off — block on
 *   actively exploited findings alone. Read as the severity `unknown`, which ranks below
 *   everything, it would fail every build instead.
 * - *A policy is versioned, not edited.* Saving inserts a new version and supersedes the old
 *   one, so the verdict a pipeline received in March still names rules somebody can read.
 */
@Component({
    selector: 'zs-gate-policies',
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
        ToggleSwitchModule
    ],
    templateUrl: './gate-policies.html'
})
export class GatePolicies {
    private readonly api = inject(ApiService);

    readonly catalogue = signal<GatePoliciesResponse | null>(null);
    readonly error = signal<string | null>(null);
    readonly saving = signal(false);
    readonly dialogVisible = signal(false);

    /** The targets that have no override yet — only offered when adding one. */
    readonly candidates = signal<{ label: string; value: string }[]>([]);

    readonly globalPolicy = computed(() => this.catalogue()?.policies.find((policy) => policy.kind === 'global') ?? null);
    readonly overrides = computed(() => this.catalogue()?.policies.filter((policy) => policy.kind !== 'global') ?? []);
    readonly builtIn = computed(() => this.catalogue()?.built_in ?? null);

    readonly severities = [
        { label: 'No severity rule — actively exploited only', value: 'none' },
        { label: 'Critical and above', value: 'critical' },
        { label: 'High and above', value: 'high' },
        { label: 'Medium and above', value: 'medium' },
        { label: 'Low and above', value: 'low' }
    ];

    scope: Scope = { kind: 'global', id: null };
    scopeLabel = 'the global policy';
    draft: Draft = blank();
    /** `kind:id`, because a select carries one value and a scope is two. */
    chosenTarget: string | null = null;

    constructor() {
        this.load();
    }

    load(): void {
        this.api.gatePolicies().subscribe({
            next: (catalogue) => this.catalogue.set(catalogue),
            error: (response) => this.error.set(messageOf(response, 'Could not load the gate policies.'))
        });
    }

    editGlobal(): void {
        this.scope = { kind: 'global', id: null };
        this.scopeLabel = 'the global policy';
        this.chosenTarget = null;
        // Pre-filled with what currently applies — the stored policy, or the built-in it would
        // depart from. A form opening on blanks would make "keep what we have" a retyping
        // exercise, which is how a flag gets dropped.
        this.draft = draftOf(this.globalPolicy() ?? this.builtIn());
        this.error.set(null);
        this.dialogVisible.set(true);
    }

    editOverride(policy: GatePolicy): void {
        this.scope = { kind: policy.kind as 'repository' | 'container', id: policy.target_id };
        this.scopeLabel = `${policy.target_name ?? policy.kind} #${policy.target_id}`;
        this.chosenTarget = null;
        this.draft = draftOf(policy);
        this.error.set(null);
        this.dialogVisible.set(true);
    }

    /**
     * Adds an override, choosing the target from the ones that have none.
     *
     * The lists are fetched here rather than on load: this screen is opened to read the rules
     * far more often than to add one, and two extra requests on every visit would be paid by
     * everybody for the rarer gesture.
     */
    addOverride(): void {
        this.scope = { kind: 'repository', id: null };
        this.scopeLabel = 'a new override';
        this.chosenTarget = null;
        this.draft = draftOf(this.globalPolicy() ?? this.builtIn());
        this.error.set(null);
        this.dialogVisible.set(true);

        const taken = new Set(this.overrides().map((policy) => `${policy.kind}:${policy.target_id}`));
        this.candidates.set([]);
        this.api.repositories().subscribe((repositories) => {
            const options = repositories
                .map((repository) => ({ label: repository.displayName, value: `repository:${repository.id}` }))
                .filter((option) => !taken.has(option.value));
            this.candidates.update((current) => [...current, ...options]);
        });
        this.api.containers().subscribe((containers) => {
            const options = containers
                .map((container) => ({ label: container.reference, value: `container:${container.id}` }))
                .filter((option) => !taken.has(option.value));
            this.candidates.update((current) => [...current, ...options]);
        });
    }

    save(): void {
        if (this.scope.kind !== 'global' && this.scope.id === null) {
            if (!this.chosenTarget) {
                this.error.set('Choose the repository or container this policy is for.');
                return;
            }
            const [kind, id] = this.chosenTarget.split(':');
            this.scope = { kind: kind as 'repository' | 'container', id: Number(id) };
        }

        this.saving.set(true);
        this.api
            .saveGatePolicy(this.scope, {
                // `none` travels as the word, not as an empty string: the server refuses a blank
                // and stores a null for `none`, and the two must not be spelt the same on the way.
                fail_on_severity: this.draft.failOnSeverity,
                fail_on_kev: this.draft.failOnKev,
                fixable_only: this.draft.fixableOnly,
                include_triaged: this.draft.includeTriaged,
                include_ai_review: this.draft.includeAiReview,
                note: this.draft.note.trim() || null
            })
            .subscribe({
                next: () => {
                    this.saving.set(false);
                    this.dialogVisible.set(false);
                    // Reloaded rather than patched in place: the version number is the server's
                    // to assign, and an invented one would name a rule nobody can find in the
                    // audit log.
                    this.load();
                },
                error: (response) => {
                    this.saving.set(false);
                    this.error.set(messageOf(response, 'The policy was refused.'));
                }
            });
    }

    remove(policy: GatePolicy): void {
        this.api.removeGatePolicy(policy.kind as 'repository' | 'container', policy.target_id as number).subscribe({
            next: () => this.load(),
            error: (response) => this.error.set(messageOf(response, 'Could not remove the override.'))
        });
    }

    /** A threshold in words — and "off" said as off, never as a severity. */
    describeThreshold(value: string | null): string {
        return value === null ? 'No severity rule — actively exploited only' : `${value} and above`;
    }

    formatDate(value: string | null): string {
        if (!value) return '—';
        const at = new Date(value);
        return Number.isNaN(at.getTime()) ? value : at.toLocaleString('fr-BE', { dateStyle: 'short', timeStyle: 'short' });
    }
}

function blank(): Draft {
    return {
        failOnSeverity: 'high',
        failOnKev: true,
        fixableOnly: false,
        includeTriaged: false,
        includeAiReview: false,
        note: ''
    };
}

function draftOf(policy: GatePolicy | null): Draft {
    if (!policy) return blank();
    return {
        failOnSeverity: policy.fail_on_severity ?? 'none',
        failOnKev: policy.fail_on_kev,
        fixableOnly: policy.fixable_only,
        includeTriaged: policy.include_triaged,
        includeAiReview: policy.include_ai_review,
        note: policy.note ?? ''
    };
}
