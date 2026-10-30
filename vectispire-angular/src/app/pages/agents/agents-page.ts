import { computed, inject, Injectable, signal } from '@angular/core';
import { messageOf } from '../../core/api-error';
import { AgentsApi } from '../../core/api/agents.api';
import type {
    AgentActivitySummary,
    AgentSummary,
    RunningScanItem,
    UnroutableLabel,
    UnservedCredentialedScans
} from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { pollWhile } from '../../core/poll-while';
import { SessionStore } from '../../core/session.store';

/**
 * The bound the control plane enforces, repeated here so the input cannot offer what the server
 * will refuse. The server stays the authority — a value typed past the spinner still gets its 400 —
 * this only saves the round trip.
 */
export const CONCURRENCY_BOUNDS = { min: 1, max: 16 } as const;

export function withinBounds(value: number | null | undefined): value is number {
    return (
        typeof value === 'number' &&
        Number.isInteger(value) &&
        value >= CONCURRENCY_BOUNDS.min &&
        value <= CONCURRENCY_BOUNDS.max
    );
}

/**
 * The fleet the agents screen shows, and what each of its dialogs is open on, shared by the
 * components the screen is made of and provided by `Agents`, so each visit starts from nothing.
 *
 * The row buttons open a dialog here — the agent whose limit is changed, deleted or whose sealing
 * key is forgotten — and each dialog makes its own write, then reloads through {@link reload}. Every
 * piece of state a component reads is a signal: the application is zoneless, and a plain field read
 * by a component of its own is not redrawn when code changes it.
 */
@Injectable()
export class AgentsPage {
    private readonly i18n = inject(I18nService);
    private readonly agentsApi = inject(AgentsApi);
    private readonly session = inject(SessionStore);
    /** Cosmetic: the route and every admin endpoint already refuse anyone else. */
    readonly isAdmin = this.session.isAdmin;

    readonly agents = signal<AgentSummary[]>([]);
    readonly activity = signal<AgentActivitySummary | null>(null);
    readonly unroutable = signal<UnroutableLabel[]>([]);
    readonly credentialedBacklog = signal<UnservedCredentialedScans | null>(null);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly busy = signal<string | null>(null);
    readonly error = signal<string | null>(null);
    readonly notice = signal<string | null>(null);
    /**
     * Why the running and waiting scans are not shown. Swallowed, a failed read left the figures out
     * and read as an idle fleet; set on each failure and cleared by the next answer, so a poll that
     * recovers says so too.
     */
    readonly activityError = signal<string | null>(null);

    /** The scan each agent is running, by agent: looked up once per answer, not once per row and pass. */
    readonly runningByAgent = computed(() => {
        const byAgent = new Map<string, RunningScanItem>();
        for (const run of this.activity()?.runningScans ?? []) {
            if (run.agentId !== null && !byAgent.has(run.agentId)) byAgent.set(run.agentId, run);
        }
        return byAgent;
    });

    readonly formVisible = signal(false);
    readonly formName = signal('');
    readonly formDescription = signal('');
    readonly formCredentialsMode = signal('local');
    readonly formLabels = signal('');
    readonly formMaxConcurrent = signal<number | null>(1);
    readonly formError = signal<string | null>(null);

    readonly secretVisible = signal(false);
    readonly issuedSecret = signal<string | null>(null);

    /**
     * The private half of a freshly pinned signing key, shown once.
     *
     * Same dialog shape as the API key for the same reason: the control plane does not keep it,
     * so this is the operator's only chance to put it in the agent's configuration.
     */
    readonly signingKeyVisible = signal(false);
    readonly issuedSigningKey = signal<string | null>(null);

    readonly concurrencyVisible = signal(false);
    readonly concurrencyAgent = signal<AgentSummary | null>(null);
    readonly concurrencyValue = signal<number | null>(1);
    readonly concurrencyError = signal<string | null>(null);

    readonly deleteVisible = signal(false);
    readonly pendingDelete = signal<AgentSummary | null>(null);
    readonly resetSealingVisible = signal(false);
    readonly pendingResetSealing = signal<AgentSummary | null>(null);

    /**
     * **Only counts while there is something to wait for.**
     *
     * This screen queried the server every five seconds unconditionally — 720 requests an hour per
     * open tab, including on an estate where nothing is running. The first load says whether there
     * is activity; the timer starts only if there is, and stops as soon as the queue is empty.
     */
    private readonly hasActivity = computed(() => {
        const activity = this.activity();
        return (activity?.runningScans?.length ?? 0) > 0 || (activity?.pendingScans?.length ?? 0) > 0;
    });

    constructor() {
        pollWhile(this.hasActivity, () => this.refreshActivity());
    }

    refreshActivity(): void {
        this.agentsApi.getAgentActivity().subscribe(this.activityObserver);
    }

    private readonly activityObserver = {
        next: (act: AgentActivitySummary) => {
            this.activity.set(act);
            this.activityError.set(null);
        },
        error: (response: unknown) => this.activityError.set(messageOf(response, this.i18n.t('agents.activity_failed')))
    };

    reload(preserveError = false): void {
        this.loading.set(true);

        this.agentsApi.unroutableLabels().subscribe({
            next: (blocked) => this.unroutable.set(blocked),
            error: () => this.unroutable.set([])
        });

        this.agentsApi.credentialedBacklog().subscribe({
            next: (backlog) => this.credentialedBacklog.set(backlog),
            error: () => this.credentialedBacklog.set(null)
        });

        this.agentsApi.getAgentActivity().subscribe(this.activityObserver);

        this.agentsApi.agents().subscribe({
            next: (agents) => {
                this.agents.set(agents);
                if (!preserveError) this.error.set(null);
                this.loading.set(false);
            },
            error: (response: unknown) => {
                this.error.set(messageOf(response, this.i18n.t('agents.error_load')));
                this.loading.set(false);
            }
        });
    }

    toggle(agent: AgentSummary): void {
        this.busy.set(agent.id);
        this.error.set(null);
        this.agentsApi.setAgentEnabled(agent.id, !agent.enabled).subscribe({
            next: () => {
                this.busy.set(null);
                this.reload();
            },
            error: (response) => {
                this.busy.set(null);
                this.error.set(messageOf(response, this.i18n.t('agents.error_operation')));
                this.reload(true);
            }
        });
    }

    /**
     * Pins a generated key, or removes the one that is there.
     *
     * Removing is a confirmation-free single click on purpose here — it is audited, and the row
     * immediately says the agent is no longer attested, which is the feedback that matters.
     */
    toggleSigning(agent: AgentSummary): void {
        this.busy.set(agent.id);
        this.agentsApi.pinAgentSigningKey(agent.id, agent.signsResults ? '' : 'generate').subscribe({
            next: (pinned) => {
                this.busy.set(null);
                if (pinned.privateKey) {
                    this.issuedSigningKey.set(pinned.privateKey);
                    this.signingKeyVisible.set(true);
                }
                this.reload();
            },
            error: (response) => {
                this.busy.set(null);
                this.error.set(messageOf(response, this.i18n.t('agents.error_signing_key')));
            }
        });
    }

    openForm(): void {
        this.formName.set('');
        this.formDescription.set('');
        this.formCredentialsMode.set('local');
        this.formLabels.set('');
        this.formMaxConcurrent.set(1);
        this.formError.set(null);
        this.formVisible.set(true);
    }

    openConcurrency(agent: AgentSummary): void {
        this.concurrencyAgent.set(agent);
        this.concurrencyValue.set(agent.maxConcurrent);
        this.concurrencyError.set(null);
        this.concurrencyVisible.set(true);
    }

    askDelete(agent: AgentSummary): void {
        this.pendingDelete.set(agent);
        this.deleteVisible.set(true);
    }

    /**
     * Asks before forgetting an agent's sealing key, because the effect is not visible where it is
     * clicked: the agent's delegated scans stop — withheld, not failed — until it proves a new key.
     */
    askResetSealing(agent: AgentSummary): void {
        this.pendingResetSealing.set(agent);
        this.resetSealingVisible.set(true);
    }
}
