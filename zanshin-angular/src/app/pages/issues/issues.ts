import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { IconFieldModule } from '@openng/optimus-ui/iconfield';
import { InputIconModule } from '@openng/optimus-ui/inputicon';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { messageOf } from '../../core/api-error';
import { ApiService } from '@/app/core/api.service';
import { Issue, IssueFilters } from '@/app/core/api.models';

/** The VEX justifications for a `not_affected` statement, as the standard names them. */
const VEX_JUSTIFICATIONS = [
    { value: 'component_not_present', label: 'Composant absent' },
    { value: 'vulnerable_code_not_present', label: 'Vulnerable code not present' },
    { value: 'vulnerable_code_not_in_execute_path', label: 'Vulnerable code not in the execute path' },
    { value: 'vulnerable_code_cannot_be_controlled_by_adversary', label: 'Not controllable by an adversary' },
    { value: 'inline_mitigations_already_exist', label: 'Inline mitigations already exist' }
];

/**
 * The backlog, and triage.
 *
 * **Pagination is server side**, not table side. A mature backlog runs to thousands of rows:
 * loading them all to display fifty would move megabytes and freeze the browser, and this is
 * precisely the screen where that would happen first.
 *
 * The triage dialog follows the VEX rules exactly as the API applies them — a justification is
 * **required** for "not affected", without which the statement carries no information and the
 * exported VEX document would be invalid. The field therefore appears only for that status, and
 * the button stays disabled while it is empty: better to prevent the submission than to explain
 * a refusal afterwards.
 */
@Component({
    selector: 'zs-issues',
    standalone: true,
    imports: [FormsModule, RouterLink, TableModule, TagModule, ButtonModule, SelectModule, InputTextModule, IconFieldModule, InputIconModule, DialogModule, TextareaModule, MessageModule],
    templateUrl: './issues.html'
})
export class Issues {
    private readonly api = inject(ApiService);
    private readonly route = inject(ActivatedRoute);

    readonly limit = 50;
    readonly issues = signal<Issue[]>([]);
    readonly total = signal(0);
    readonly offset = signal(0);
    readonly loading = signal(false);

    state = 'open';
    severity: string | null = null;
    type: string | null = null;
    search = '';

    /**
     * The selected target, as {@code repository:12} or {@code container:3}.
     *
     * One control rather than two, because a repository and an image are alternatives here and
     * two selects would let somebody ask for both — a combination that matches nothing and
     * whose empty result looks like a broken filter.
     */
    target: string | null = null;

    /**
     * The targets this account may see.
     *
     * Read from the two list endpoints and not from the admin-only one that already returns a
     * repository/container pair: those two apply the visibility filter, so an account confined
     * to three repositories is offered three and not the whole estate. A filter that offers
     * what its results will never contain is worse than no filter.
     */
    readonly targets = signal<{ label: string; value: string }[]>([]);

    readonly states = [
        { label: 'Open', value: 'open' },
        { label: 'Resolved', value: 'resolved' },
        { label: 'All', value: 'all' }
    ];
    readonly severities = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'].map((value) => ({ label: value, value }));
    readonly types = [
        { label: 'Vulnerability', value: 'vulnerability' },
        { label: 'Exposed secret', value: 'secret' },
        { label: 'Infrastructure configuration', value: 'iac' },
        { label: 'License', value: 'license' },
        { label: 'End of life', value: 'eol' },
        { label: 'Vulnerable code', value: 'sast' },
        { label: 'Code quality', value: 'quality' }
    ];

    triageOpen = false;
    triageStatus = 'under_review';
    triageJustification: string | null = null;
    triageComment = '';
    triageExpiresInDays: number | null = null;
    readonly triageError = signal<string | null>(null);
    private triaged: Issue | null = null;

    readonly justifications = VEX_JUSTIFICATIONS;
    readonly triageOptions = [
        { label: 'Under review', value: 'under_review' },
        { label: 'Affected', value: 'affected' },
        { label: 'Not affected', value: 'not_affected' },
        { label: 'Fixed', value: 'fixed' }
    ];

    /** The target filters come from the URL — that is what makes the Security screen's links
     *  work, which the Reflex version produced without ever reading them. */
    private readonly targetFilters: IssueFilters = {};

    constructor() {
        const params = this.route.snapshot.queryParamMap;
        const repositoryId = params.get('repository_id');
        const containerId = params.get('container_id');
        // Reflected into the control, not only into the query: arriving from a link used to
        // filter the list while every filter on screen read "all", so the short list looked
        // like the whole backlog having lost most of its rows.
        if (repositoryId) this.target = `repository:${repositoryId}`;
        if (containerId) this.target = `container:${containerId}`;
        if (params.get('type')) this.type = params.get('type');

        // The dashboard has always linked here with these three, and this screen read none of
        // them: clicking "8 high" opened the whole backlog, and so did the KEV panel. Nothing
        // failed — the page loaded, full of issues, simply not the ones that were asked for.
        if (params.get('severity')) this.severity = params.get('severity');
        if (params.get('state')) this.state = params.get('state')!;
        if (params.get('is_kev') === 'true') this.targetFilters.is_kev = true;

        this.loadTargets();
        this.reload(0);
    }

    /**
     * Both lists, and a failure on either leaves the filter empty rather than the screen.
     *
     * The backlog is what somebody came for; not being able to narrow it is a degradation, not
     * a reason to show an error over the list they can still read.
     */
    private loadTargets(): void {
        const options: { label: string; value: string }[] = [];
        this.api.repositories().subscribe({
            next: (repositories) => {
                options.push(...repositories.map((row) => ({ label: row.displayName, value: `repository:${row.id}` })));
                this.targets.set([...options]);
            },
            error: () => undefined
        });
        this.api.containers().subscribe({
            next: (containers) => {
                options.push(...containers.map((row) => ({ label: row.reference, value: `container:${row.id}` })));
                this.targets.set([...options]);
            },
            error: () => undefined
        });
    }

    reload(offset: number): void {
        this.loading.set(true);
        this.offset.set(Math.max(0, offset));
        const [kind, id] = this.target?.split(':') ?? [];
        this.api
            .issues({
                ...this.targetFilters,
                repository_id: kind === 'repository' ? Number(id) : undefined,
                container_id: kind === 'container' ? Number(id) : undefined,
                state: this.state,
                severity: this.severity ?? undefined,
                type: this.type ?? undefined,
                search: this.search || undefined,
                limit: this.limit,
                offset: this.offset()
            })
            .subscribe({
                next: (page) => {
                    this.issues.set(page.items);
                    this.total.set(page.total);
                    this.loading.set(false);
                },
                error: () => this.loading.set(false)
            });
    }

    pageLabel(): string {
        if (this.total() === 0) return 'No result';
        return `${this.offset() + 1}–${Math.min(this.offset() + this.limit, this.total())} of ${this.total()}`;
    }

    /**
     * The type in words. Open table: an unknown type shows raw rather than being hidden, because
     * a type Zanshin does not know is a type somebody added and nobody wired to this screen.
     */
    typeLabel(type: string): string {
        return this.types.find((option) => option.value === type)?.label ?? type;
    }

    severityColour(severity: string | null): 'danger' | 'warn' | 'info' | 'secondary' {
        if (severity === 'critical' || severity === 'high') return 'danger';
        if (severity === 'medium') return 'warn';
        if (severity === 'low') return 'info';
        return 'secondary';
    }

    triageColour(status: string): 'success' | 'danger' | 'warn' | 'secondary' {
        if (status === 'not_affected' || status === 'fixed') return 'success';
        if (status === 'affected') return 'danger';
        return 'secondary';
    }

    triageLabel(status: string): string {
        return this.triageOptions.find((option) => option.value === status)?.label ?? status;
    }

    openTriage(issue: Issue): void {
        this.triaged = issue;
        this.triageStatus = issue.triageStatus;
        this.triageJustification = issue.triageJustification;
        this.triageComment = issue.triageComment ?? '';
        this.triageExpiresInDays = null;
        this.triageError.set(null);
        this.triageOpen = true;
    }

    /** Preventing the submission beats explaining a refusal afterwards. */
    canSubmitTriage(): boolean {
        return this.triageStatus !== 'not_affected' || !!this.triageJustification;
    }

    submitTriage(): void {
        if (!this.triaged || !this.canSubmitTriage()) return;
        this.api
            .triage(this.triaged.id, {
                status: this.triageStatus,
                justification: this.triageJustification,
                comment: this.triageComment || null,
                expires_in_days: this.triageExpiresInDays || null
            })
            .subscribe({
                next: () => {
                    this.triageOpen = false;
                    this.reload(this.offset());
                },
                error: (response) => this.triageError.set(messageOf(response, 'The triage was refused.'))
            });
    }
}
