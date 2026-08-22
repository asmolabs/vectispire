import { DatePipe } from '@angular/common';
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
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { messageOf } from '../../core/api-error';
import { ApiService } from '@/app/core/api.service';
import { Issue, TriageRequest } from '@/app/core/api.models';

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
 *
 * **The same dialog decides one row or the selection.** Narrow to a CVE with the search, tick the
 * page, decide once — the filters are the grouping, which is why there is no "group by CVE" here
 * and no second route on the server either.
 */
import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'zs-issues',
    standalone: true,
    imports: [DatePipe, FormsModule, RouterLink, TableModule, TagModule, ButtonModule, SelectModule, InputTextModule, IconFieldModule, InputIconModule, DialogModule, TextareaModule, MessageModule, ToggleSwitchModule, TranslatePipe],
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
     * The triage decision to narrow to.
     *
     * Named `triageFilter` and not `triageStatus` because the dialog below already owns that
     * name: one field for the row being edited and the list being filtered would mean opening
     * the dialog silently re-filters the list behind it.
     */
    triageFilter: string | null = null;

    /**
     * The three switches, held as ordinary fields and **read straight from the URL** on arrival.
     *
     * That is the whole point of them. The dashboard has linked here with `is_kev` and `overdue`
     * since the first version, and this screen kept them in a private object the controls could
     * not see: the list was narrowed and every filter on screen read "all", so the short list
     * looked like the whole backlog having lost most of its rows. A control the link cannot
     * light up contradicts the URL that opened it.
     */
    onlyDirect = false;
    onlyKev = false;
    overdue = false;

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

    /**
     * The rows a bulk decision would apply to.
     *
     * Held here and not left to the table, because it has to be **cleared on every reload**: a
     * selection that outlives the rows it was made on is a decision taken about issues the user
     * is no longer looking at — change a filter, keep four ticks, dismiss four strangers.
     */
    readonly selected = signal<Issue[]>([]);

    /**
     * Whether the dialog is deciding on the selection or on one row.
     *
     * The same dialog for both on purpose: two dialogs would be two places where the VEX rule
     * about a required justification lives, and the second one to be written is the one that
     * forgets it.
     */
    private bulk = false;

    readonly justifications = VEX_JUSTIFICATIONS;

    /** One list for the filter, the dialog and the row's label: three copies of the triage
     *  vocabulary would drift, and the first symptom is a filter offering a status no row shows. */
    readonly triageOptions = [
        { label: 'Under review', value: 'under_review' },
        { label: 'Affected', value: 'affected' },
        { label: 'Not affected', value: 'not_affected' },
        { label: 'Fixed', value: 'fixed' }
    ];

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
        // Into the controls, not into a hidden object: the filter has to apply *and* show as
        // applied, or the screen disagrees with the link that opened it.
        if (params.get('is_kev') === 'true') this.onlyKev = true;
        // The same arrangement for the deadline figure: the dashboard links here, and a link
        // this screen does not read is a filter that silently does nothing.
        if (params.get('overdue') === 'true') this.overdue = true;
        if (params.get('only_direct') === 'true') this.onlyDirect = true;
        if (params.get('triage_status')) this.triageFilter = params.get('triage_status');

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
        // Dropped before the request, not after it: between the two the screen would offer
        // "triage selected (4)" over rows that are on their way out, and a bulk decision taken in
        // that window would land on whatever was ticked under the previous filter.
        this.selected.set([]);
        this.offset.set(Math.max(0, offset));
        const [kind, id] = this.target?.split(':') ?? [];
        this.api
            .issues({
                repository_id: kind === 'repository' ? Number(id) : undefined,
                container_id: kind === 'container' ? Number(id) : undefined,
                state: this.state,
                severity: this.severity ?? undefined,
                type: this.type ?? undefined,
                triage_status: this.triageFilter ?? undefined,
                // Omitted rather than sent as `false`: the server treats these three as "act on
                // true alone", so `only_direct=false` is a parameter that says nothing while
                // making every request URL look like it carries a filter.
                only_direct: this.onlyDirect || undefined,
                is_kev: this.onlyKev || undefined,
                overdue: this.overdue || undefined,
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

    /**
     * The deadline, in words.
     *
     * The state comes from the server and is not re-derived here: this only turns it into a
     * phrase. A screen computing lateness from `slaDueAt` would be a second implementation of
     * the policy, and the two would part company the day a window moves.
     */
    slaLabel(issue: Issue): string | null {
        if (!issue.slaState || issue.slaDays === null) return null;
        if (issue.slaState === 'overdue') {
            const late = Math.abs(issue.slaDays);
            return late === 0 ? 'late today' : `${late} day${late === 1 ? '' : 's'} late`;
        }
        // "due in 0 days" reads worse than "due today", and the zero is a real case: the last
        // day of a window rounds to it.
        return issue.slaDays === 0 ? 'due today' : `due in ${issue.slaDays} days`;
    }

    slaColour(issue: Issue): 'danger' | 'warn' | 'secondary' {
        if (issue.slaState === 'overdue') return 'danger';
        if (issue.slaState === 'due_soon') return 'warn';
        return 'secondary';
    }

    /**
     * Whether a dismissal's review date is close enough to plan for.
     *
     * A week, the same horizon the remediation deadline uses: two different warning windows on
     * one screen would be two ideas of "soon" for a reader to reconcile.
     *
     * The expiry itself happens on the server, hourly — this only colours the date. A screen
     * deciding that a decision has lapsed would disagree with the gate, which reads the row.
     */
    reviewIsImminent(issue: Issue): boolean {
        if (!issue.triageExpiresAt) return false;
        const dueInDays = (new Date(issue.triageExpiresAt).getTime() - Date.now()) / 86_400_000;
        return dueInDays <= 7;
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
        this.bulk = false;
        this.triageStatus = issue.triageStatus;
        this.triageJustification = issue.triageJustification;
        this.triageComment = issue.triageComment ?? '';
        this.triageExpiresInDays = null;
        this.triageError.set(null);
        this.triageOpen = true;
    }

    /**
     * The same decision on everything ticked.
     *
     * One CVE appears in forty repositories, and "not reachable in our configuration" is one
     * judgement about one context, not forty. Deciding it forty times is how a backlog stops
     * being triaged at all.
     *
     * The fields open on the defaults rather than on any row's current decision: a batch has no
     * single "current" status, and pre-filling from the first tick would present one row's
     * dismissal as the state of all of them.
     */
    openBulkTriage(): void {
        if (this.selected().length === 0) return;
        this.triaged = null;
        this.bulk = true;
        this.triageStatus = 'under_review';
        this.triageJustification = null;
        this.triageComment = '';
        this.triageExpiresInDays = null;
        this.triageError.set(null);
        this.triageOpen = true;
    }

    /** The dialog says how wide the decision is, because "Save" looks identical for one row and
     *  for forty — and one of the two is not undoable row by row. */
    triageHeader(): string {
        return this.bulk ? `Triage ${this.selected().length} selected issue(s)` : 'Triage this issue';
    }

    /** Preventing the submission beats explaining a refusal afterwards. */
    canSubmitTriage(): boolean {
        return this.triageStatus !== 'not_affected' || !!this.triageJustification;
    }

    submitTriage(): void {
        if (!this.canSubmitTriage()) return;
        if (this.bulk) {
            this.submitBulkTriage();
            return;
        }
        if (!this.triaged) return;
        this.api
            .triage(this.triaged.id, this.triageBody())
            .subscribe({
                next: () => {
                    this.triageOpen = false;
                    this.reload(this.offset());
                },
                error: (response) => this.triageError.set(messageOf(response, 'The triage was refused.'))
            });
    }

    private triageBody(): TriageRequest {
        return {
            status: this.triageStatus,
            justification: this.triageJustification,
            comment: this.triageComment || null,
            expires_in_days: this.triageExpiresInDays || null
        };
    }

    /**
     * The batch, and the one failure whose wording matters.
     *
     * The server checks every id before it writes the first, so a refusal means **nothing was
     * triaged**. Its own 404 sentence is "Issue not found." — true, and read next to a list of
     * forty ticks it invites the reader to assume the other thirty-nine went through. The count
     * is stated here for that reason: a message that leaves a partial write plausible is worse
     * than no message, because the reader stops rather than retrying.
     *
     * `reload` clears the selection on its way out, which is also what keeps a successful batch
     * from staying ticked over rows whose triage column has just changed.
     */
    private submitBulkTriage(): void {
        const ids = this.selected().map((issue) => issue.id);
        if (ids.length === 0) return;
        this.api.triageMany({ ids, ...this.triageBody() }).subscribe({
            next: () => {
                this.triageOpen = false;
                this.reload(this.offset());
            },
            error: (response) => {
                const refused = `None of the ${ids.length} selected issues were triaged: the batch is refused as a whole.`;
                this.triageError.set(
                    (response as { status?: number } | null)?.status === 404
                        ? `${refused} One of them is no longer visible to you — reload the list and select again.`
                        : `${refused} ${messageOf(response, 'The triage was refused.')}`
                );
            }
        });
    }
}
