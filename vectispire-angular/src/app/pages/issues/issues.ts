import { DatePipe } from '@angular/common';
import { I18nService } from '../../core/i18n/i18n.service';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, ParamMap, Params, Router, RouterLink } from '@angular/router';
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
import { IntelApi } from '@/app/core/api/intel.api';
import { TargetsApi } from '@/app/core/api/targets.api';
import { IssuesApi } from '@/app/core/api/issues.api';
import { SolutionsApi } from '@/app/core/api/solutions.api';
import { SessionStore } from '@/app/core/session.store';
import { Issue, TriageRequest, AiVulnerabilityAdvice, AiDeterministic, SolutionTree } from '@/app/core/api.models';
import * as wording from '@/app/shared/ai-advice';
import { SEVERITIES, SEVERITY_KEYS } from '@/app/shared/checklist-rules';
import { findingTypeLabel, findingTypeOptions } from '@/app/shared/finding-types';
import { ANY_CATEGORY, isoDay, mondayOf, owaspCategory } from '@/app/shared/owasp-weekly';

/** The VEX justifications for a `not_affected` statement, as the standard names them. */

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
import { LatestRequest } from '@/app/core/latest-request';

@Component({
    selector: 'zs-issues',
    imports: [
        DatePipe,
        FormsModule,
        RouterLink,
        TableModule,
        TagModule,
        ButtonModule,
        SelectModule,
        InputTextModule,
        IconFieldModule,
        InputIconModule,
        DialogModule,
        TextareaModule,
        MessageModule,
        ToggleSwitchModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './issues.html'
})
export class Issues {
    private readonly page = new LatestRequest();

    private readonly i18n = inject(I18nService);
    private readonly intelApi = inject(IntelApi);
    private readonly targetsApi = inject(TargetsApi);
    private readonly issuesApi = inject(IssuesApi);
    private readonly solutionsApi = inject(SolutionsApi);
    private readonly route = inject(ActivatedRoute);
    private readonly router = inject(Router);

    readonly session = inject(SessionStore);
    /**
     * **Two signals, not one.** `canCauseEffects` says whether the account can triage at all —
     * false for an auditor alone. `canApproveTriage` says whether its decision settles or goes into
     * an approval queue. Both existed in `session.store` and were read nowhere: the same screen was
     * shown to all six roles, so an auditor was offered "Triage selected" and a developer read
     * "Close" on a button that opens a request.
     */
    readonly canTriage = this.session.canCauseEffects;
    readonly canApprove = this.session.canApproveTriage;

    /**
     * The triage label, which says what the click is going to do.
     *
     * <p><b>Three hard-coded copies, in French, in a bilingual application.</b> This label was born
     * with the separation between governing and acting, after the pass that had pulled out the
     * eighty-seven hard-coded labels: it arrived too late for that pass and nobody caught up with
     * it. An English-speaking reader read "Envoyer pour approbation" in the middle of a translated
     * screen.
     *
     * <p>It is here rather than copied because the distinction it carries — my decision settles, or
     * it goes into a queue — must read the same on all three buttons that offer it.
     *
     * <p>The name carries "action" because {@code triageLabel(status)} already existed and names
     * something else: a finding's state, not what a click would do. The two first carried the same
     * name, the module stopped compiling, and the development server went on serving the previous
     * bundle — so three runs of the suite judged the code from before.
     */
    readonly triageActionLabel = computed(() => {
        this.i18n.translations();
        return this.i18n.t(this.canApprove() ? 'issues.triage_action' : 'issues.triage_request');
    });

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
    /** What the dashboard's per-severity figures count: open, less settled triage. */
    unsettled = false;

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

    /**
     * The project and the solution the list is narrowed to, from the URL alone.
     *
     * No select for them: the tree is where a project is chosen, and its badges link here. What
     * this screen owes the link is to **show** the scope it applies — a list narrowed to one
     * project with nothing on screen saying so reads as a backlog that lost most of its rows —
     * and to let it be taken off. Both may be present; the server applies both.
     */
    readonly projectId = signal<number | null>(null);
    readonly solutionId = signal<number | null>(null);

    /**
     * The tree, read once and only when a scope needs naming — never a request per row, and none
     * at all on the common visit that carries no scope.
     */
    private readonly tree = signal<SolutionTree | null>(null);
    private treeRequested = false;

    /**
     * The scope in words. **A project the tree does not hold is named by its number**, the one the
     * URL already carries: the tree answers only what the reader may see, so "unknown project" for
     * a hidden one and a name for a visible one would be the difference the server's empty page is
     * careful not to make. The number says nothing the link did not.
     */
    readonly projectLabel = computed(() => {
        const id = this.projectId();
        if (id === null) return null;
        for (const solution of this.tree()?.solutions ?? []) {
            const project = (solution.projects ?? []).find((candidate) => candidate.id === id);
            if (project) return `${solution.name} / ${project.name}`;
        }
        return `#${id}`;
    });
    readonly solutionLabel = computed(() => {
        const id = this.solutionId();
        if (id === null) return null;
        return (this.tree()?.solutions ?? []).find((candidate) => candidate.id === id)?.name ?? `#${id}`;
    });

    /**
     * The weekly OWASP view's drill-down: a category as the grid places it, and the dates of an
     * issue's life — ISO days in UTC, `_to` included, as the server reads them.
     *
     * **Read from the URL into signals and shown in a banner**, because no other control can show
     * them: a list narrowed to "A06 open on 27/09" with nothing on screen saying so reads as a backlog
     * that lost most of its rows — and a figure that opens a list disagreeing with it reads as a wrong
     * figure. A garbled value is dropped, as a garbled id is: the server would answer it with a 400.
     */
    readonly owaspCategory = signal<string | null>(null);
    readonly openAt = signal<string | null>(null);
    readonly firstSeenFrom = signal<string | null>(null);
    readonly firstSeenTo = signal<string | null>(null);
    readonly resolvedFrom = signal<string | null>(null);
    readonly resolvedTo = signal<string | null>(null);
    readonly reopenedFrom = signal<string | null>(null);
    readonly reopenedTo = signal<string | null>(null);

    readonly asksDates = computed(
        () =>
            this.openAt() !== null ||
            this.firstSeenFrom() !== null ||
            this.firstSeenTo() !== null ||
            this.resolvedFrom() !== null ||
            this.resolvedTo() !== null ||
            this.reopenedFrom() !== null ||
            this.reopenedTo() !== null
    );

    /**
     * `all` when a date is asked, `open` otherwise — the server's own default, shown in the control.
     * "Open on that Sunday" is mostly issues resolved since: the backlog's usual `open` would hide them
     * and the list would come out shorter than the figure that opened it.
     */
    private defaultState(): string {
        return this.asksDates() ? 'all' : 'open';
    }

    /** What the drill-down asks, in words; `null` when the URL carries none of it. */
    readonly weeklyBanner = computed(() => {
        this.i18n.translations();
        const asked = this.owaspCategory();
        // `any` is every category at once — a week's total — and is said so, never shown as a code.
        const category = asked === ANY_CATEGORY ? this.i18n.t('issues.weekly.any') : asked;
        const sentences: string[] = [];
        const openAt = this.openAt();
        if (openAt !== null) {
            sentences.push(
                category !== null
                    ? this.i18n.t('issues.weekly.open_at_category', { category, date: openAt })
                    : this.i18n.t('issues.weekly.open_at', { date: openAt })
            );
        }
        if (this.firstSeenFrom() !== null || this.firstSeenTo() !== null) {
            const range = {
                category: category ?? '',
                from: this.firstSeenFrom() ?? '…',
                to: this.firstSeenTo() ?? '…'
            };
            sentences.push(
                category !== null
                    ? this.i18n.t('issues.weekly.first_seen_category', range)
                    : this.i18n.t('issues.weekly.first_seen', range)
            );
        }
        if (this.resolvedFrom() !== null || this.resolvedTo() !== null) {
            const range = { category: category ?? '', from: this.resolvedFrom() ?? '…', to: this.resolvedTo() ?? '…' };
            sentences.push(
                category !== null
                    ? this.i18n.t('issues.weekly.resolved_category', range)
                    : this.i18n.t('issues.weekly.resolved', range)
            );
        }
        if (this.reopenedFrom() !== null || this.reopenedTo() !== null) {
            const range = { category: category ?? '', from: this.reopenedFrom() ?? '…', to: this.reopenedTo() ?? '…' };
            sentences.push(
                category !== null
                    ? this.i18n.t('issues.weekly.reopened_category', range)
                    : this.i18n.t('issues.weekly.reopened', range)
            );
        }
        if (sentences.length === 0 && asked === ANY_CATEGORY) {
            sentences.push(this.i18n.t('issues.weekly.category_any'));
        } else if (sentences.length === 0 && category !== null) {
            sentences.push(this.i18n.t('issues.weekly.category', { category }));
        }
        return sentences.length === 0 ? null : sentences.join(' · ');
    });

    /**
     * The way back to the weekly view, on the week the figure came from and in the same scope. Built
     * from the parameters themselves, never from a URL the link carried: a return address taken from
     * the query string is an open redirect.
     */
    readonly weeklyBack = computed<Params>(() => {
        const day =
            this.openAt() ??
            this.firstSeenFrom() ??
            this.resolvedFrom() ??
            this.reopenedFrom() ??
            this.firstSeenTo() ??
            this.resolvedTo() ??
            this.reopenedTo();
        const params: Params = { view: 'weekly' };
        if (day !== null) params['week'] = mondayOf(day);
        const projectId = this.projectId();
        const solutionId = this.solutionId();
        if (projectId !== null) params['project_id'] = String(projectId);
        else if (solutionId !== null) params['solution_id'] = String(solutionId);
        return params;
    });

    /** Takes the drill-down off and leaves every other filter; the state returns to its own default. */
    clearWeekly(): void {
        const explicitState = this.route.snapshot.queryParamMap.has('state');
        this.owaspCategory.set(null);
        this.openAt.set(null);
        this.firstSeenFrom.set(null);
        this.firstSeenTo.set(null);
        this.resolvedFrom.set(null);
        this.resolvedTo.set(null);
        this.reopenedFrom.set(null);
        this.reopenedTo.set(null);
        if (!explicitState) this.state = 'open';
        this.filtersChanged();
    }

    readonly states = computed(() => {
        this.i18n.translations();
        return [
            { label: this.i18n.t('issues.states.open'), value: 'open' },
            { label: this.i18n.t('issues.states.resolved'), value: 'resolved' },
            { label: this.i18n.t('issues.states.all'), value: 'all' }
        ];
    });
    readonly severities = computed(() => {
        this.i18n.translations();
        return SEVERITIES.map((value) => ({ label: this.i18n.t(SEVERITY_KEYS[value]), value }));
    });
    /** Written once, in `shared/finding-types`, so the filter and the row's label cannot disagree. */
    readonly types = computed(() => {
        this.i18n.translations();
        return findingTypeOptions(this.i18n);
    });

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

    readonly justifications = computed(() => {
        this.i18n.translations();
        return [
            { value: 'component_not_present', label: this.i18n.t('issues.vex.component_not_present') },
            { value: 'vulnerable_code_not_present', label: this.i18n.t('issues.vex.vulnerable_code_not_present') },
            {
                value: 'vulnerable_code_not_in_execute_path',
                label: this.i18n.t('issues.vex.vulnerable_code_not_in_execute_path')
            },
            {
                value: 'vulnerable_code_cannot_be_controlled_by_adversary',
                label: this.i18n.t('issues.vex.vulnerable_code_cannot_be_controlled_by_adversary')
            },
            {
                value: 'inline_mitigations_already_exist',
                label: this.i18n.t('issues.vex.inline_mitigations_already_exist')
            }
        ];
    });

    /** One list for the filter, the dialog and the row's label: three copies of the triage
     *  vocabulary would drift, and the first symptom is a filter offering a status no row shows. */
    readonly triageOptions = computed(() => {
        this.i18n.translations();
        return [
            { label: this.i18n.t('issues.triage_status.under_review'), value: 'under_review' },
            { label: this.i18n.t('issues.triage_status.pending_approval'), value: 'pending_approval' },
            { label: this.i18n.t('issues.triage_status.affected'), value: 'affected' },
            { label: this.i18n.t('issues.triage_status.not_affected'), value: 'not_affected' },
            { label: this.i18n.t('issues.triage_status.fixed'), value: 'fixed' }
        ];
    });

    constructor() {
        // **The URL is the filter, and it is followed, not read once.** The page read a snapshot:
        // a second link into it — a badge on the tree while the list was open, the back button,
        // a chip taken off — changed the address and left the list as it was. Every control
        // writes the URL (`filtersChanged`), and every change of the URL lands here.
        this.route.queryParamMap.pipe(takeUntilDestroyed()).subscribe((params) => {
            this.applyUrl(params);
            this.nameScope();
            this.reload(0);
        });

        this.loadTargets();

        // **The advisor is offered only if it exists.** With no model configured, the button opened
        // a dialog that could say nothing; a read failure — not an access one — so a call that fails
        // leaves the button hidden rather than promising one that misses.
        this.intelApi.getAiAdvisorStatus().subscribe({
            next: (status) => this.aiEnabled.set(status?.enabled === true),
            error: () => this.aiEnabled.set(false)
        });
    }

    /**
     * Every filter from the URL, **absent meaning off**: a parameter that is not there has to clear
     * its control, or taking a chip off would leave the list narrowed by what the chip said.
     */
    private applyUrl(params: ParamMap): void {
        const repositoryId = params.get('repository_id');
        const containerId = params.get('container_id');
        // Reflected into the control, not only into the query: arriving from a link used to
        // filter the list while every filter on screen read "all", so the short list looked
        // like the whole backlog having lost most of its rows.
        this.target = repositoryId ? `repository:${repositoryId}` : containerId ? `container:${containerId}` : null;
        this.type = params.get('type');
        this.owaspCategory.set(owaspCategory(params.get('owasp_category')));
        this.openAt.set(isoDay(params.get('open_at')));
        this.firstSeenFrom.set(isoDay(params.get('first_seen_from')));
        this.firstSeenTo.set(isoDay(params.get('first_seen_to')));
        this.resolvedFrom.set(isoDay(params.get('resolved_from')));
        this.resolvedTo.set(isoDay(params.get('resolved_to')));
        this.reopenedFrom.set(isoDay(params.get('reopened_from')));
        this.reopenedTo.set(isoDay(params.get('reopened_to')));
        // The dashboard has always linked here with these, and this screen once read none of
        // them: clicking "8 high" opened the whole backlog, and so did the KEV panel. Nothing
        // failed — the page loaded, full of issues, simply not the ones that were asked for.
        this.severity = params.get('severity');
        this.state = params.get('state') ?? this.defaultState();
        this.onlyKev = params.get('is_kev') === 'true';
        this.overdue = params.get('overdue') === 'true';
        // The per-severity figures on the dashboard and the tree leave settled triage out and
        // link here with this; unread, "3 critical" would open a list of five.
        this.unsettled = params.get('unsettled') === 'true';
        this.onlyDirect = params.get('only_direct') === 'true';
        this.triageFilter = params.get('triage_status');
        this.search = params.get('search') ?? '';
        this.projectId.set(idOf(params.get('project_id')));
        this.solutionId.set(idOf(params.get('solution_id')));
    }

    /** The filters as the URL spells them; a default is left out, so a plain visit stays `/issues`. */
    private urlParams(): Params {
        const [kind, id] = this.target?.split(':') ?? [];
        const params: Params = {
            repository_id: kind === 'repository' ? id : undefined,
            container_id: kind === 'container' ? id : undefined,
            project_id: this.projectId() ?? undefined,
            solution_id: this.solutionId() ?? undefined,
            state: this.state !== this.defaultState() ? this.state : undefined,
            severity: this.severity ?? undefined,
            type: this.type ?? undefined,
            triage_status: this.triageFilter ?? undefined,
            only_direct: this.onlyDirect || undefined,
            is_kev: this.onlyKev || undefined,
            overdue: this.overdue || undefined,
            unsettled: this.unsettled || undefined,
            search: this.search || undefined,
            owasp_category: this.owaspCategory() ?? undefined,
            open_at: this.openAt() ?? undefined,
            first_seen_from: this.firstSeenFrom() ?? undefined,
            first_seen_to: this.firstSeenTo() ?? undefined,
            resolved_from: this.resolvedFrom() ?? undefined,
            resolved_to: this.resolvedTo() ?? undefined,
            reopened_from: this.reopenedFrom() ?? undefined,
            reopened_to: this.reopenedTo() ?? undefined
        };
        return Object.fromEntries(
            Object.entries(params)
                .filter(([, value]) => value !== undefined)
                .map(([key, value]) => [key, String(value)])
        );
    }

    /**
     * A control moved: the URL is rewritten and the subscription reloads. Replacing the entry
     * rather than pushing one, so that "back" returns to the page the list was opened from and
     * not through every filter tried on the way.
     *
     * An unchanged URL emits nothing, and pressing Enter again in the search box is still a
     * request to read the list again — so that case reloads here.
     */
    filtersChanged(): void {
        const next = this.urlParams();
        const current = this.route.snapshot.queryParamMap;
        const same =
            current.keys.length === Object.keys(next).length &&
            Object.entries(next).every(([key, value]) => current.get(key) === value);
        if (same) {
            this.reload(0);
            return;
        }
        void this.router.navigate([], { relativeTo: this.route, queryParams: next, replaceUrl: true });
    }

    removeProject(): void {
        this.projectId.set(null);
        this.filtersChanged();
    }

    removeSolution(): void {
        this.solutionId.set(null);
        this.filtersChanged();
    }

    /** A failure leaves the chip named by its number: the list, not the name, is what was asked for. */
    private nameScope(): void {
        if (this.treeRequested || (this.projectId() === null && this.solutionId() === null)) return;
        this.treeRequested = true;
        this.solutionsApi.solutionTree().subscribe({
            next: (tree) => this.tree.set(tree),
            error: () => undefined
        });
    }

    /**
     * Both lists, and a failure on either leaves the filter empty rather than the screen.
     *
     * The backlog is what somebody came for; not being able to narrow it is a degradation, not
     * a reason to show an error over the list they can still read.
     */
    private loadTargets(): void {
        const options: { label: string; value: string }[] = [];
        this.targetsApi.repositories().subscribe({
            next: (repositories) => {
                options.push(...repositories.map((row) => ({ label: row.displayName, value: `repository:${row.id}` })));
                this.targets.set([...options]);
            },
            error: () => undefined
        });
        this.targetsApi.containers().subscribe({
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
        // Latest wins: an answer to a previous filter is cancelled, never shown under this one.
        this.page.run(
            this.issuesApi.issues({
                repository_id: kind === 'repository' ? Number(id) : undefined,
                container_id: kind === 'container' ? Number(id) : undefined,
                project_id: this.projectId() ?? undefined,
                solution_id: this.solutionId() ?? undefined,
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
                unsettled: this.unsettled || undefined,
                search: this.search || undefined,
                owasp_category: this.owaspCategory() ?? undefined,
                open_at: this.openAt() ?? undefined,
                first_seen_from: this.firstSeenFrom() ?? undefined,
                first_seen_to: this.firstSeenTo() ?? undefined,
                resolved_from: this.resolvedFrom() ?? undefined,
                resolved_to: this.resolvedTo() ?? undefined,
                reopened_from: this.reopenedFrom() ?? undefined,
                reopened_to: this.reopenedTo() ?? undefined,
                limit: this.limit,
                offset: this.offset()
            }),
            {
                next: (page) => {
                    this.issues.set(page.items);
                    this.total.set(page.total);
                    this.loading.set(false);
                },
                error: () => this.loading.set(false)
            }
        );
    }

    pageLabel(): string {
        if (this.total() === 0) return this.i18n.t('issues.no_result');
        return this.i18n.t('issues.page_range', {
            from: this.offset() + 1,
            to: Math.min(this.offset() + this.limit, this.total()),
            total: this.total()
        });
    }

    /**
     * The type in words. Open table: an unknown type shows raw rather than being hidden, because
     * a type Vectispire does not know is a type somebody added and nobody wired to this screen.
     */
    typeLabel(type: string): string {
        this.types();
        return findingTypeLabel(this.i18n, type);
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
            if (late === 0) return this.i18n.t('issues.sla_late_today');
            return this.i18n.t(late === 1 ? 'issues.sla_late_one' : 'issues.sla_late_many', { count: late });
        }
        // "due in 0 days" reads worse than "due today", and the zero is a real case: the last
        // day of a window rounds to it.
        if (issue.slaDays === 0) return this.i18n.t('issues.sla_due_today');
        return this.i18n.t(issue.slaDays === 1 ? 'issues.sla_due_one' : 'issues.sla_due_many', {
            count: issue.slaDays
        });
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
        if (status === 'pending_approval') return 'warn';
        return 'secondary';
    }

    triageLabel(status: string): string {
        return this.triageOptions().find((option) => option.value === status)?.label ?? status;
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
        return this.bulk
            ? this.i18n.t('issues.triage_header_bulk', { count: this.selected().length })
            : this.i18n.t('issues.triage_header_single');
    }

    /** Preventing the submission beats explaining a refusal afterwards. */
    canSubmitTriage(): boolean {
        return (
            (this.triageStatus !== 'not_affected' && this.triageStatus !== 'pending_approval') ||
            !!this.triageJustification
        );
    }

    submitTriage(): void {
        if (!this.canSubmitTriage()) return;
        if (this.bulk) {
            this.submitBulkTriage();
            return;
        }
        if (!this.triaged) return;
        this.issuesApi.triage(this.triaged.id, this.triageBody()).subscribe({
            next: () => {
                this.triageOpen = false;
                this.reload(this.offset());
            },
            error: (response) => this.triageError.set(messageOf(response, this.i18n.t('issues.triage_refused')))
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

    private submitBulkTriage(): void {
        const ids = this.selected().map((issue) => issue.id);
        if (ids.length === 0) return;
        this.issuesApi.triageMany({ ids, ...this.triageBody() }).subscribe({
            next: () => {
                this.triageOpen = false;
                this.reload(this.offset());
            },
            error: (response) => {
                const refused = this.i18n.t('issues.bulk_triage_refused', { count: ids.length });
                this.triageError.set(
                    (response as { status?: number } | null)?.status === 404
                        ? `${refused} ${this.i18n.t('issues.bulk_triage_not_visible')}`
                        : `${refused} ${messageOf(response, this.i18n.t('issues.triage_refused'))}`
                );
            }
        });
    }

    /**
     * The advisor, and the two ways it lied.
     *
     * <p><b>The button was offered to everybody, all the time.</b> With no model configured it
     * opened a dialog onto an unreachable service — and an absent option must be absent, not
     * present and refusing. `getAiAdvisorStatus` said exactly that and nobody called it.
     *
     * <p><b>And the failure was shown nowhere.</b> The message set in `aiAdviceError` had no branch
     * in the template: the dialog opened, the spinner stopped, and nothing was left. The message
     * itself promised "local fallback generation" — a fallback this code never wrote. An error that
     * promises what will not happen is worse than a silent one.
     */
    readonly aiEnabled = signal<boolean>(false);
    readonly aiAdviceLoading = signal<boolean>(false);
    readonly aiAdvice = signal<AiVulnerabilityAdvice | null>(null);
    readonly aiAdviceError = signal<string | null>(null);

    /**
     * The product's own sentences, in the reader's language, from exactly the values it sent —
     * unknown said as unknown. This formatted a missing EPSS score as 85 %.
     */
    adviceSummary(advice: AiVulnerabilityAdvice, own: AiDeterministic): string {
        return wording.adviceSummary(this.i18n, advice.identifier, own);
    }

    adviceExploitation(own: AiDeterministic): string {
        return wording.adviceExploitation(this.i18n, own);
    }

    adviceFix(own: AiDeterministic): string {
        return wording.adviceFix(this.i18n, own);
    }

    aiModalOpen = false;
    aiTargetIssue: Issue | null = null;

    openAiAdvisor(issue: Issue): void {
        this.aiTargetIssue = issue;
        this.aiAdvice.set(null);
        this.aiAdviceError.set(null);
        this.aiAdviceLoading.set(true);
        this.aiModalOpen = true;

        this.intelApi.explainIssueWithAi(issue.id, this.i18n.currentLang()).subscribe({
            next: (advice) => {
                this.aiAdvice.set(advice);
                this.aiAdviceLoading.set(false);
            },
            error: (response) => {
                this.aiAdviceLoading.set(false);
                this.aiAdviceError.set(messageOf(response, this.i18n.t('issues.ai_unreachable')));
            }
        });
    }

    applySuggestedVex(): void {
        const advice = this.aiAdvice();
        if (!advice || !this.aiTargetIssue) return;

        this.openTriage(this.aiTargetIssue);
        if (advice.vexSuggestion) {
            this.triageStatus = advice.vexSuggestion.status || 'under_investigation';
            this.triageJustification = advice.vexSuggestion.justification || null;
            this.triageComment = `${this.i18n.t('issues.ai_suggestion_prefix')} ${advice.vexSuggestion.impactStatement || advice.summaryExplanation}`;
        }
        this.aiModalOpen = false;
    }

    copyText(text: string): void {
        if (navigator?.clipboard) {
            void navigator.clipboard.writeText(text);
        }
    }
}

/**
 * A positive integer, or nothing. A garbled id is dropped rather than sent: the server would refuse
 * `project_id=abc` with a 400, and the page would show an error for what is a bad link.
 */
function idOf(value: string | null): number | null {
    if (value === null || !/^\d+$/.test(value)) return null;
    const id = Number(value);
    return id > 0 ? id : null;
}
