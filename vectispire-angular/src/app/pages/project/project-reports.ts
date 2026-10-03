import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ReportPluginsApi } from '../../core/api/report-plugins.api';
import type { ReportPlugin, ReportPluginActivation, ReportRun } from '../../core/api.models';
import { saveDocument } from '../../core/download';
import { I18nService } from '../../core/i18n/i18n.service';
import { keyFor } from '../../core/i18n/literal-keys';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '../../core/latest-request';
import { pollWhile } from '../../core/poll-while';
import { SessionStore } from '../../core/session.store';
import {
    ACTIVE_RUN_STATES,
    CONFLICT_KEYS,
    MEDIA_TYPE_EXTENSIONS,
    RUN_REASON_KEYS,
    RUN_STATE_KEYS,
    RUN_STATE_SEVERITY,
    isNotFound,
    reportConflictOf,
    shortDigest
} from '../../shared/report-plugins';

/** Where the commands that verify a package are written, per language of the user guide's site. */
export const VERIFY_DOC = {
    en: 'https://asmolabs.github.io/vectispire/administration/report-plugins/#the-document-and-how-to-verify-it',
    fr: 'https://asmolabs.github.io/vectispire/fr/administration/report-plugins/#le-document-et-comment-le-verifier'
} as const;

/** A run moves in seconds to minutes; five seconds is what the scans wait too. */
export const POLL_MS = 5000;

/**
 * A project's reports (decision 0035): the report plugins switched on for it, the runs, and the two
 * documents that leave with the project's whole triaged state — a produced run's package and the
 * plain export.
 *
 * **Only for a reader who sees the whole project**, images included: every route here answers 404
 * otherwise, so the parent page does not render this section for a partial reader and says why.
 *
 * **Who does what, as the server decides it.** Security leads switch a plugin on and off. Write
 * accounts and auditors request a report and take the export; the platform governor, who acts on
 * nothing a project holds, does neither — the button stays visible, disabled, with the reason, so
 * that the governor does not go looking for a permission. Anybody here reads the runs and downloads
 * a produced document.
 */
@Component({
    selector: 'app-project-reports',
    imports: [
        DatePipe,
        FormsModule,
        ButtonModule,
        CardModule,
        MessageModule,
        SelectModule,
        TableModule,
        TagModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './project-reports.html'
})
export class ProjectReports {
    private readonly api = inject(ReportPluginsApi);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);
    private readonly runsRequest = new LatestRequest();

    readonly projectId = input.required<number>();

    readonly activations = signal<ReportPluginActivation[] | null>(null);
    readonly runs = signal<ReportRun[] | null>(null);
    readonly registry = signal<ReportPlugin[]>([]);
    readonly error = signal<string | null>(null);
    readonly notice = signal<string | null>(null);
    readonly busy = signal<string | null>(null);
    readonly exporting = signal(false);
    readonly toActivate = signal<string | null>(null);

    readonly managesActivations = this.session.isSecurityLead;
    /** `canCauseEffects` or the auditor — decision 0035's answer 4; the platform governor is neither. */
    readonly mayRequest = computed(() => this.session.canCauseEffects() || this.session.role() === 'AUDITOR');

    readonly shortDigest = shortDigest;
    readonly verifyDoc = computed(() => VERIFY_DOC[this.i18n.currentLang() === 'fr' ? 'fr' : 'en']);

    /** Waiting is worth a request only while something can still change. */
    readonly active = computed(() => (this.runs() ?? []).some((run) => ACTIVE_RUN_STATES.includes(run.state)));

    /** The plugins a run is under way for: a second request is a 409 the button need not invite. */
    readonly busyPlugins = computed(
        () =>
            new Set(
                (this.runs() ?? []).filter((run) => ACTIVE_RUN_STATES.includes(run.state)).map((run) => run.pluginId)
            )
    );

    /**
     * What a security lead may switch on: approved — the server refuses the others — and not on already.
     * A disabled plugin is offered: switching it on is remembered for when the governor enables it.
     */
    readonly activatable = computed(() => {
        const on = new Set((this.activations() ?? []).map((one) => one.pluginId));
        return this.registry()
            .filter((plugin) => plugin.approvedDigest && !on.has(plugin.id))
            .map((plugin) => ({ label: `${plugin.name} (${plugin.id})`, value: plugin.id }));
    });

    constructor() {
        effect(() => {
            const id = this.projectId();
            untracked(() => this.load(id));
        });
        pollWhile(this.active, () => this.loadRuns(this.projectId()), POLL_MS);
    }

    private load(id: number): void {
        this.error.set(null);
        this.notice.set(null);
        this.activations.set(null);
        this.runs.set(null);
        this.api.projectReportPlugins(id).subscribe({
            next: (activations) => this.activations.set(activations),
            error: (failure) => {
                this.activations.set([]);
                this.error.set(this.failureOf(failure, 'reports.error_load'));
            }
        });
        this.loadRuns(id);
        if (this.managesActivations()) {
            // Governance reading: a security lead holds it. A failure leaves the selector empty, nothing more.
            this.api.reportPlugins().subscribe({
                next: (plugins) => this.registry.set(plugins),
                error: () => this.registry.set([])
            });
        }
    }

    private loadRuns(id: number): void {
        this.runsRequest.run(this.api.projectReports(id), {
            next: (runs) => this.runs.set(runs),
            error: (failure) => {
                if (this.runs() === null) this.runs.set([]);
                this.error.set(this.failureOf(failure, 'reports.error_load'));
            }
        });
    }

    /** A 409 in the reader's words, a 404 as the absence it is, the server's own sentence otherwise. */
    private failureOf(failure: unknown, fallback: string): string {
        const conflict = reportConflictOf(failure);
        if (conflict) return this.i18n.t(CONFLICT_KEYS[conflict]);
        if (isNotFound(failure)) return this.i18n.t('reports.error_not_found');
        return messageOf(failure, this.i18n.t(fallback));
    }

    pluginName(pluginId: string): string {
        return this.activations()?.find((one) => one.pluginId === pluginId)?.pluginName ?? pluginId;
    }

    stateLabel(run: ReportRun): string {
        this.i18n.translations();
        const key = keyFor(RUN_STATE_KEYS, run.state);
        return key ? this.i18n.t(key) : run.state;
    }

    stateSeverity(run: ReportRun): 'secondary' | 'info' | 'success' | 'warn' | 'danger' {
        return (
            (RUN_STATE_SEVERITY as Record<string, 'secondary' | 'info' | 'success' | 'warn' | 'danger'>)[run.state] ??
            'secondary'
        );
    }

    /** A reason this client does not know is shown as sent: never a key path, never an empty cell. */
    reasonLabel(run: ReportRun): string | null {
        if (!run.reason) return null;
        this.i18n.translations();
        const key = keyFor(RUN_REASON_KEYS, run.reason);
        return key ? this.i18n.t(key, { code: run.exitCode ?? '—' }) : run.reason;
    }

    extension(mediaType: string | null): string {
        return (MEDIA_TYPE_EXTENSIONS as Record<string, string>)[mediaType ?? ''] ?? mediaType ?? '';
    }

    size(bytes: number | null): string {
        if (bytes === null) return '—';
        if (bytes < 1024) return this.i18n.t('reports.size_bytes', { n: bytes });
        if (bytes < 1024 * 1024) return this.i18n.t('reports.size_kib', { n: (bytes / 1024).toFixed(1) });
        return this.i18n.t('reports.size_mib', { n: (bytes / (1024 * 1024)).toFixed(1) });
    }

    // --- Activations ---------------------------------------------------------------------------------

    activate(): void {
        const pluginId = this.toActivate();
        if (!pluginId) return;
        this.busy.set(`activate:${pluginId}`);
        this.error.set(null);
        this.api.activateReportPlugin(this.projectId(), pluginId).subscribe({
            next: (activation) => {
                this.busy.set(null);
                this.toActivate.set(null);
                this.activations.update((all) => [
                    ...(all ?? []).filter((one) => one.pluginId !== activation.pluginId),
                    activation
                ]);
                this.notice.set(this.i18n.t('reports.activated_notice', { name: activation.pluginName ?? pluginId }));
            },
            error: (failure) => {
                this.busy.set(null);
                this.error.set(this.failureOf(failure, 'reports.error_activate'));
            }
        });
    }

    deactivate(activation: ReportPluginActivation): void {
        this.busy.set(`deactivate:${activation.pluginId}`);
        this.error.set(null);
        this.api.deactivateReportPlugin(this.projectId(), activation.pluginId).subscribe({
            next: () => {
                this.busy.set(null);
                this.activations.update((all) => (all ?? []).filter((one) => one.pluginId !== activation.pluginId));
                this.notice.set(
                    this.i18n.t('reports.deactivated_notice', { name: activation.pluginName ?? activation.pluginId })
                );
            },
            error: (failure) => {
                this.busy.set(null);
                this.error.set(this.failureOf(failure, 'reports.error_deactivate'));
            }
        });
    }

    // --- Requests ------------------------------------------------------------------------------------

    request(activation: ReportPluginActivation): void {
        this.busy.set(`request:${activation.pluginId}`);
        this.error.set(null);
        this.notice.set(null);
        this.api.requestReport(this.projectId(), activation.pluginId).subscribe({
            next: (run) => {
                this.busy.set(null);
                this.runs.update((all) => [run, ...(all ?? []).filter((one) => one.id !== run.id)]);
                this.notice.set(
                    this.i18n.t('reports.requested_notice', { name: activation.pluginName ?? activation.pluginId })
                );
            },
            error: (failure) => {
                this.busy.set(null);
                // A plugin switched off since the page loaded answers 404: said as such, not as a lost project.
                this.error.set(
                    isNotFound(failure)
                        ? this.i18n.t('reports.error_not_activated', {
                              name: activation.pluginName ?? activation.pluginId
                          })
                        : this.failureOf(failure, 'reports.error_request')
                );
                // A run in progress the page did not know of: show it.
                if (reportConflictOf(failure) === 'run_in_progress') this.loadRuns(this.projectId());
            }
        });
    }

    // --- Downloads -----------------------------------------------------------------------------------

    /**
     * Saved as a download, never opened: the token is on the request, and the server serves the package
     * as an attachment under a sandbox policy for the same reason. A refusal's body is a Blob, so the
     * status is what is read.
     */
    download(run: ReportRun): void {
        this.busy.set(`download:${run.id}`);
        this.error.set(null);
        this.api.downloadReportPackage(this.projectId(), run.id).subscribe({
            next: (response) => {
                this.busy.set(null);
                saveDocument(response, `report-${run.id}-${run.pluginId}.zip`);
            },
            error: (failure) => {
                this.busy.set(null);
                this.error.set(
                    this.i18n.t(isNotFound(failure) ? 'reports.error_document_gone' : 'reports.error_download')
                );
            }
        });
    }

    downloadExport(): void {
        const id = this.projectId();
        this.exporting.set(true);
        this.error.set(null);
        this.api.downloadProjectExport(id).subscribe({
            next: (response) => {
                this.exporting.set(false);
                saveDocument(response, `vectispire-project-${id}-export.zip`);
            },
            error: (failure) => {
                this.exporting.set(false);
                const status = (failure as { status?: number } | null)?.status;
                this.error.set(
                    this.i18n.t(
                        status === 409
                            ? 'reports.error_export_too_large'
                            : status === 404
                              ? 'reports.error_not_found'
                              : 'reports.error_export'
                    )
                );
            }
        });
    }
}
