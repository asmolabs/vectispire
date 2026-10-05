import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { messageOf } from '../../core/api-error';
import { ReportPluginsApi } from '../../core/api/report-plugins.api';
import type { ReportPlugin, ReportPluginManifestView } from '../../core/api.models';
import { saveDocument } from '../../core/download';
import { I18nService } from '../../core/i18n/i18n.service';
import { keyFor } from '../../core/i18n/literal-keys';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SessionStore } from '../../core/session.store';
import {
    CONFLICT_KEYS,
    MANIFEST_STATUS_KEYS,
    MANIFEST_STATUS_SEVERITY,
    MEDIA_TYPE_EXTENSIONS,
    isNotFound,
    reportConflictOf,
    shortDigest
} from '../../shared/report-plugins';
import { checkManifest } from './manifest-check';

/** The server's bounds on a withdrawal's justification (decision 0035 §4), repeated only to shape the input. */
export const WITHDRAWAL_MIN = 20;
export const WITHDRAWAL_MAX = 500;

/** The export major this installation produces today — the one a plugin author downloads the schema of. */
export const EXPORT_MAJOR = 1;

/**
 * The report plugin registry (decision 0035 §4).
 *
 * **Read by governance readers; each gesture offered to the role the server takes it from.** The
 * platform governor registers, gives a new manifest, enables and withdraws; a security lead approves.
 * **Four-eyes on the image**: the account that registered a digest never approves it — the plugin will
 * produce documents under the installation's key, and one person deciding alone which code may do that
 * is the concentration four-eyes splits. The page says so beside the button rather than letting the
 * click meet a 409.
 *
 * **There is no delete**: an id names every document the plugin produced. A wrong image is withdrawn,
 * with a justification, and a fixed one is a new manifest.
 */
@Component({
    selector: 'app-report-plugins',
    imports: [
        DatePipe,
        FormsModule,
        ButtonModule,
        CardModule,
        DialogModule,
        MessageModule,
        TableModule,
        TagModule,
        TextareaModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './report-plugins.html'
})
export class ReportPlugins {
    private readonly api = inject(ReportPluginsApi);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);

    readonly governs = this.session.governsPlatform;
    readonly approves = this.session.isSecurityLead;
    readonly withdrawalMin = WITHDRAWAL_MIN;
    readonly withdrawalMax = WITHDRAWAL_MAX;
    readonly shortDigest = shortDigest;

    readonly plugins = signal<ReportPlugin[]>([]);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);
    readonly notice = signal<string | null>(null);
    readonly busy = signal<string | null>(null);
    readonly openId = signal<string | null>(null);
    readonly opened = computed(() => this.plugins().find((plugin) => plugin.id === this.openId()) ?? null);

    // --- The manifest dialog: a registration, or a new manifest for `manifestFor`.
    readonly manifestVisible = signal(false);
    readonly manifestFor = signal<ReportPlugin | null>(null);
    readonly manifestText = signal('');
    readonly manifestCheck = computed(() =>
        this.manifestText().trim() ? checkManifest(this.manifestText(), this.manifestFor()?.id ?? null) : null
    );
    readonly saving = signal(false);
    readonly manifestError = signal<string | null>(null);

    // --- The withdrawal dialog.
    readonly withdrawing = signal<{ plugin: ReportPlugin; manifest: ReportPluginManifestView } | null>(null);
    readonly withdrawalText = signal('');
    readonly withdrawalBusy = signal(false);
    readonly withdrawalError = signal<string | null>(null);

    constructor() {
        this.reload();
    }

    reload(): void {
        this.loading.set(true);
        this.api.reportPlugins().subscribe({
            next: (plugins) => {
                this.plugins.set(plugins);
                this.loading.set(false);
            },
            error: (failure) => {
                this.error.set(messageOf(failure, this.i18n.t('report_plugins.error_load')));
                this.loading.set(false);
            }
        });
    }

    toggle(plugin: ReportPlugin): void {
        this.openId.set(this.openId() === plugin.id ? null : plugin.id);
    }

    statusLabel(status: string): string {
        this.i18n.translations();
        const key = keyFor(MANIFEST_STATUS_KEYS, status);
        return key ? this.i18n.t(key) : status;
    }

    statusSeverity(status: string): 'warn' | 'success' | 'secondary' | 'danger' {
        return (
            (MANIFEST_STATUS_SEVERITY as Record<string, 'warn' | 'success' | 'secondary' | 'danger'>)[status] ??
            'secondary'
        );
    }

    extension(mediaType: string | null | undefined): string {
        return (MEDIA_TYPE_EXTENSIONS as Record<string, string>)[mediaType ?? ''] ?? mediaType ?? '—';
    }

    manifestJson(manifest: ReportPluginManifestView): string {
        return JSON.stringify(manifest.manifest, null, 2);
    }

    /**
     * Whether the person on screen may not approve this digest: they registered it. The four-eyes setting
     * is deliberately not read — only a registration made under four-eyes waits, so the rule it was
     * registered under is the one it is approved under, even if the setting was turned off since
     * (decision 0035, amended 2026-10-05). Reading today's setting here once offered a button the server
     * now refuses.
     */
    approvalBlocked(manifest: ReportPluginManifestView): boolean {
        return manifest.registeredBy === this.session.user()?.username;
    }

    /** A refusal in the reader's words when the server named its cause, its own sentence otherwise. */
    private refusal(failure: unknown, fallback: string): string {
        const conflict = reportConflictOf(failure);
        if (conflict) return this.i18n.t(CONFLICT_KEYS[conflict]);
        if (isNotFound(failure)) return this.i18n.t('report_plugins.error_gone');
        return messageOf(failure, this.i18n.t(fallback));
    }

    private replace(updated: ReportPlugin): void {
        this.plugins.update((plugins) => plugins.map((one) => (one.id === updated.id ? updated : one)));
    }

    // --- Register, or a new manifest ---------------------------------------------------------------

    openRegister(): void {
        this.manifestFor.set(null);
        this.manifestText.set('');
        this.manifestError.set(null);
        this.manifestVisible.set(true);
    }

    openUpdate(plugin: ReportPlugin): void {
        this.manifestFor.set(plugin);
        const current = plugin.manifests.find((one) => one.digest === (plugin.pendingDigest ?? plugin.approvedDigest));
        this.manifestText.set(current ? JSON.stringify(current.manifest, null, 2) : '');
        this.manifestError.set(null);
        this.manifestVisible.set(true);
    }

    saveManifest(): void {
        const manifest = this.manifestCheck()?.manifest;
        if (!manifest) return;
        const target = this.manifestFor();
        const request = target
            ? this.api.updateReportPlugin(target.id, manifest)
            : this.api.registerReportPlugin(manifest);
        this.saving.set(true);
        this.manifestError.set(null);
        request.subscribe({
            next: (plugin) => {
                this.saving.set(false);
                this.manifestVisible.set(false);
                this.notice.set(
                    this.i18n.t(
                        plugin.pendingDigest ? 'report_plugins.saved_pending_notice' : 'report_plugins.saved_notice',
                        { id: plugin.id }
                    )
                );
                this.openId.set(plugin.id);
                this.reload();
            },
            error: (failure) => {
                this.saving.set(false);
                // Kept in the dialog, where the manifest can still be fixed.
                this.manifestError.set(this.refusal(failure, 'report_plugins.error_save'));
            }
        });
    }

    // --- Approve -------------------------------------------------------------------------------------

    approve(plugin: ReportPlugin, manifest: ReportPluginManifestView): void {
        this.busy.set(manifest.digest);
        this.error.set(null);
        this.api.approveReportManifest(plugin.id, manifest.digest).subscribe({
            next: (updated) => {
                this.busy.set(null);
                this.replace(updated);
                this.notice.set(
                    this.i18n.t('report_plugins.approved_notice', {
                        id: updated.id,
                        digest: shortDigest(manifest.digest)
                    })
                );
            },
            error: (failure) => {
                this.busy.set(null);
                this.error.set(this.refusal(failure, 'report_plugins.error_approve'));
            }
        });
    }

    // --- Enable, disable -----------------------------------------------------------------------------

    setEnabled(plugin: ReportPlugin, enabled: boolean): void {
        this.busy.set(plugin.id);
        this.error.set(null);
        this.api.setReportPluginEnabled(plugin.id, enabled).subscribe({
            next: (updated) => {
                this.busy.set(null);
                this.replace(updated);
                this.notice.set(
                    this.i18n.t(enabled ? 'report_plugins.enabled_notice' : 'report_plugins.disabled_notice', {
                        id: updated.id
                    })
                );
            },
            error: (failure) => {
                this.busy.set(null);
                this.error.set(this.refusal(failure, 'report_plugins.error_enable'));
            }
        });
    }

    // --- Withdraw ------------------------------------------------------------------------------------

    openWithdrawal(plugin: ReportPlugin, manifest: ReportPluginManifestView): void {
        this.withdrawalText.set('');
        this.withdrawalError.set(null);
        this.withdrawing.set({ plugin, manifest });
    }

    closeWithdrawal(): void {
        this.withdrawing.set(null);
    }

    withdrawalLength(): number {
        return this.withdrawalText().trim().length;
    }

    withdraw(): void {
        const target = this.withdrawing();
        if (!target) return;
        this.withdrawalBusy.set(true);
        this.withdrawalError.set(null);
        this.api
            .withdrawReportManifest(target.plugin.id, target.manifest.digest, this.withdrawalText().trim())
            .subscribe({
                next: (updated) => {
                    this.withdrawalBusy.set(false);
                    this.withdrawing.set(null);
                    this.replace(updated);
                    this.notice.set(
                        this.i18n.t('report_plugins.withdrawn_notice', {
                            id: updated.id,
                            digest: shortDigest(target.manifest.digest)
                        })
                    );
                },
                error: (failure) => {
                    this.withdrawalBusy.set(false);
                    this.withdrawalError.set(this.refusal(failure, 'report_plugins.error_withdraw'));
                }
            });
    }

    // --- The export schema, for plugin authors -------------------------------------------------------

    downloadSchema(): void {
        this.error.set(null);
        this.api.downloadExportSchema(EXPORT_MAJOR).subscribe({
            next: (response) => saveDocument(response, `vectispire-project-export-v${EXPORT_MAJOR}.schema.json`),
            error: () => this.error.set(this.i18n.t('report_plugins.error_schema'))
        });
    }
}
