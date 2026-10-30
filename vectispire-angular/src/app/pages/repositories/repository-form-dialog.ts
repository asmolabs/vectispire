import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { messageOf } from '../../core/api-error';
import { TargetsApi } from '../../core/api/targets.api';
import type { AssetTier, MonitoredRepository } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ScheduleFields } from '../../shared/schedule-fields';
import {
    CredentialKind,
    httpsHost,
    TARGET_ALREADY_REGISTERED,
    urlCarriesSecret,
    urlTransport
} from './repository-model';
import { RepositoriesPage } from './repositories-page';

/**
 * A repository added or edited: its URL, tier, branch, name, sub-path and agent label, the one
 * credential its transport allows, and its schedule. A form whose URL is required; the server's refusal
 * — a scheme it refuses, a cron it cannot read, a target already filed — is said in the dialog.
 *
 * **What the form shows is what it sends.** A credential the URL no longer allows falls back to "none"
 * and a token for another host is dropped as the URL is typed, so the server's refusal never names
 * something the operator cannot see.
 */
@Component({
    selector: 'app-repository-form-dialog',
    imports: [
        FormsModule,
        ButtonModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        SelectModule,
        TranslatePipe,
        ScheduleFields
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './repository-form-dialog.html'
})
export class RepositoryFormDialog {
    private readonly i18n = inject(I18nService);
    private readonly targetsApi = inject(TargetsApi);
    protected readonly page = inject(RepositoriesPage);

    readonly formError = signal<string | null>(null);
    readonly formVisible = signal(false);
    /** The row being edited, or null when the dialog is adding one. */
    readonly editing = signal<MonitoredRepository | null>(null);
    protected readonly sshKeyOptions = this.page.sshKeyOptions;
    protected readonly defaultScanMinutes = this.page.defaultScanMinutes;
    protected readonly saving = this.page.saving;

    form = {
        url: '',
        branch: 'main',
        name: '',
        subPath: '',
        requiredAgentLabel: '',
        scanIntervalMinutes: null as number | null,
        scanCron: '',
        scanManualOnly: false,
        // The empty string is "no key", and it is a value the server acts on rather than one it
        // ignores — see the comment on the payload in `submit`.
        sshKeyId: '',
        credentialKind: 'none' as CredentialKind,
        httpsTokenId: '',
        tier: 'TIER_2_BUSINESS_OPERATIONAL' as string
    };

    /**
     * The credential kinds the URL allows.
     *
     * **Read from the URL rather than offered in full and refused on save**: an SSH key is useless
     * to an https:// clone and a token to an SSH one, and the server refuses both combinations.
     * Methods, not `computed`: `form` is a plain object bound with `ngModel`, and a computed over
     * it would never recompute.
     */
    credentialKinds(): { label: string; value: CredentialKind }[] {
        const transport = urlTransport(this.form.url);
        return [
            { label: this.i18n.t('repositories.credential_none'), value: 'none' as const },
            ...(transport !== 'https'
                ? [{ label: this.i18n.t('repositories.credential_ssh'), value: 'ssh' as const }]
                : []),
            ...(transport !== 'ssh'
                ? [{ label: this.i18n.t('repositories.credential_https'), value: 'https' as const }]
                : [])
        ];
    }

    /**
     * The tokens bound to the URL's host — the only ones the server would accept here (decision
     * 0022). While the host does not parse yet, all of them, so the choice is not empty mid-typing.
     */
    httpsTokenOptions(): { label: string; value: string }[] {
        const host = httpsHost(this.form.url);
        return this.page
            .gitTokens()
            .filter((token) => host === null || token.host.toLowerCase() === host)
            .map((token) => ({ label: `${token.name} (${token.host})`, value: token.id }));
    }

    /** The host the URL names, for the "no token for this host" hint. */
    urlHost(): string | null {
        return httpsHost(this.form.url);
    }

    urlCarriesSecret(): boolean {
        return urlCarriesSecret(this.form.url);
    }

    /**
     * Keeps the credential shown consistent with the URL being typed.
     *
     * A kind the new URL does not allow falls back to "none", and a token bound to another host is
     * dropped: **what the form shows is what it sends.** Leaving a hidden choice in place would
     * send a credential the screen no longer displays, and the server's refusal would then name
     * something the operator cannot see.
     */
    onUrlChange(): void {
        if (!this.credentialKinds().some((kind) => kind.value === this.form.credentialKind)) {
            this.form.credentialKind = 'none';
        }
        if (
            this.form.httpsTokenId &&
            !this.httpsTokenOptions().some((option) => option.value === this.form.httpsTokenId)
        ) {
            this.form.httpsTokenId = '';
        }
    }

    openForm(repository?: MonitoredRepository): void {
        this.editing.set(repository ?? null);
        this.form = repository
            ? {
                  url: repository.url,
                  branch: repository.branch,
                  name: repository.name ?? '',
                  subPath: repository.subPath ?? '',
                  requiredAgentLabel: repository.requiredAgentLabel ?? '',
                  scanIntervalMinutes: repository.scanIntervalMinutes,
                  scanCron: repository.scanCron ?? '',
                  scanManualOnly: repository.scanManualOnly ?? false,
                  sshKeyId: repository.sshKeyId ?? '',
                  credentialKind: repository.httpsTokenId ? 'https' : repository.sshKeyId ? 'ssh' : 'none',
                  httpsTokenId: repository.httpsTokenId ?? '',
                  tier: repository.tier ?? 'TIER_2_BUSINESS_OPERATIONAL'
              }
            : {
                  url: '',
                  branch: 'main',
                  name: '',
                  subPath: '',
                  requiredAgentLabel: '',
                  scanIntervalMinutes: null,
                  scanCron: '',
                  scanManualOnly: false,
                  sshKeyId: '',
                  credentialKind: 'none',
                  httpsTokenId: '',
                  tier: 'TIER_2_BUSINESS_OPERATIONAL'
              };
        // A stored key beside an https:// URL predates the rule and would be refused on save; the
        // form shows "none" instead of a blank choice. The token is not checked here — the list of
        // tokens may not have arrived yet, and a hint names a mismatch anyway.
        if (!this.credentialKinds().some((kind) => kind.value === this.form.credentialKind)) {
            this.form.credentialKind = 'none';
        }
        this.formError.set(null);
        this.formVisible.set(true);
    }

    submit(): void {
        const editing = this.editing();
        // **Empty string and not `undefined` when editing.** On the create path an absent field
        // means "no value"; on the update path the server reads absent as "leave alone", so a
        // field the operator cleared has to be sent as empty or the clearing is silently
        // dropped — the form would show it gone and the next scan would disagree.
        const blank = editing ? '' : undefined;
        // Only the credential of the chosen kind is sent; the other is cleared, since the server
        // refuses a repository holding both and a switch from key to token is one save.
        const kind = this.form.credentialKind;
        const body = {
            url: this.form.url.trim(),
            branch: this.form.branch.trim() || 'main',
            name: this.form.name.trim() || blank,
            subPath: this.form.subPath.trim() || blank,
            required_agent_label: this.form.requiredAgentLabel.trim() || blank,
            tier: this.form.tier as AssetTier,
            // **Zero, not `undefined`, when the field was cleared on the update path.** The server
            // reads absent as "leave alone", so `undefined` would keep the old interval while the
            // form showed nothing — the scans would carry on at the old pace. Zero returns the
            // target to the installation's default; switching rescans off is `scanManualOnly`.
            scanIntervalMinutes: this.form.scanIntervalMinutes ?? (editing ? 0 : undefined),
            // Always sent, empty included: the empty string is the only value the update path
            // distinguishes from "leave alone", so it is the only way to remove an expression.
            scanCron: this.form.scanCron.trim(),
            // Always sent: the dialog shows the switch, so what it shows is what is saved.
            scanManualOnly: this.form.scanManualOnly,
            // Same rule, same reason. Sending `undefined` when the operator picked "no key" would
            // leave the old key attached while this form showed none — and the next clone would
            // use a credential the screen says is gone.
            sshKeyId: kind === 'ssh' ? this.form.sshKeyId : '',
            // Absent on create when there is none, empty on update to detach one: the server reads
            // absent as "leave alone" there, which would keep a token this form shows as removed.
            https_token_id: (kind === 'https' ? this.form.httpsTokenId : '') || blank
        };

        this.page.saving.set(true);
        const call = editing
            ? this.targetsApi.updateRepository(editing.id, body)
            : this.targetsApi.createRepository(body);
        call.subscribe({
            next: () => {
                this.page.saving.set(false);
                this.formVisible.set(false);
                this.editing.set(null);
                this.page.reload();
            },
            error: (response) => {
                this.page.saving.set(false);
                // The server's message is the one that knows *why* — scheme refused, host
                // missing. Replacing it with a generic "error" would lose that.
                this.formError.set(
                    this.alreadyRegistered(response) ??
                        messageOf(response, this.i18n.t(editing ? 'repositories.error_save' : 'repositories.error_add'))
                );
            }
        });
    }

    /**
     * The same repository, branch and sub-path already filed — said in the reader's language, naming
     * the target when the server named it.
     *
     * The server sends the existing target's id only to a caller who sees it, and this screen lists
     * exactly what the caller sees, so the name is read from the list rather than from the English
     * sentence. Without an id — or one the list has not loaded — the sentence names nothing, as the
     * server's does: a target the caller cannot see is not revealed by its name here either.
     */
    private alreadyRegistered(failure: unknown): string | null {
        const problem = (failure as { error?: { type?: unknown; existingRepositoryId?: unknown } } | null)?.error;
        if (problem?.type !== TARGET_ALREADY_REGISTERED) return null;
        const existing = this.page.repositories().find((repository) => repository.id === problem.existingRepositoryId);
        return existing
            ? this.i18n.t('repositories.already_registered', { name: existing.displayName })
            : this.i18n.t('repositories.already_registered_unnamed');
    }
}
