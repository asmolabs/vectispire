import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { TooltipModule } from '@openng/optimus-ui/tooltip';
import { messageOf } from '../../core/api-error';
import { ForgesApi } from '../../core/api/forges.api';
import type { EncryptionState, ForgeConnection, Schema } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { keyFor } from '../../core/i18n/literal-keys';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { encryptionBadge, type EncryptionBadge } from '../../shared/encryption-state';
import {
    CA_PROBLEM_KEYS,
    CREDENTIAL_KIND_KEYS,
    DISCOVERY_STATE_KEYS,
    EDITION_KEYS,
    caCertificateCount,
    caPemProblem,
    daysLeft,
    expiryState,
    isCloudAddress,
    type ExpiryState
} from '../../shared/forge-words';

const FORGE_TOKEN_HINT_KEYS = {
    current: 'forges.encryption.current_hint',
    previous_key: 'forges.encryption.previous_key_hint',
    unreadable: 'forges.encryption.unreadable_hint'
} as const satisfies Record<EncryptionState, string>;

type ForgeKindChoice = 'gitlab' | 'github';
type CaMode = 'keep' | 'replace' | 'unpin';

interface CreateForm {
    kind: ForgeKindChoice;
    name: string;
    baseUrl: string;
    owner: string;
    token: string;
    internalNetwork: boolean;
    caPem: string;
}

interface EditForm {
    name: string;
    internalNetwork: boolean;
    caMode: CaMode;
    caPem: string;
}

/**
 * The forge connections (decision 0037 §2): a read-only token per forge, probed before it is kept, from which
 * repositories are discovered and imported.
 *
 * **The probe's refusal is the most useful sentence on this page.** A connection is refused for what the
 * forge said of its token — rejected, a scope outside the read-only allow-list, a server too old, an
 * address the outbound guard blocks — and the server says which in `detail`; the form keeps everything but
 * the token's echo so that the fix is one field, not the whole form.
 *
 * **Tokens live in the form while the dialog is open, and no longer**: closing any dialog forgets what was
 * typed, as the HTTPS tokens screen does.
 */
@Component({
    selector: 'app-forge-connections',
    imports: [
        DatePipe,
        FormsModule,
        RouterLink,
        ButtonModule,
        CardModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        TagModule,
        TextareaModule,
        TooltipModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './forge-connections.html'
})
export class ForgeConnections {
    private readonly api = inject(ForgesApi);
    private readonly i18n = inject(I18nService);

    readonly stateKeys = DISCOVERY_STATE_KEYS;

    readonly connections = signal<ForgeConnection[]>([]);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);

    readonly createVisible = signal(false);
    readonly createError = signal<string | null>(null);
    form: CreateForm = ForgeConnections.emptyForm();

    readonly editing = signal<ForgeConnection | null>(null);
    readonly editError = signal<string | null>(null);
    editForm: EditForm = { name: '', internalNetwork: false, caMode: 'keep', caPem: '' };

    readonly rotating = signal<ForgeConnection | null>(null);
    readonly rotateError = signal<string | null>(null);
    rotateToken = '';

    readonly deleting = signal<ForgeConnection | null>(null);

    private static emptyForm(): CreateForm {
        return { kind: 'gitlab', name: '', baseUrl: '', owner: '', token: '', internalNetwork: false, caPem: '' };
    }

    constructor() {
        this.reload();
    }

    reload(): void {
        this.loading.set(true);
        this.api.forgeConnections().subscribe({
            next: (connections) => {
                this.connections.set(connections);
                this.error.set(null);
                this.loading.set(false);
            },
            error: (response) => {
                this.error.set(messageOf(response, this.i18n.t('forges.connections.error_load')));
                this.loading.set(false);
            }
        });
    }

    edition(connection: ForgeConnection): string {
        const key = keyFor(EDITION_KEYS, connection.edition);
        return key ? this.i18n.t(key) : connection.edition;
    }

    credentialKind(connection: ForgeConnection): string | null {
        if (!connection.credentialKind) return null;
        const key = keyFor(CREDENTIAL_KIND_KEYS, connection.credentialKind);
        return key ? this.i18n.t(key) : connection.credentialKind;
    }

    badge(state: string): EncryptionBadge {
        return encryptionBadge(this.i18n, state, FORGE_TOKEN_HINT_KEYS);
    }

    expiry(connection: ForgeConnection): ExpiryState {
        return expiryState(connection.tokenExpiresAt, new Date());
    }

    daysLeft(connection: ForgeConnection): number {
        return connection.tokenExpiresAt ? daysLeft(connection.tokenExpiresAt, new Date()) : 0;
    }

    /** What a pasted CA looks like, in words: a problem, the count it holds, or nothing yet. */
    caFeedback(pem: string): { problem: string | null; count: number } {
        const problem = caPemProblem(pem);
        return {
            problem: problem ? this.i18n.t(CA_PROBLEM_KEYS[problem]) : null,
            count: problem || !pem.trim() ? 0 : caCertificateCount(pem)
        };
    }

    cloud(): boolean {
        return isCloudAddress(this.form.baseUrl);
    }

    /** A connection whose address is a vendor's cloud cannot be internal nor pin a CA. */
    editCloud(): boolean {
        const connection = this.editing();
        return connection !== null && isCloudAddress(connection.baseUrl);
    }

    openCreate(): void {
        this.form = ForgeConnections.emptyForm();
        this.createError.set(null);
        this.createVisible.set(true);
    }

    closeCreate(): void {
        this.form = ForgeConnections.emptyForm();
        this.createVisible.set(false);
    }

    create(): void {
        const cloud = this.cloud();
        if (!cloud && caPemProblem(this.form.caPem)) return;
        const request: Schema<'ForgeConnectionRequest'> = {
            kind: this.form.kind,
            name: this.form.name.trim(),
            // Blank is the vendor's cloud: github.com or gitlab.com, as the server reads it.
            baseUrl: this.form.baseUrl.trim() || undefined,
            owner: this.form.kind === 'github' ? this.form.owner.trim() || undefined : undefined,
            token: this.form.token.trim(),
            internalNetwork: cloud ? false : this.form.internalNetwork,
            caPem: cloud ? undefined : this.form.caPem.trim() || undefined
        };
        this.saving.set(true);
        this.createError.set(null);
        this.api.createForgeConnection(request).subscribe({
            next: () => {
                this.saving.set(false);
                this.closeCreate();
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                // The token is cleared, the rest kept: the refusal names one field to fix, and a token the
                // forge rejected is not one to send twice by pressing the button again.
                this.form.token = '';
                this.createError.set(messageOf(response, this.i18n.t('forges.connections.error_create')));
            }
        });
    }

    openEdit(connection: ForgeConnection): void {
        this.editForm = {
            name: connection.name,
            internalNetwork: connection.internalNetwork,
            caMode: 'keep',
            caPem: ''
        };
        this.editError.set(null);
        this.editing.set(connection);
    }

    closeEdit(): void {
        this.editing.set(null);
    }

    saveEdit(): void {
        const connection = this.editing();
        if (!connection) return;
        if (this.editForm.caMode === 'replace' && (caPemProblem(this.editForm.caPem) || !this.editForm.caPem.trim())) {
            return;
        }
        const change: Schema<'ForgeConnectionChange'> = {};
        const name = this.editForm.name.trim();
        if (name !== connection.name) change.name = name;
        if (this.editForm.internalNetwork !== connection.internalNetwork) {
            change.internalNetwork = this.editForm.internalNetwork;
        }
        // Absent keeps the pinned CA, blank unpins it: the two must not be confused, or saving a name
        // would drop the CA and the next discovery would meet the internal certificate unverified.
        if (this.editForm.caMode === 'replace') change.caPem = this.editForm.caPem.trim();
        if (this.editForm.caMode === 'unpin') change.caPem = '';
        if (Object.keys(change).length === 0) {
            this.closeEdit();
            return;
        }
        this.saving.set(true);
        this.editError.set(null);
        this.api.updateForgeConnection(connection.id, change).subscribe({
            next: () => {
                this.saving.set(false);
                this.closeEdit();
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.editError.set(messageOf(response, this.i18n.t('forges.connections.error_update')));
            }
        });
    }

    openRotate(connection: ForgeConnection): void {
        this.rotateToken = '';
        this.rotateError.set(null);
        this.rotating.set(connection);
    }

    closeRotate(): void {
        this.rotateToken = '';
        this.rotating.set(null);
    }

    rotate(): void {
        const connection = this.rotating();
        if (!connection) return;
        this.saving.set(true);
        this.rotateError.set(null);
        this.api.replaceForgeConnectionToken(connection.id, this.rotateToken.trim()).subscribe({
            next: () => {
                this.saving.set(false);
                this.closeRotate();
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.rotateToken = '';
                this.rotateError.set(messageOf(response, this.i18n.t('forges.connections.error_rotate')));
            }
        });
    }

    askDelete(connection: ForgeConnection): void {
        this.deleting.set(connection);
    }

    confirmDelete(): void {
        const connection = this.deleting();
        if (!connection) return;
        this.saving.set(true);
        this.api.deleteForgeConnection(connection.id).subscribe({
            next: () => {
                this.saving.set(false);
                this.deleting.set(null);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                this.deleting.set(null);
                this.error.set(messageOf(response, this.i18n.t('forges.connections.error_delete')));
            }
        });
    }
}
