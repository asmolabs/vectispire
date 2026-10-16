import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ChecklistsApi } from '../../core/api/checklists.api';
import type {
    ChecklistContact,
    ChecklistContactCandidate,
    ChecklistContacts,
    ChecklistContactWarning
} from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '../../core/latest-request';

// Literal keys, so the i18n check sees each warning's translation (decision 0019); the spec reads each
// against both bundles.
export const WARNING_KEYS = {
    account_gone: 'checklist_contacts.warning_account_gone',
    account_inactive: 'checklist_contacts.warning_account_inactive',
    no_email: 'checklist_contacts.warning_no_email',
    cannot_fill: 'checklist_contacts.warning_cannot_fill'
} as const satisfies Record<ChecklistContactWarning, string>;

/** One choice of a profile's list: an account, by the name the server sent or by its id. */
export interface ContactOption {
    value: number;
    label: string;
}

/**
 * Who each profile of the project's checklist is — a value of its template's contact column, "PO",
 * "Arch" — linked to an account, which is reminded weekly of its lines still to fill in (decision 0044).
 *
 * **A profile linked to nobody, or to an account that would not be reminded, is the CISOs'**: the screen
 * says so beside it, in the server's terms (`warning`), rather than leaving the reader to guess why a
 * reminder never came.
 *
 * Linking is a writer's — the roles that answer the checklist; everyone else reads the list. The accounts
 * offered are the server's candidates: it alone knows who sees the whole project.
 */
@Component({
    selector: 'app-checklist-contacts',
    imports: [FormsModule, CardModule, MessageModule, SelectModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './checklist-contacts.html'
})
export class ChecklistContactsPanel {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    // The edition moves with every answer; an older list must not land over a newer one.
    private readonly readRequest = new LatestRequest();

    readonly projectId = input.required<number>();
    /** `@RequiresWriteAccount`: who may link, and read the candidates. */
    readonly writes = input(false);
    /** The revision's edition on screen: the lines to fill in change with it, so the list is read again. */
    readonly edition = input<number | null>(null);

    readonly contacts = signal<ChecklistContacts | null>(null);
    readonly candidates = signal<ChecklistContactCandidate[]>([]);
    readonly busy = signal(false);
    readonly error = signal<string | null>(null);
    readonly warningKeys = WARNING_KEYS;

    /**
     * Each profile's choices: the candidates, and the account it is linked to when that one is no longer
     * among them — deactivated, gone, moved off the project — so the list still shows who it is linked to.
     */
    readonly options = computed(() => {
        const offered: ContactOption[] = this.candidates().map((candidate) => ({
            value: candidate.accountId,
            label: candidate.name ?? this.i18n.t('checklist_contacts.account_n', { id: candidate.accountId })
        }));
        const byProfile: Record<string, ContactOption[]> = {};
        for (const profile of this.contacts()?.profiles ?? []) {
            const linked = profile.accountId;
            byProfile[profile.profile] =
                linked === null || offered.some((option) => option.value === linked)
                    ? offered
                    : [...offered, { value: linked, label: this.accountLabel(profile) }];
        }
        return byProfile;
    });

    constructor() {
        effect(() => {
            const projectId = this.projectId();
            this.edition();
            untracked(() => this.load(projectId));
        });
        effect(() => {
            const projectId = this.projectId();
            if (!this.writes()) return;
            untracked(() =>
                this.api.checklistContactCandidates(projectId).subscribe({
                    next: (candidates) => this.candidates.set(candidates),
                    error: (failure) =>
                        this.error.set(messageOf(failure, this.i18n.t('checklist_contacts.candidates_failed')))
                })
            );
        });
    }

    /** The linked account as the list names it: its name, or its id when it has none a screen may show. */
    accountLabel(profile: ChecklistContact): string {
        if (profile.accountId === null) return this.i18n.t('checklist_contacts.nobody');
        return profile.accountName ?? this.i18n.t('checklist_contacts.account_n', { id: profile.accountId });
    }

    /** A choice made in a profile's list: another account linked, or — cleared — the profile unlinked. */
    choose(profile: ChecklistContact, accountId: number | null): void {
        if (accountId === profile.accountId) return;
        const projectId = this.projectId();
        const request =
            accountId === null
                ? this.api.unlinkChecklistContact(projectId, profile.profile)
                : this.api.linkChecklistContact(projectId, profile.profile, accountId);
        this.busy.set(true);
        this.error.set(null);
        request.subscribe({
            next: (contacts) => {
                this.contacts.set(contacts);
                this.busy.set(false);
            },
            error: (failure) => {
                this.busy.set(false);
                this.error.set(messageOf(failure, this.i18n.t('checklist_contacts.link_failed')));
                // What the server holds now, rather than the choice it refused.
                this.load(projectId);
            }
        });
    }

    private load(projectId: number): void {
        this.readRequest.run(this.api.checklistContacts(projectId), {
            next: (contacts) => this.contacts.set(contacts),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('checklist_contacts.load_failed')))
        });
    }
}
