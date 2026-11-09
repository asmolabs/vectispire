import { ChangeDetectionStrategy, Component, computed, effect, inject, input, untracked } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ChecklistActs } from './checklist-acts';
import { ChecklistAsMeasuredPanel } from './checklist-as-measured';
import { ChecklistContactsPanel } from './checklist-contacts';
import { ChecklistHeader } from './checklist-header';
import { ChecklistLineCard } from './checklist-line';
import { ChecklistOpening } from './checklist-opening';
import { ChecklistPage } from './checklist-page';
import { ChecklistRefusal } from './checklist-refusal';
import { ChecklistRevisions } from './checklist-revisions';

/**
 * A project's security checklist (decision 0032 §4, §5, §8), answered by people.
 *
 * **Read by whoever sees the whole project, and by nobody else.** The server answers 404 to a
 * reader who sees part of it — the words of an absent project — and the screen says exactly that,
 * without guessing which of the two it is.
 *
 * **Writes are offered to the roles that cause effects** (`@RequiresWriteAccount`); the auditor and
 * the platform governor read.
 *
 * The screen is the frame: what it shows and how it writes is `ChecklistPage`, provided here so each
 * visit starts from nothing, and each part — the header, the acts, the lines, the revisions — is a
 * component of its own reading that state.
 */
@Component({
    selector: 'app-project-checklist',
    imports: [
        RouterLink,
        CardModule,
        MessageModule,
        TranslatePipe,
        ChecklistActs,
        ChecklistAsMeasuredPanel,
        ChecklistContactsPanel,
        ChecklistHeader,
        ChecklistLineCard,
        ChecklistOpening,
        ChecklistRefusal,
        ChecklistRevisions
    ],
    providers: [ChecklistPage],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './project-checklist.html'
})
export class ProjectChecklist {
    protected readonly page = inject(ChecklistPage);

    /** The route's `:projectId`, bound by `withComponentInputBinding`. */
    readonly projectId = input.required<string>();
    private readonly id = computed(() => Number(this.projectId()));

    constructor() {
        // An effect rather than a call in the constructor: a signal input is not bound yet there.
        effect(() => {
            const id = this.id();
            untracked(() => this.page.load(id));
        });
    }
}
