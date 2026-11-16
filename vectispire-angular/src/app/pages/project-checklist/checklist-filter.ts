import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { MultiSelectModule } from '@openng/optimus-ui/multiselect';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ChecklistPage } from './checklist-page';
import { NO_FILTER } from './checklist-model';

/** One profile the lines can be narrowed to: its key, as the lines name it, and the column's spelling. */
export interface ProfileOption {
    value: string;
    label: string;
}

/**
 * Narrows the lines to the people they are to be asked of — the profiles of the template's contact column,
 * "PO", "BA", "Arch" — and to those still to fill in, so that each person finds their own lines among a
 * hundred (decision 0044).
 *
 * **"My lines" are the lines of the profiles linked to the reader**, as the contacts card links them: the
 * same link that sends the weekly reminder, so the lines a reminder names are the lines this shows.
 *
 * **A view, never a judgement**: the header still counts every line, and a submission still weighs them all.
 * The bar says how many lines it hides, so a filtered page cannot pass for a finished one.
 */
@Component({
    selector: 'app-checklist-filter',
    imports: [FormsModule, ButtonModule, CheckboxModule, MultiSelectModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './checklist-filter.html'
})
export class ChecklistFilterBar {
    protected readonly page = inject(ChecklistPage);

    /**
     * The profiles the shown revision's lines name, in the order they first name them, each in the
     * column's spelling the contacts card gives it — the key itself while that list is not read, or for a
     * profile a newer version no longer names.
     */
    readonly options = computed<ProfileOption[]>(() => {
        const labels = new Map((this.page.contacts()?.profiles ?? []).map((one) => [one.profile, one.label] as const));
        const keys = new Set<string>();
        for (const line of this.page.view()?.lines ?? []) {
            for (const key of line.profiles ?? []) keys.add(key);
        }
        return [...keys].map((key) => ({ value: key, label: labels.get(key) ?? key }));
    });

    /** The profiles linked to the reader that the shown lines name; empty when none is. */
    readonly mine = computed(() => {
        const named = new Set(this.options().map((option) => option.value));
        return (this.page.contacts()?.profiles ?? [])
            .filter((one) => one.mine && named.has(one.profile))
            .map((one) => one.profile);
    });

    readonly total = computed(() => this.page.view()?.lines.length ?? 0);
    readonly shown = computed(() => this.page.shownLines().length);
    readonly active = computed(() => {
        const filter = this.page.lineFilter();
        return filter.profiles.length > 0 || filter.toFill;
    });

    setProfiles(profiles: string[] | null): void {
        this.page.lineFilter.update((filter) => ({ ...filter, profiles: profiles ?? [] }));
    }

    setToFill(toFill: boolean): void {
        this.page.lineFilter.update((filter) => ({ ...filter, toFill }));
    }

    showMine(): void {
        this.setProfiles(this.mine());
    }

    clear(): void {
        this.page.lineFilter.set(NO_FILTER);
    }
}
