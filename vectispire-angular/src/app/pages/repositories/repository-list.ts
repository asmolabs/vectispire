import { ChangeDetectionStrategy, Component, computed, inject, output } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DataViewModule } from '@openng/optimus-ui/dataview';
import type { MonitoredRepository } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { DetectedLanguages } from '../../shared/detected-languages';
import { LastScanTag } from '../../shared/last-scan';
import { scheduleLabel } from '../../shared/schedule-fields';
import { RepositoriesPage } from './repositories-page';

/**
 * The monitored repositories, a card each and paged on the client — a forge import registers hundreds
 * at once. Each card says what its schedule is, because a target nobody rescans looks monitored until
 * somebody reads the date of its last scan; the schedules are worked out once per list or language.
 */
@Component({
    selector: 'app-repository-list',
    imports: [RouterLink, ButtonModule, DataViewModule, TranslatePipe, DetectedLanguages, LastScanTag],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './repository-list.html'
})
export class RepositoryList {
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(RepositoriesPage);

    /** A repository to edit: the page opens its form on it. */
    readonly edit = output<MonitoredRepository>();

    protected readonly schedules = computed(() => {
        // The labels go through `i18n.t`, which reads the bundle: a language switch recomputes them.
        return Object.fromEntries(
            this.page.repositories().map((repository) => [repository.id, scheduleLabel(repository, this.i18n)])
        );
    });
}
