import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ReportImports } from '../../shared/report-imports';
import { SarifImports } from '../../shared/sarif-imports';
import { RepositoriesPage } from './repositories-page';

/** A repository's imports — coverage, tests, SARIF: read-only, the uploads come from CI with a declared key. */
@Component({
    selector: 'app-imports-dialog',
    imports: [DialogModule, TranslatePipe, ReportImports, SarifImports],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './imports-dialog.html'
})
export class ImportsDialog {
    protected readonly page = inject(RepositoriesPage);
}
