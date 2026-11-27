import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '../../core/api-error';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ScanDocuments, type ScanDocument } from '../../shared/scan-documents';
import { RepositoriesPage } from './repositories-page';

/**
 * A repository's latest SBOM, without going through its scans: the scan page offered it, and the CLI's
 * `sbom --repo-id`, but not the screen where the repository is. **The dialog names the scan the
 * documents come from** before offering them, and says so when it is not the newest completed one —
 * an SBOM handed over as "latest" that is a month older than the last scan is a wrong inventory.
 */
@Component({
    selector: 'app-sbom-dialog',
    imports: [DatePipe, RouterLink, ButtonModule, DialogModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './sbom-dialog.html'
})
export class SbomDialog {
    private readonly i18n = inject(I18nService);
    private readonly scanDocuments = inject(ScanDocuments);
    protected readonly page = inject(RepositoriesPage);

    /** The scan to download from, or null while looking or when there is none. */
    protected readonly found = computed(() => {
        const lookup = this.page.sbomLookup();
        return lookup?.state === 'found' ? lookup : null;
    });

    /** The document being saved, so its button spins and a second click does not start another. */
    protected readonly saving = signal<ScanDocument | null>(null);
    protected readonly downloadError = signal<string | null>(null);

    download(kind: ScanDocument): void {
        const scan = this.found()?.scan;
        if (!scan) return;
        this.saving.set(kind);
        this.downloadError.set(null);
        this.scanDocuments.save(kind, scan.id).subscribe({
            next: () => this.saving.set(null),
            error: (response: unknown) => {
                this.saving.set(null);
                this.downloadError.set(messageOf(response, this.i18n.t('repositories.sbom_error_download')));
            }
        });
    }

    close(): void {
        this.page.sbomVisible.set(false);
        this.downloadError.set(null);
    }
}
