import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ChecklistPage } from './checklist-page';
import {
    documentSigned,
    isAutomatic,
    PUBLIC_KEY_FILE,
    PUBLIC_KEY_PATH,
    statusLabel,
    statusSeverity
} from './checklist-model';

/**
 * The revision shown: what is answered, where it stands, who moved it through its life — and the
 * document to hand over, signed only as far as the status can say (decision 0032 §10).
 */
@Component({
    selector: 'app-checklist-header',
    imports: [DatePipe, ButtonModule, CardModule, MessageModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './checklist-header.html'
})
export class ChecklistHeader {
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(ChecklistPage);

    /** Served to anybody, so the link works on its own — no session, no request of the page. */
    protected readonly publicKeyPath = PUBLIC_KEY_PATH;
    protected readonly publicKeyFile = PUBLIC_KEY_FILE;
    protected readonly copied = signal(false);

    private readonly status = computed(() => this.page.summary()?.status ?? '');
    protected readonly statusText = computed(() => statusLabel(this.i18n, this.status()));
    protected readonly statusTone = computed(() => statusSeverity(this.status()));
    protected readonly signed = computed(() => documentSigned(this.status()));
    /** Lines whose current answer Vectispire wrote: what the scans filled, at a glance. */
    protected readonly automaticCount = computed(
        () => (this.page.view()?.lines ?? []).filter((line) => isAutomatic(line.answer)).length
    );

    /**
     * The guide's commands for the revision shown, when it is signed off: unpack, then check each entry
     * against the key fetched on its own — `--insecure-ignore-tlog=true` because Vectispire publishes no
     * transparency-log entry, and cosign fails looking for one without it.
     */
    protected readonly verificationCommands = computed(() => {
        const shown = this.page.summary();
        if (!shown || !documentSigned(shown.status)) return null;
        return [
            `curl -fsS -o ${PUBLIC_KEY_FILE} "${window.location.origin}${PUBLIC_KEY_PATH}"`,
            `unzip ${this.page.documentName(shown.revision)}`,
            ...['checklist.xlsx', 'checklist.json'].map(
                (entry) =>
                    `cosign verify-blob --key ${PUBLIC_KEY_FILE} --insecure-ignore-tlog=true --signature ${entry}.sig ${entry}`
            )
        ].join('\n');
    });

    protected copyCommands(commands: string): void {
        void navigator.clipboard.writeText(commands).then(() => {
            this.copied.set(true);
            setTimeout(() => this.copied.set(false), 3000);
        });
    }
}
