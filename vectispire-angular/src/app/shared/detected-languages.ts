import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { TagModule } from '@openng/optimus-ui/tag';
import { TranslatePipe } from '../core/i18n/translate.pipe';

/**
 * The languages a scan counted in a tree, as small tags.
 *
 * **Unknown and empty are two sentences.** `null` means nobody has counted — no completed scan since
 * the count existed, or the walk stopped at its bound — and `[]` means counted, and nothing found. An
 * empty cell for both would tell the reader of an unscanned repository that it holds no language,
 * which is the one thing that is not known about it.
 *
 * Wire names as they are (`java`, `typescript`): the plugin manifests declare them that way, and the
 * reader compares one list with the other.
 */
@Component({
    selector: 'app-detected-languages',
    standalone: true,
    imports: [TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `
        @if (languages(); as known) {
            @if (known.length === 0) {
                <span class="text-sm text-muted-color" data-testid="languages-none">{{
                    'detected_languages.none' | translate
                }}</span>
            } @else {
                <span class="inline-flex flex-wrap gap-1" data-testid="languages">
                    @for (language of known; track language) {
                        <p-tag severity="secondary" styleClass="text-xs" [value]="language" />
                    }
                </span>
            }
        } @else {
            <span class="text-sm text-muted-color" data-testid="languages-unknown">{{
                'detected_languages.unknown' | translate
            }}</span>
        }
    `
})
export class DetectedLanguages {
    /** `undefined` too: a server from before the count sends nothing, which is as unknown as `null`. */
    readonly languages = input.required<readonly string[] | null | undefined>();
}
