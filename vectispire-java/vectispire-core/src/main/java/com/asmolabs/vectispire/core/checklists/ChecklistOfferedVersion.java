package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.checklists.InvalidTemplateException;
import com.asmolabs.vectispire.common.domain.checklists.WrittenFormulaException;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;
import java.util.List;

/**
 * A published template version a project's checklist may be opened on or moved to — what the person
 * opening one picks from, without the governance reading the templates' own routes require.
 *
 * <p><b>A version no sign-off could fill in is listed, and says so</b> ({@code unrenderable}, null on every
 * other), rather than left out. Such a version was published before the publication's trial rendering
 * (0.10.0 and earlier), and opening a checklist on it, or moving one to it, is refused; hidden, it would
 * vanish from the list of a project whose checklist stands on it, and from no screen of the managers who
 * see it published — and nobody would learn which cells to correct, nor whom to ask.
 *
 * @param unrenderable why no checklist opens on, or moves to, this version; null when one may
 */
public record ChecklistOfferedVersion(
        String templateSlug,
        String templateName,
        int ordinal,
        String label,
        long itemCount,
        boolean offersNotApplicable,
        Instant publishedAt,
        Unrenderable unrenderable) {

    /**
     * Why the trial rendering refused a version: the refusal's own sentence, and the cells at fault when
     * the reason is a formula in a cell a sign-off writes — the members a {@code
     * checklist-version-unrenderable} refusal carries, so that a screen says it once for both.
     *
     * @param detail the trial rendering's reason, in English
     * @param cells each written cell carrying a formula other cells depend on; empty for another reason
     */
    @Schema(name = "ChecklistVersionUnrenderable")
    public record Unrenderable(String detail, List<ChecklistConflict.UnrenderableCell> cells) {

        static Unrenderable of(InvalidTemplateException refused) {
            return new Unrenderable(refused.getMessage(), refused instanceof WrittenFormulaException written
                    ? written.cells().stream().map(ChecklistConflict.UnrenderableCell::of).toList()
                    : List.of());
        }
    }
}
