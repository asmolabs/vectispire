package com.asmolabs.vectispire.core.checklists.web;

import com.asmolabs.vectispire.core.checklists.ChecklistConflict;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * The 409s of a checklist route that name their lines, as the OpenAPI document describes them — never
 * built: {@code ApiExceptionHandler} writes the RFC 9457 problem, and a {@code ChecklistConflict}'s
 * members join it as extension members. Declared so that the {@code lines} member has a schema: a
 * client read it as untyped data and restated both shapes by hand.
 */
final class ChecklistRefusals {

    private ChecklistRefusals() {}

    /** {@code urn:vectispire:problem:checklist-incomplete}: the lines kept from a submission or a sign-off. */
    @Schema(name = "ChecklistIncompleteProblem", description = "A checklist-incomplete refusal: an RFC 9457 problem "
            + "whose lines member names each line kept from the submission or the sign-off, with its problems.")
    record Incomplete(String type, String title, int status, String detail, String instance,
            List<ChecklistConflict.IncompleteLine> lines) {}

    /**
     * {@code urn:vectispire:problem:checklist-measurement-contradicted} and {@code …-measurement-changed}:
     * the lines whose measurement refused the write.
     */
    @Schema(name = "ChecklistMeasurementProblem", description = "A checklist-measurement-contradicted or "
            + "checklist-measurement-changed refusal: an RFC 9457 problem whose lines member names each line with "
            + "its answer, what the rule finds now and, for a sign-off, what it found at the submission.")
    record Measured(String type, String title, int status, String detail, String instance,
            List<ChecklistConflict.MeasuredLine> lines) {}

    /**
     * {@code urn:vectispire:problem:checklist-template-unrenderable} and {@code checklist-version-unrenderable}:
     * the cells a sign-off writes that carry a formula other cells depend on, found by the trial rendering.
     */
    @Schema(name = "ChecklistUnrenderableProblem", description = "A checklist-template-unrenderable or "
            + "checklist-version-unrenderable refusal: an RFC 9457 problem whose cells member names each cell a "
            + "sign-off writes that carries a formula other cells depend on — cell, kind shared or array, range.")
    record Unrenderable(String type, String title, int status, String detail, String instance,
            List<ChecklistConflict.UnrenderableCell> cells) {}
}
