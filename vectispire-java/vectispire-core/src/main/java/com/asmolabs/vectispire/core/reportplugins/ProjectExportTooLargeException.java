package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportBounds;
import java.util.Map;

/**
 * An export over its bounds, refused rather than cut short (decision 0035 §1): 409 {@code
 * project-export-too-large}, with the part that exceeded, how many it held and the bound, as members a
 * client reads without parsing the sentence.
 *
 * <p>A conflict, not a 400: the request is right, the project is too large today, and the same request
 * succeeds once its backlog or its inventory is back under the bound.
 */
public class ProjectExportTooLargeException extends ConflictException {

    private static final long serialVersionUID = 1L;

    public ProjectExportTooLargeException(ProjectExportBounds.Exceeded exceeded) {
        super(exceeded.sentence(), "project-export-too-large",
                Map.of("part", exceeded.part(), "found", exceeded.found(), "limit", exceeded.limit()));
    }
}
