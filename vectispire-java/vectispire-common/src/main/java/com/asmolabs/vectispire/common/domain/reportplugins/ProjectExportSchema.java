package com.asmolabs.vectispire.common.domain.reportplugins;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Optional;

/**
 * The published schema of {@link ProjectExport}, one JSON Schema (draft 2020-12) file per major, kept
 * beside the code that produces it (decision 0035 §1).
 *
 * <p><b>The file is the contract</b>, and the records follow it: a test validates every export the suite
 * builds against it, and another pins its SHA-256, so a change to either side is a reviewed change to the
 * other — and to {@link #VERSION}, by the rule the schema states: a minor adds, a major is anything else.
 */
public final class ProjectExportSchema {

    /** What every export states in its first field. */
    public static final String NAME = "vectispire-project-export";

    /** The version this build produces, {@code MAJOR.MINOR}; its major is {@link #MAJOR}. */
    public static final String VERSION = "1.0";

    public static final int MAJOR = 1;

    private ProjectExportSchema() {}

    /** Where a major's schema lives on the classpath. */
    static String resource(int major) {
        return "/schemas/project-export/v" + major + ".schema.json";
    }

    /**
     * The schema of a major this build produces, as the file's bytes; empty for any other — a major retired,
     * or not written yet. Only {@link #MAJOR} exists so far: when a second major appears, the previous one is
     * produced beside it for a release line (decision 0035 §1) and both are found here.
     */
    public static Optional<byte[]> of(int major) {
        if (major != MAJOR) {
            return Optional.empty();
        }
        try (InputStream in = ProjectExportSchema.class.getResourceAsStream(resource(major))) {
            if (in == null) {
                throw new IllegalStateException("The schema of the project export's major " + major
                        + " is not on the classpath: " + resource(major));
            }
            return Optional.of(in.readAllBytes());
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
    }
}
