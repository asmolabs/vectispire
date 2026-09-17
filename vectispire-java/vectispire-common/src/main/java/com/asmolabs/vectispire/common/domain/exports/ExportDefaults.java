package com.asmolabs.vectispire.common.domain.exports;

/**
 * What an exported document says about the tool that wrote it, when nobody configured it.
 *
 * <h2>Why this is not "1.0.0"</h2>
 *
 * <p>It was, in three places at once, while the signed jar was {@code 0.9.0} and the npm workspace
 * claimed {@code 1.0.0} for a third reason. <b>A VEX or CSAF document names the tool that produced
 * it</b>, and a document announcing a version nobody can obtain is unreconcilable with the artefact
 * somebody verified — in the one file an assessor actually opens.
 *
 * <p>The deployment supplies the real value through {@code vectispire.exports.tool-version}, so
 * this constant is only reached when configuration is missing. That it is reachable at all is why
 * it has to be right: a fallback that lies is worse than one that is absent, because nothing about
 * the document says it was a fallback.
 *
 * <p>{@code ExportVersionTest} keeps it in step with {@code gradle.properties} and with
 * {@code application.yaml}. A version repeated in four places drifts; the test is what makes the
 * repetition safe rather than merely tidy.
 */
final class ExportDefaults {

    /** Tracks {@code version=} in {@code vectispire-java/gradle.properties}. */
    static final String TOOL_VERSION = "0.9.0";

    private ExportDefaults() {}
}
