package com.asmolabs.vectispire.common.domain.issues;

import java.util.Locale;

/**
 * The key naming the tool a plugin or imported finding belongs to — a fingerprint input, and the
 * scope a clean run resolves (see {@link IssueFingerprint}).
 *
 * <p><b>A data contract.</b> The prefixes, the separator and the lowercasing below are in every such
 * issue's identity. The two prefixes are also the provenance an auditor reads: {@code plugin:} was
 * analysed by Vectispire, {@code import:} was declared by a report somebody uploaded.
 */
public final class ToolKeys {

    public static final String PLUGIN_PREFIX = "plugin:";
    public static final String IMPORT_PREFIX = "import:";

    /** The widest key: a 40-character source, a separator and a 100-character tool name after the prefix. */
    public static final int MAX_LENGTH = 200;

    private ToolKeys() {}

    /** {@code plugin:<id>}: the image and its version stay out, so a new version keeps the triage. */
    public static String plugin(String pluginId) {
        return PLUGIN_PREFIX + require(pluginId, "plugin id");
    }

    /**
     * {@code import:<source>/<tool>}, the tool name as SARIF's {@code tool.driver.name}, stripped and
     * lowercased: "ESLint" and "eslint" from one source are one tool, and its version stays out.
     */
    public static String imported(String sourceSlug, String toolName) {
        return IMPORT_PREFIX + require(sourceSlug, "source") + "/" + require(toolName, "tool name").toLowerCase(Locale.ROOT);
    }

    private static String require(String value, String what) {
        String stripped = value == null ? "" : value.strip();
        if (stripped.isEmpty()) {
            throw new IllegalArgumentException("A tool key needs a " + what + ".");
        }
        return stripped;
    }
}
