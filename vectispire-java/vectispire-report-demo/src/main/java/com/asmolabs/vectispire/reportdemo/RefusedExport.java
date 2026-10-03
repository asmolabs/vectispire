package com.asmolabs.vectispire.reportdemo;

/**
 * An export this plugin will not render, and the exit code that says why.
 *
 * <p>Two kinds, because the fix differs. <b>Unsupported</b> is a document of another schema or another
 * major: the plugin is the wrong one for it, and the platform should not have handed it over (decision
 * 0035 §1 — a manifest's {@code export_schema} is checked before a run). <b>Unreadable</b> is a document
 * that claims to be an export of this major and is not one: not JSON, or a part missing. Neither is
 * rendered as far as it goes — a summary of half an export would be signed by the platform as a summary
 * of the project.
 */
final class RefusedExport extends Exception {

    private static final long serialVersionUID = 1L;

    /** The exit code a plugin reports; the platform reads only zero or not (0035 §2), a person reads the rest. */
    enum Kind {
        UNREADABLE(1),
        UNSUPPORTED(2);

        private final int exitCode;

        Kind(int exitCode) {
            this.exitCode = exitCode;
        }

        int exitCode() {
            return exitCode;
        }
    }

    private final Kind kind;

    RefusedExport(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    Kind kind() {
        return kind;
    }
}
