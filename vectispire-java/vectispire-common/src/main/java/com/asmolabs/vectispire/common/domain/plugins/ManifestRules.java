package com.asmolabs.vectispire.common.domain.plugins;

import java.util.List;

/**
 * The rules a container plugin's manifest is held to whatever the plugin does — its name, its argument
 * list, its output's file name — shared by the scanner plugins' manifest ({@link PluginManifest}, decision
 * 0017) and the report plugins' ({@code ReportPluginManifest}, decision 0035).
 *
 * <p><b>Shared as code, not as rows.</b> Decision 0035 §4 keeps the two registries in tables of their own
 * — every rule of each would otherwise be conditional on the other's kind — and shares what both enforce
 * identically. A second copy of the argument rule would be the one that drifted: the day one side admits a
 * control character the other refuses, a manifest separator could be smuggled into one digest.
 */
public final class ManifestRules {

    public static final int MAX_ID = 40;
    public static final int MAX_NAME = 100;
    public static final int MAX_ARGUMENTS = 32;
    public static final int MAX_ARGUMENT = 4_096;

    private ManifestRules() {}

    /**
     * A plugin's id: lowercase letters, digits and inner hyphens, 2 to {@value #MAX_ID} characters — the key
     * of its registry, never renamed nor reused.
     *
     * @param why what the id is part of, which is why it never changes — the end of the refusal's sentence
     * @throws InvalidPluginException naming the rule
     */
    public static String requireId(String id, String why) {
        if (id == null || id.length() < 2 || id.length() > MAX_ID) {
            throw new InvalidPluginException("A plugin id is 2 to " + MAX_ID + " characters.");
        }
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            boolean alphanumeric = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
            boolean edge = i == 0 || i == id.length() - 1;
            if (!alphanumeric && (edge || c != '-')) {
                throw new InvalidPluginException("A plugin id is lowercase letters, digits and inner hyphens: " + why);
            }
        }
        return id;
    }

    /**
     * Each argument is one argv entry handed to the image's entrypoint, no shell on Vectispire's side.
     *
     * @throws InvalidPluginException naming the bound broken
     */
    public static void requireArguments(List<String> arguments) {
        if (arguments.size() > MAX_ARGUMENTS) {
            throw new InvalidPluginException("A plugin takes at most " + MAX_ARGUMENTS + " arguments.");
        }
        for (String argument : arguments) {
            // A newline or a tab is an ordinary character of an argv entry — a `sh -c` script inside
            // the image has several lines — and no shell on this side reads them. Every other
            // control character is refused, the digest's list separator among them.
            if (argument == null || argument.length() > MAX_ARGUMENT
                    || hasControl(argument.replace('\n', ' ').replace('\t', ' '))) {
                throw new InvalidPluginException("Each argument is a string of at most " + MAX_ARGUMENT
                        + " characters with no control character but a newline or a tab.");
            }
        }
    }

    /**
     * A bare file name in {@code directory}: no path, no leading dot, letters, digits, dots, hyphens and
     * underscores — what the executor reads back as a regular file, never through a link.
     *
     * @throws InvalidPluginException naming the rule
     */
    public static void requireOutputName(String output, String directory) {
        if (output.length() > MAX_NAME || output.startsWith(".")) {
            throw new InvalidPluginException("The output is a file name of at most " + MAX_NAME
                    + " characters, not starting with a dot.");
        }
        for (int i = 0; i < output.length(); i++) {
            char c = output.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == '-';
            if (!allowed) {
                throw new InvalidPluginException("The output is a file name in " + directory
                        + " — letters, digits, dots, hyphens and underscores, no directory.");
            }
        }
    }

    /** Required, bounded, and free of control characters — a name shown on every screen and in the audit log. */
    public static void requireText(String value, int max, String what) {
        if (value == null || value.isEmpty()) {
            throw new InvalidPluginException(what + " is required.");
        }
        if (value.length() > max || hasControl(value)) {
            throw new InvalidPluginException(what + " is at most " + max + " characters, with no control character.");
        }
    }

    public static boolean hasControl(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) {
                return true;
            }
        }
        return false;
    }
}
