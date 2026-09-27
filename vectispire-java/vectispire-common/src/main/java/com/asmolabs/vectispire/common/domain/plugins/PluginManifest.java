package com.asmolabs.vectispire.common.domain.plugins;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * What a plugin is: an image pinned by digest, the languages it reads, how it is called, and what it
 * is allowed beyond the closed shape every scanner runs in.
 *
 * <p><b>Declared by the platform governor, executed by whoever scans</b> — the built-in worker or a
 * remote agent. The task names a manifest by its {@link #digest()}, and the executor refuses one
 * whose content does not hash to it, so two executors cannot run two versions of a plugin under one
 * name (the {@code rulesHash} argument of {@code ScanTask}, applied to code).
 *
 * <h2>What the plugin is given, and what it is not</h2>
 *
 * <p>The analysed tree, read-only, at {@value #SOURCE}; one empty writable directory,
 * {@value #OUTPUT}, where it writes {@link #output()}; no network unless {@link #network()} says so
 * with a reason; no Docker socket, no capability, a read-only root, {@code noexec} scratch, the
 * scanner limits' memory, process and CPU ceilings, and the workspace owner's uid rather than root.
 * The arguments are a list handed to the image's entrypoint — no shell — with {@value #SOURCE_PLACEHOLDER}
 * and {@value #OUTPUT_PLACEHOLDER} replaced by those two paths.
 *
 * <p><b>Nothing here widens the confinement.</b> The timeout can only be shorter than the scanner
 * limits'; memory, processes and CPU are not negotiable per plugin. The one widening is the network,
 * and it is the governor's, written down with its justification in the audit log.
 *
 * @param id the plugin's identity, in every issue's fingerprint: renaming it resolves and recreates
 *     the plugin's whole backlog. A new image version keeps the id and keeps the triage
 * @param exitCodes the codes meaning "analysed" — findings or not. Anything else fails the step and
 *     leaves the plugin's issues untouched (decision 0007)
 * @param networkJustification required with {@code network}, refused without it
 * @param timeoutSeconds {@code null} for the scanner limits' timeout, otherwise shorter than it
 * @param signature who the image must be signed by, or {@code null} for an image trusted by its
 *     digest alone — which an executor may refuse ({@code VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED})
 */
public record PluginManifest(
        String id,
        String name,
        String image,
        Set<Language> languages,
        List<String> arguments,
        String output,
        @JsonProperty("exit_codes") Set<Integer> exitCodes,
        boolean network,
        @JsonProperty("network_justification") String networkJustification,
        @JsonProperty("timeout_seconds") Integer timeoutSeconds,
        PluginSignature signature) {

    /** Where the analysed tree is mounted, read-only. */
    public static final String SOURCE = "/repo/source";

    /** The one writable directory, empty at start, discarded with the workspace. */
    public static final String OUTPUT = "/repo/output";

    public static final String SOURCE_PLACEHOLDER = "{source}";
    public static final String OUTPUT_PLACEHOLDER = "{output}";

    public static final String DEFAULT_OUTPUT = "results.sarif";

    /** The scanner limits' timeout: a plugin may ask for less, never for more. */
    public static final int MAX_TIMEOUT_SECONDS = 900;

    static final int MIN_TIMEOUT_SECONDS = 10;
    static final int MAX_ID = 40;
    static final int MAX_NAME = 100;
    static final int MAX_ARGUMENTS = 32;
    static final int MAX_ARGUMENT = 4_096;
    static final int MAX_EXIT_CODES = 8;
    static final int MIN_JUSTIFICATION = 20;
    static final int MAX_JUSTIFICATION = 500;

    /** A manifest trusting its image by digest alone. */
    public PluginManifest(String id, String name, String image, Set<Language> languages, List<String> arguments,
            String output, Set<Integer> exitCodes, boolean network, String networkJustification, Integer timeoutSeconds) {
        this(id, name, image, languages, arguments, output, exitCodes, network, networkJustification, timeoutSeconds, null);
    }

    /** Absent collections become empty, absent exit codes {@code [0]}, a blank output the default. */
    public PluginManifest {
        languages = languages == null || languages.isEmpty()
                ? Set.of()
                : Collections.unmodifiableSet(EnumSet.copyOf(languages));
        arguments = arguments == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(arguments));
        exitCodes = exitCodes == null || exitCodes.isEmpty()
                ? Set.of(0)
                : Collections.unmodifiableSet(new TreeSet<>(exitCodes));
        output = output == null || output.isBlank() ? DEFAULT_OUTPUT : output.strip();
        id = id == null ? null : id.strip();
        name = name == null ? null : name.strip();
        image = image == null ? null : image.strip();
        networkJustification = networkJustification == null || networkJustification.isBlank()
                ? null
                : networkJustification.strip();
    }

    /**
     * This manifest, or a refusal naming the first thing wrong with it.
     *
     * @throws InvalidPluginException meant to be shown to the governor as it is
     */
    public PluginManifest validated() {
        requireId(id);
        requireText(name, MAX_NAME, "The plugin's name");
        ImageDigest.parse(image);
        if (languages.isEmpty()) {
            throw new InvalidPluginException("A plugin declares the languages it reads, from " + Language.wireNames()
                    + ": it runs only on a repository where one of them is present.");
        }
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
        requireOutput(output);
        if (exitCodes.size() > MAX_EXIT_CODES) {
            throw new InvalidPluginException("A plugin declares at most " + MAX_EXIT_CODES + " exit codes.");
        }
        for (Integer code : exitCodes) {
            if (code == null || code < 0 || code > 255) {
                throw new InvalidPluginException("An exit code is between 0 and 255.");
            }
        }
        if (network) {
            if (networkJustification == null || networkJustification.length() < MIN_JUSTIFICATION
                    || networkJustification.length() > MAX_JUSTIFICATION || hasControl(networkJustification)) {
                throw new InvalidPluginException("A plugin that needs the network says why, in " + MIN_JUSTIFICATION
                        + " to " + MAX_JUSTIFICATION + " characters: every plugin runs with the network cut, "
                        + "and an exception is a decision somebody has to be able to read.");
            }
        } else if (networkJustification != null) {
            throw new InvalidPluginException("A justification is given for a network the plugin does not ask for.");
        }
        if (timeoutSeconds != null && (timeoutSeconds < MIN_TIMEOUT_SECONDS || timeoutSeconds > MAX_TIMEOUT_SECONDS)) {
            throw new InvalidPluginException("The timeout is between " + MIN_TIMEOUT_SECONDS + " and "
                    + MAX_TIMEOUT_SECONDS + " seconds: a plugin may ask for less time than a scanner, never more.");
        }
        if (signature != null) {
            signature.validated();
        }
        return this;
    }

    /**
     * The manifest's identity: what a task names and an executor checks.
     *
     * <p>Every field, in a fixed order, sets sorted by value rather than by enum position, lists
     * joined with a separator no field may contain. A change of anything an executor would do
     * differently — the image, an argument, the network, the signer — is a new digest.
     *
     * <p><b>The signer is appended only when there is one</b>, so a manifest without it hashes as it
     * did before the field existed: every manifest a {@code t_plugin_manifest} row keeps is keyed by
     * that digest, and a changed formula would have left each of them hashing to nothing its task
     * names — served to nobody, every plugin absent until re-registered. The two forms cannot
     * collide: the last field without a signer is the timeout, digits or nothing, and with one it is
     * followed by the signer's fields; no field may contain the separator.
     */
    @JsonIgnore
    public String digest() {
        // `Arrays.asList`, not `List.of`: a justification is null on most manifests.
        List<String> fields = new ArrayList<>(java.util.Arrays.asList(
                "vectispire-plugin-manifest/1",
                id,
                name,
                image,
                languages.stream().map(Language::wireName).sorted().collect(Collectors.joining(",")),
                String.join("\u001f", arguments),
                output,
                exitCodes.stream().sorted().map(String::valueOf).collect(Collectors.joining(",")),
                network ? "network" : "no-network",
                networkJustification,
                timeoutSeconds == null ? "" : String.valueOf(timeoutSeconds)));
        if (signature != null) {
            fields.addAll(signature.digestFields());
        }
        return Digests.sha256Fields(fields.toArray(String[]::new));
    }

    /** The arguments with the two placeholders replaced by the paths the container sees. */
    public List<String> command(String sourcePath, String outputPath) {
        return arguments.stream()
                .map(argument -> argument.replace(SOURCE_PLACEHOLDER, sourcePath).replace(OUTPUT_PLACEHOLDER, outputPath))
                .toList();
    }

    /** The plugin's id checked alone — for a route that names one in its path. */
    public static String requireId(String id) {
        if (id == null || id.length() < 2 || id.length() > MAX_ID) {
            throw new InvalidPluginException("A plugin id is 2 to " + MAX_ID + " characters.");
        }
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            boolean alphanumeric = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
            boolean edge = i == 0 || i == id.length() - 1;
            if (!alphanumeric && (edge || c != '-')) {
                throw new InvalidPluginException("A plugin id is lowercase letters, digits and inner hyphens: "
                        + "it enters every issue's fingerprint and is never renamed.");
            }
        }
        return id;
    }

    private static void requireOutput(String output) {
        if (output.length() > MAX_NAME || output.startsWith(".")) {
            throw new InvalidPluginException("The output is a file name of at most " + MAX_NAME
                    + " characters, not starting with a dot.");
        }
        for (int i = 0; i < output.length(); i++) {
            char c = output.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == '-';
            if (!allowed) {
                throw new InvalidPluginException("The output is a file name in " + OUTPUT
                        + " — letters, digits, dots, hyphens and underscores, no directory.");
            }
        }
    }

    private static void requireText(String value, int max, String what) {
        if (value == null || value.isEmpty()) {
            throw new InvalidPluginException(what + " is required.");
        }
        if (value.length() > max || hasControl(value)) {
            throw new InvalidPluginException(what + " is at most " + max + " characters, with no control character.");
        }
    }

    private static boolean hasControl(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) {
                return true;
            }
        }
        return false;
    }
}
