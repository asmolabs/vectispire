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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
 * @param schemaVersion the manifest format, {@code MAJOR.MINOR} as the report plugins' export states
 *     its own: a minor adds an optional field, a major may change what a field means. Absent is
 *     {@value #UNVERSIONED}
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
        PluginSignature signature,
        @JsonProperty("schema_version") String schemaVersion) {

    /**
     * The newest format this build reads, and the one a governor may register. A newer minor is refused
     * at registration — its fields would be dropped unread here and stored as if never written — but run
     * by an executor, which needs no field it does not know: a minor's fields are optional, and one that
     * is set enters the {@link #digest()}, so an executor that does not know it refuses the manifest
     * there.
     */
    public static final String SCHEMA_VERSION = "1.0";

    /**
     * What a manifest stating no version is read as: the format every manifest had before the field
     * existed, which every stored row and every governor's file written until then is. <b>Pinned, not
     * {@link #SCHEMA_VERSION}</b>: when a major 2 comes, a manifest without the field was still written
     * for 1, and reading it as 2 would change what its fields mean under the digest it is run by.
     */
    public static final String UNVERSIONED = "1.0";

    /** The one major this build reads; a manifest of another is refused, never read field by field. */
    static final int SCHEMA_MAJOR = 1;

    private static final Pattern VERSION = Pattern.compile("(0|[1-9][0-9]{0,3})\\.(0|[1-9][0-9]{0,3})");

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
    static final int MAX_ID = ManifestRules.MAX_ID;
    static final int MAX_NAME = ManifestRules.MAX_NAME;
    static final int MAX_ARGUMENTS = ManifestRules.MAX_ARGUMENTS;
    static final int MAX_ARGUMENT = ManifestRules.MAX_ARGUMENT;
    static final int MAX_EXIT_CODES = 8;
    static final int MIN_JUSTIFICATION = 20;
    static final int MAX_JUSTIFICATION = 500;

    /** A manifest trusting its image by digest alone. */
    public PluginManifest(String id, String name, String image, Set<Language> languages, List<String> arguments,
            String output, Set<Integer> exitCodes, boolean network, String networkJustification, Integer timeoutSeconds) {
        this(id, name, image, languages, arguments, output, exitCodes, network, networkJustification, timeoutSeconds, null);
    }

    /** A manifest stating no version, read as {@value #UNVERSIONED}. */
    public PluginManifest(String id, String name, String image, Set<Language> languages, List<String> arguments,
            String output, Set<Integer> exitCodes, boolean network, String networkJustification, Integer timeoutSeconds,
            PluginSignature signature) {
        this(id, name, image, languages, arguments, output, exitCodes, network, networkJustification, timeoutSeconds,
                signature, null);
    }

    /**
     * Absent collections become empty, absent exit codes {@code [0]}, a blank output the default, an
     * absent version {@value #UNVERSIONED}.
     */
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
        schemaVersion = schemaVersion == null || schemaVersion.isBlank() ? UNVERSIONED : schemaVersion.strip();
    }

    /**
     * This manifest, or a refusal naming the first thing wrong with it.
     *
     * @throws InvalidPluginException meant to be shown to the governor as it is
     */
    public PluginManifest validated() {
        // First: under another major the fields below may not mean what they are checked for.
        int major = major(schemaVersion);
        if (major != SCHEMA_MAJOR) {
            throw new InvalidPluginException("The manifest is schema_version " + schemaVersion + "; this Vectispire "
                    + "reads major " + SCHEMA_MAJOR + " only, and a manifest of another major may mean something else "
                    + "by the same field.");
        }
        requireId(id);
        requireText(name, MAX_NAME, "The plugin's name");
        ImageDigest.parse(image);
        if (languages.isEmpty()) {
            throw new InvalidPluginException("A plugin declares the languages it reads, from " + Language.wireNames()
                    + ": it runs only on a repository where one of them is present.");
        }
        ManifestRules.requireArguments(arguments);
        ManifestRules.requireOutputName(output, OUTPUT);
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
     * {@link #validated()}, and a version this build knows field by field — what a governor may register.
     *
     * <p>Only registration asks it. A field of a newer minor would be dropped unread by this build and
     * the manifest stored without it, a confinement or a choice the governor wrote silently gone; an
     * executor is spared the check because such a field, once set, is in the digest it verifies.
     */
    public PluginManifest validatedForRegistration() {
        validated();
        if (minor(schemaVersion) > minor(SCHEMA_VERSION)) {
            throw new InvalidPluginException("The manifest is schema_version " + schemaVersion + "; this Vectispire "
                    + "knows " + SCHEMA_VERSION + " and would drop what a later version added. Register it on a "
                    + "release that knows it, or state " + SCHEMA_VERSION + ".");
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
     *
     * <p><b>The version is appended only outside major {@value #SCHEMA_MAJOR}</b>, for the same reason:
     * a 1.x manifest hashes as it did before the field existed, so an agent of the release before it —
     * which ignores the field and hashes the rest (decision 0043 §2) — still finds the digest its task
     * names. A minor needs nothing more, since the field it adds hashes itself when it is set. A manifest
     * of another major does hash differently, and that agent refuses it rather than run it misread.
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
        if (!VERSION.matcher(schemaVersion).matches() || major(schemaVersion) != SCHEMA_MAJOR) {
            fields.add("schema_version " + schemaVersion);
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
        return ManifestRules.requireId(id, "it enters every issue's fingerprint and is never renamed.");
    }

    private static int major(String version) {
        return Integer.parseInt(parsed(version).group(1));
    }

    private static int minor(String version) {
        return Integer.parseInt(parsed(version).group(2));
    }

    private static Matcher parsed(String version) {
        Matcher matcher = VERSION.matcher(version);
        if (!matcher.matches()) {
            throw new InvalidPluginException("A manifest's schema_version is MAJOR.MINOR, such as " + SCHEMA_VERSION
                    + ", or absent for " + UNVERSIONED + ".");
        }
        return matcher;
    }

    private static void requireText(String value, int max, String what) {
        ManifestRules.requireText(value, max, what);
    }

    private static boolean hasControl(String value) {
        return ManifestRules.hasControl(value);
    }
}
