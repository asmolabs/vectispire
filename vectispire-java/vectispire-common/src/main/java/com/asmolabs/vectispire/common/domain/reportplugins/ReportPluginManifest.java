package com.asmolabs.vectispire.common.domain.reportplugins;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.plugins.ImageDigest;
import com.asmolabs.vectispire.common.domain.plugins.InvalidPluginException;
import com.asmolabs.vectispire.common.domain.plugins.ManifestRules;
import com.asmolabs.vectispire.common.domain.plugins.PluginSignature;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * What a report plugin is (decision 0035 §2): an image pinned by digest, the export major it reads, how it is
 * called, the one file it writes and of which type, and who must have signed it.
 *
 * <p><b>Narrower than a scanner plugin's manifest</b>, deliberately. There is no {@code network} field: a
 * renderer needs nothing from the network, and its input is the most aggregated confidential document the
 * platform builds — an exception would be a declared exfiltration channel. There is no exit-code list: a
 * renderer exits {@code 0} or failed. And the {@link #signature()} is <b>required</b>, with no waiver: the
 * platform signs what the plugin writes, and signing the output of an image nobody vouched for would lend the
 * installation's key to whoever could push to a registry.
 *
 * <p><b>No secret, and nothing that rotates.</b> A private image is pulled and verified with the control
 * plane's Docker configuration (§5): the manifest names no credential, so its digest covers nothing that
 * changes when a password does.
 *
 * <p>What it shares with a scanner plugin's manifest is code, not a table: the image rule ({@link
 * ImageDigest}), the signer ({@link PluginSignature}), the id, name, argument and output rules ({@link
 * ManifestRules}).
 *
 * @param exportSchema the major of {@code vectispire-project-export} the plugin reads
 * @param output the one file the plugin writes in {@value #OUTPUT}, ending with the media type's extension
 * @param maxOutputBytes the ceiling of that file, at most {@value #MAX_OUTPUT_BYTES}; absent, {@value
 *     #DEFAULT_OUTPUT_BYTES}
 * @param timeoutSeconds {@value #MIN_TIMEOUT_SECONDS} to {@value #MAX_TIMEOUT_SECONDS}; absent, {@value
 *     #DEFAULT_TIMEOUT_SECONDS}
 */
public record ReportPluginManifest(
        String id,
        String name,
        String image,
        @JsonProperty("export_schema") Integer exportSchema,
        List<String> arguments,
        String output,
        @JsonProperty("media_type") ReportMediaType mediaType,
        @JsonProperty("max_output_bytes") Long maxOutputBytes,
        @JsonProperty("timeout_seconds") Integer timeoutSeconds,
        PluginSignature signature) {

    /** Where the export is mounted, read-only, holding {@code export.json} alone. */
    public static final String INPUT = "/report/input";

    /** The one writable directory — 0017 §10's bounded output, with this manifest's ceiling. */
    public static final String OUTPUT = "/report/output";

    public static final String INPUT_PLACEHOLDER = "{input}";
    public static final String OUTPUT_PLACEHOLDER = "{output}";

    public static final long DEFAULT_OUTPUT_BYTES = 20L * 1024 * 1024;
    public static final long MAX_OUTPUT_BYTES = 50L * 1024 * 1024;
    public static final int DEFAULT_TIMEOUT_SECONDS = 120;
    public static final int MIN_TIMEOUT_SECONDS = 10;
    public static final int MAX_TIMEOUT_SECONDS = 300;

    /** Absent lists become empty, absent bounds their defaults, so a manifest hashes as it will run. */
    public ReportPluginManifest {
        id = id == null ? null : id.strip();
        name = name == null ? null : name.strip();
        image = image == null ? null : image.strip();
        arguments = arguments == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(arguments));
        output = output == null || output.isBlank() ? null : output.strip();
        maxOutputBytes = maxOutputBytes == null ? DEFAULT_OUTPUT_BYTES : maxOutputBytes;
        timeoutSeconds = timeoutSeconds == null ? DEFAULT_TIMEOUT_SECONDS : timeoutSeconds;
    }

    /** The plugin's id checked alone — for a route that names one in its path. */
    public static String requireId(String id) {
        return ManifestRules.requireId(id, "documents in the world name it, so it is never renamed nor reused.");
    }

    /**
     * This manifest, or a refusal naming the first thing wrong with it.
     *
     * @throws InvalidPluginException meant to be shown to the governor as it is
     */
    public ReportPluginManifest validated() {
        requireId(id);
        ManifestRules.requireText(name, ManifestRules.MAX_NAME, "The plugin's name");
        ImageDigest.parse(image);
        if (exportSchema == null || exportSchema < 1) {
            throw new InvalidPluginException("A report plugin declares the major of " + ProjectExportSchema.NAME
                    + " it reads (export_schema): it is never handed a document of another.");
        }
        ManifestRules.requireArguments(arguments);
        if (mediaType == null) {
            throw new InvalidPluginException("A report plugin declares the type of the file it writes (media_type), "
                    + "one of " + ReportMediaType.wireNames() + ".");
        }
        if (output == null) {
            throw new InvalidPluginException("A report plugin names the one file it writes in " + OUTPUT + " (output).");
        }
        ManifestRules.requireOutputName(output, OUTPUT);
        // A bare extension starts with a dot, which the name rule above already refused.
        if (!output.toLowerCase(Locale.ROOT).endsWith(mediaType.extension())) {
            throw new InvalidPluginException("The output of a plugin producing " + mediaType.wireName()
                    + " is a file name ending with " + mediaType.extension() + ": the name is what a recipient opens.");
        }
        if (maxOutputBytes < 1 || maxOutputBytes > MAX_OUTPUT_BYTES) {
            throw new InvalidPluginException("The output's ceiling (max_output_bytes) is 1 to " + MAX_OUTPUT_BYTES
                    + " bytes.");
        }
        if (timeoutSeconds < MIN_TIMEOUT_SECONDS || timeoutSeconds > MAX_TIMEOUT_SECONDS) {
            throw new InvalidPluginException("The timeout is between " + MIN_TIMEOUT_SECONDS + " and "
                    + MAX_TIMEOUT_SECONDS + " seconds.");
        }
        if (signature == null) {
            throw new InvalidPluginException("A report plugin declares who signed its image — keyless (identity and "
                    + "issuer) or a public key — and there is no waiver: the platform signs what it produces.");
        }
        signature.validated();
        return this;
    }

    /**
     * The manifest's identity: what an approval, a run and a document's provenance name.
     *
     * <p>Every field, in a fixed order, lists joined with a separator no field may contain, under a prefix
     * of its own — a report plugin's manifest and a scanner plugin's can never hash alike. Called on a
     * {@link #validated()} manifest.
     */
    @JsonIgnore
    public String digest() {
        List<String> fields = new ArrayList<>(List.of(
                "vectispire-report-plugin-manifest/1",
                id,
                name,
                image,
                String.valueOf(exportSchema),
                String.join("\u001f", arguments),
                output,
                mediaType.wireName(),
                String.valueOf(maxOutputBytes),
                String.valueOf(timeoutSeconds)));
        fields.addAll(signature.digestFields());
        return Digests.sha256Fields(fields.toArray(String[]::new));
    }

    /** The arguments with the two placeholders replaced by the paths the container sees. */
    public List<String> command(String inputPath, String outputPath) {
        return arguments.stream()
                .map(argument -> argument.replace(INPUT_PLACEHOLDER, inputPath).replace(OUTPUT_PLACEHOLDER, outputPath))
                .toList();
    }
}
