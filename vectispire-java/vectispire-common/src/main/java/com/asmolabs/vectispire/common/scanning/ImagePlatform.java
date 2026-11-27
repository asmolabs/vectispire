package com.asmolabs.vectispire.common.scanning;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The platform an image is exported for: what the save asks the daemon for, and the check that the archive it
 * wrote holds that platform and no other.
 *
 * <p><b>The save used to name no platform</b>, and the pull did. On a daemon with the containerd image store
 * (Docker Desktop, and Docker Engine 29's default) a save without one wants the <em>host's</em> variant of a
 * multi-architecture image: on an arm64 host it failed ({@code content digest … not found}) when only the amd64
 * variant had been pulled, and <b>exported the arm64 variant in silence</b> when both were there — the
 * inventory and the vulnerabilities of an architecture nobody deploys, recorded as the image's.
 *
 * <p>The save takes a {@code platform} since API 1.48, as a JSON-encoded OCI platform; an older daemon ignores
 * the parameter. So the archive is checked whatever the daemon: every configuration its {@code manifest.json}
 * names must be of the platform asked for, or the step fails (absent, decision 0007) — another architecture
 * is never scanned in its place. Normalized as containerd normalizes, so {@code linux/arm64/v8} asked and
 * {@code arm64} found agree.
 *
 * <p>Held to {@code vectispire-rust/reference/container/image-platform/} ({@code ImagePlatformReferenceSetTest}),
 * which the Rust agent's {@code image_archive} reads: the two agents ask and refuse alike.
 */
final class ImagePlatform {

    /** What containerd's {@code platforms.Parse} admits in a component; it also keeps the query's JSON plain. */
    private static final Pattern COMPONENT = Pattern.compile("[A-Za-z0-9_-]+");

    static final int MANIFEST_LIMIT = 1024 * 1024;
    static final int CONFIG_LIMIT = 4 * 1024 * 1024;

    private static final ObjectMapper JSON =
            new ObjectMapper().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    /** One platform, normalized; an empty variant is "any" when asked, "none" when found. */
    record Platform(String os, String architecture, String variant) {

        static Platform of(String os, String architecture, String variant) {
            String o = lower(os);
            String a = lower(architecture);
            String v = lower(variant);
            if (o.equals("macos")) {
                o = "darwin";
            }
            switch (a) {
                case "i386" -> {
                    a = "386";
                    v = "";
                }
                case "x86_64", "x86-64", "amd64" -> {
                    a = "amd64";
                    if (v.equals("v1")) {
                        v = "";
                    }
                }
                case "aarch64", "arm64" -> {
                    a = "arm64";
                    if (v.equals("8") || v.equals("v8")) {
                        v = "";
                    }
                }
                case "armhf" -> {
                    a = "arm";
                    v = "v7";
                }
                case "armel" -> {
                    a = "arm";
                    v = "v6";
                }
                case "arm" -> {
                    switch (v) {
                        case "", "7" -> v = "v7";
                        case "5", "6", "8" -> v = "v" + v;
                        default -> {}
                    }
                }
                default -> {}
            }
            return new Platform(o, a, v);
        }

        /** {@code os/architecture[/variant]}, a component nobody wrote shown as {@code unknown}. */
        String format() {
            String shown = (os.isEmpty() ? "unknown" : os) + "/" + (architecture.isEmpty() ? "unknown" : architecture);
            return variant.isEmpty() ? shown : shown + "/" + variant;
        }

        /** The save's {@code platform} parameter: the components are {@link #COMPONENT}s, so nothing to escape. */
        String saveQuery() {
            return "{\"os\":\"" + os + "\",\"architecture\":\"" + architecture + "\""
                    + (variant.isEmpty() ? "" : ",\"variant\":\"" + variant + "\"") + "}";
        }

        boolean admits(Platform found) {
            return os.equals(found.os)
                    && architecture.equals(found.architecture)
                    && (variant.isEmpty() || variant.equals(found.variant));
        }
    }

    /** The archive's files, by name: {@link ImageArchive#entry} on disk, a map in the reference set. */
    @FunctionalInterface
    interface Entries {
        Optional<byte[]> entry(String name, int limit) throws ImageArchive.Unreadable;
    }

    private ImagePlatform() {}

    /**
     * The platform {@code platform} asks for; empty when it is null or blank — the task named none, the daemon
     * chooses at the pull and at the save alike, and there is nothing to check against.
     *
     * @throws IllegalStateException if it is not {@code os/architecture[/variant]}
     */
    static Optional<Platform> requested(String platform) {
        if (platform == null || platform.isBlank()) {
            return Optional.empty();
        }
        String[] parts = platform.split("/", -1);
        if (parts.length < 2 || parts.length > 3) {
            throw malformed(platform);
        }
        for (String part : parts) {
            if (!COMPONENT.matcher(part).matches()) {
                throw malformed(platform);
            }
        }
        return Optional.of(Platform.of(parts[0], parts[1], parts.length == 3 ? parts[2] : ""));
    }

    private static IllegalStateException malformed(String platform) {
        return new IllegalStateException("The image platform \"" + platform + "\" is not of the form "
                + "os/architecture[/variant]; no image is exported for a platform its archive cannot be checked against.");
    }

    /**
     * Why the archive of {@code reference}, exported for {@code platform} ({@code requested} once parsed), may not
     * be scanned — empty when every image it holds is of that platform.
     */
    static Optional<String> refusal(String reference, String platform, Platform requested, Entries archive) {
        List<Platform> found = new ArrayList<>();
        try {
            for (String config : configurations(archive)) {
                JsonNode document = read(archive.entry(config, CONFIG_LIMIT)
                        .orElseThrow(() -> new ImageArchive.Unreadable("the configuration " + config + " is not in it")));
                if (document == null || !document.isObject()) {
                    throw new ImageArchive.Unreadable("the configuration " + config + " is not a JSON object");
                }
                found.add(Platform.of(text(document, "os"), text(document, "architecture"), text(document, "variant")));
            }
        } catch (ImageArchive.Unreadable unreadable) {
            return Optional.of("The archive exported for " + reference + " could not be checked for " + platform + ": "
                    + unreadable.getMessage() + ". It is not scanned unchecked.");
        }
        if (found.stream().allMatch(requested::admits)) {
            return Optional.empty();
        }
        return Optional.of("The Docker daemon exported " + reference + " as "
                + String.join(", ", found.stream().map(Platform::format).toList()) + " where " + platform
                + " was asked: a daemon selects the platform of a save from API 1.48 on, and another architecture "
                + "is not scanned in place of the one asked for.");
    }

    /** The {@code Config} of every image {@code manifest.json} lists, in its order; at least one. */
    private static List<String> configurations(Entries archive) throws ImageArchive.Unreadable {
        JsonNode manifest = read(archive.entry("manifest.json", MANIFEST_LIMIT)
                .orElseThrow(() -> new ImageArchive.Unreadable("it holds no manifest.json")));
        if (manifest == null || !manifest.isArray() || manifest.isEmpty()) {
            throw new ImageArchive.Unreadable("its manifest.json is not a list of images");
        }
        List<String> configs = new ArrayList<>();
        for (JsonNode image : manifest) {
            JsonNode config = image.get("Config");
            if (!image.isObject() || config == null || !config.isTextual() || config.asText().isEmpty()) {
                throw new ImageArchive.Unreadable("an image of its manifest.json names no configuration");
            }
            configs.add(config.asText());
        }
        return configs;
    }

    /** The document, or null when the bytes are not one JSON value (and nothing after it). */
    private static JsonNode read(byte[] bytes) {
        try {
            return JSON.readTree(bytes);
        } catch (IOException notJson) {
            return null;
        }
    }

    private static String text(JsonNode document, String field) {
        JsonNode value = document.get(field);
        return value != null && value.isTextual() ? value.asText() : "";
    }

    /** ASCII only, as the Rust side lowers: a locale's rules must not decide what a platform is. */
    private static String lower(String text) {
        StringBuilder lowered = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            lowered.append(c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c);
        }
        return lowered.toString();
    }
}
