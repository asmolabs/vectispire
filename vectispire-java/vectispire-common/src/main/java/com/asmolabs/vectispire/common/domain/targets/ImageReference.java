package com.asmolabs.vectispire.common.domain.targets;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * A container image reference, validated and formatted.
 *
 * <p>The same nature as {@link RepositoryUrl}: the reference is handed to a scanner that pulls
 * it from a registry. An uncontrolled value there pulls an arbitrary image — or, if it
 * contains a space, shifts the container command line's arguments.
 *
 * <p>OCI's grammar is more permissive than what follows. Anything that is not obviously an
 * image is refused, at the price of turning away legitimate exotic forms: <b>the cost of a
 * refusal is a message; the cost of one acceptance too many is not.</b>
 */
public record ImageReference(String registry, String imageName, String tag) {

    private static final Pattern REGISTRY = Pattern.compile("^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\\d{1,5})?$");
    private static final Pattern IMAGE_NAME =
            Pattern.compile("^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$");
    private static final Pattern TAG = Pattern.compile("^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$");
    private static final Pattern DIGEST = Pattern.compile("^sha256:[a-f0-9]{64}$");

    private static final String DIGEST_PREFIX = "sha256:";

    /** Empty if the reference is acceptable, otherwise the message to show. */
    public Optional<String> validate() {
        if (registry != null && !registry.isEmpty() && !REGISTRY.matcher(registry).matches()) {
            return Optional.of("Invalid registry \"" + registry + "\". Expected a host, optionally followed by \":port\".");
        }
        if (imageName == null || imageName.isEmpty()) {
            return Optional.of("The image name is required.");
        }
        if (!IMAGE_NAME.matcher(imageName).matches()) {
            // Upper case is refused by the registry itself, not by us: better to say so at
            // entry than at the first scan, hours later, in a log.
            return Optional.of("Invalid image name \"" + imageName + "\". Lower case, digits, \". _ -\" and \"/\".");
        }
        if (tag == null || tag.isEmpty()) {
            return Optional.of("The tag is required (\"latest\" if nothing else).");
        }
        if (!TAG.matcher(tag).matches() && !DIGEST.matcher(tag).matches()) {
            return Optional.of("Invalid tag \"" + tag + "\". Expected a tag or a \"sha256:…\" digest.");
        }
        return Optional.empty();
    }

    /** The reference as a registry expects it — what is displayed and what is scanned. */
    public String format() {
        String base = registry == null || registry.isEmpty() ? imageName : registry + "/" + imageName;
        // A digest joins with "@", a tag with ":". Getting this wrong produces a reference the
        // registry rejects — at pull time, on the agent, far from here.
        return tag.startsWith(DIGEST_PREFIX) ? base + "@" + tag : base + ":" + tag;
    }

    /**
     * The name shown for this image.
     *
     * <p>The digest is not shortened: this name also serves as a search key and an export
     * label, where the whole value matters. Shortening is a display concern, and it belongs to
     * the display.
     */
    public String displayName() {
        return imageName + ":" + tag;
    }
}
