package com.asmolabs.zanshin.common.scanning;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The rules Zanshin ships, materialised where a scanner can read them.
 *
 * <p><b>They live in the jar and the scanners need files.</b> Semgrep and gitleaks run as sibling
 * containers with the workspace bind-mounted, and a bind mount is resolved by the Docker
 * <em>daemon</em>: a path inside Zanshin's own jar does not exist as far as it is concerned.
 * Decision 0006 records the same conclusion for the workspace copy.
 *
 * <p><b>Before this class the path was {@code Path.of("rules")}</b> — relative to whatever
 * directory the process happened to start in. No such directory exists in the repository, in the
 * jar, or in the container image, so <em>every</em> repository scan failed at rule placement with
 * "could not place rules from rules". Container scans were unaffected, which is why it went
 * unnoticed: they run the dependency step alone and never place a rule.
 *
 * <p><b>The gitleaks configuration is the part that matters most.</b> Without it the scanner
 * falls back to a `.gitleaks.toml` inside the repository being scanned — written by whoever is
 * being audited — and an empty file with a universal allowlist switches detection off with no
 * error at all.
 */
public final class BundledRules {

    /** Kept in step with `src/main/resources/rules/` by {@code BundledRulesTest}. */
    private static final List<String> FILES =
            List.of("gitleaks/gitleaks.toml", "semgrep/python/dangerous-eval.yaml");

    private static final String ROOT = "/rules/";

    private BundledRules() {}

    /**
     * Copies the bundled tree to a directory and returns it.
     *
     * <p>Done once at startup rather than per scan: the content never changes while the process
     * runs, and unpacking it for every scan would be work with no possible different outcome.
     */
    public static Path materialise() {
        try {
            return materialise(Files.createTempDirectory("zanshin-bundled-rules-"));
        } catch (IOException failed) {
            throw new UncheckedIOException("Could not create a directory for the bundled rules", failed);
        }
    }

    public static Path materialise(Path into) {
        try {
            for (String file : FILES) {
                Path target = into.resolve(file);
                Files.createDirectories(target.getParent());
                try (InputStream source = BundledRules.class.getResourceAsStream(ROOT + file)) {
                    if (source == null) {
                        // A packaging mistake, and one that would otherwise surface as a scan
                        // that "found nothing" — the worst possible symptom for a secrets rule.
                        throw new IllegalStateException(
                                "Bundled rule " + file + " is missing from the jar. Zanshin cannot scan a "
                                        + "repository without it: gitleaks would fall back to a configuration "
                                        + "supplied by the repository being scanned.");
                    }
                    Files.copy(source, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
            return into;
        } catch (IOException failed) {
            throw new UncheckedIOException("Could not unpack the bundled rules to " + into, failed);
        }
    }

    /** The files this jar is expected to carry, for a test that keeps the list honest. */
    public static List<String> expected() {
        return FILES;
    }
}
