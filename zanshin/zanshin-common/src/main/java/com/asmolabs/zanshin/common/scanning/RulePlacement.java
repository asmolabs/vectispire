package com.asmolabs.zanshin.common.scanning;

import com.asmolabs.zanshin.common.domain.rules.RuleSet;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * The rules Zanshin places into a scan's workspace.
 *
 * <p><b>Why copy rather than mount the original directory.</b> Volume paths are resolved by the
 * Docker <em>daemon</em>, not by the process calling it: when Zanshin itself runs in a
 * container with the socket mounted, a directory from its image is invisible to the sibling
 * container. The workspace is the only path both sides see, locally as on a remote agent.
 *
 * <p><b>Why this is a class of its own and not a private method of the runner.</b> Two scanners
 * depend on it — one for its rules, the other for its configuration — and the integration tests
 * exercise them one at a time, without going through the runner. A private method would leave
 * the tests rebuilding this placement by hand, hence diverging from the real path the day it
 * changes.
 */
public final class RulePlacement {

    /** Where the operator's rules land inside the workspace. */
    private static final String OPERATOR_SUBDIR = "operator";

    private final Path bundled;

    /**
     * @param bundled the tree Zanshin ships — {@code semgrep/} and {@code gitleaks/}
     */
    public RulePlacement(Path bundled) {
        this.bundled = bundled;
    }

    /**
     * What an executor calls to obtain a rule set it does not hold.
     *
     * <p>A function rather than an interface with a database behind it: the agent has no
     * database, and this is the seam that lets the same code run on both sides.
     */
    @FunctionalInterface
    public interface RuleSetProvider extends Function<String, List<RuleSet.StoredFile>> {}

    /**
     * Copies the bundled tree into the workspace.
     *
     * <p>Called <b>before any scanner</b>, and not from the step with the most obvious use for
     * it: the secrets scanner's configuration has to be in place even when source analysis is
     * off, otherwise the tool falls back to the scanned repository's own configuration — that
     * is, the target supplies the rules of its own audit.
     */
    public void placeBundled(Workspace workspace) {
        copyTree(bundled, workspace.rules());
    }

    /**
     * Merges the operator's rule directory into the workspace, if one is configured.
     *
     * <p>This is the second of the three rule sources decision 0006 describes, and the one the
     * whole licensing argument rests on: Zanshin ships only rules it wrote, so an operator's own
     * coverage can only arrive this way. It was documented in the README and in the settings
     * table, and <b>read nowhere</b> — a scan ran with the bundled rules alone, and nothing said
     * so.
     *
     * <h2>Placed in a subdirectory, not merged file by file</h2>
     *
     * <p>The analyser is pointed at the directory and walks it, so a subtree is enough for the
     * rules to load. Keeping them apart means an operator file can never silently overwrite a
     * bundled one by sharing its name.
     *
     * <p>This placement is free <b>only because {@code --no-rewrite-rule-ids} is passed</b>:
     * without it every {@code check_id} is prefixed with the rule file's relative path, so
     * moving rules between directories renames every identifier — and the identifier enters an
     * issue's fingerprint, which resolves the entire SAST backlog and recreates it as new,
     * triage lost. <b>If that flag is ever dropped, this subdirectory becomes a data
     * migration.</b>
     *
     * <h2>Failing is the point</h2>
     *
     * <p>A configured directory that cannot be read <b>throws</b> rather than letting the scan
     * run with the bundled rules alone. The caller places this inside the source-analysis step,
     * so the failure leaves that step's result absent — "did not run" — and the backlog intact.
     *
     * <p>Running anyway would be the dangerous outcome: the analyser would exit cleanly with
     * fewer findings, which reads as "analysed, those issues are gone" and <b>resolves every
     * finding the operator's rules had produced</b>. Silently, on every target, the first time a
     * volume is forgotten in a deployment.
     */
    public boolean placeOperatorRules(Workspace workspace, String directory) {
        String configured = directory == null ? "" : directory.trim();
        if (configured.isEmpty()) {
            return false;
        }

        Path source = Path.of(configured);
        if (!Files.exists(source)) {
            throw new OperatorRulesUnavailableException(
                    "ZANSHIN_SEMGREP_RULES_DIR points at " + configured + ", which cannot be read.");
        }
        if (!Files.isDirectory(source)) {
            throw new OperatorRulesUnavailableException(
                    "ZANSHIN_SEMGREP_RULES_DIR points at " + configured + ", which is not a directory.");
        }

        copyTree(source, operatorDirectory(workspace));
        return true;
    }

    /**
     * Places the rule set a task names, and says whether it did.
     *
     * <h2>The precedence, and why it is exclusive</h2>
     *
     * <p>An uploaded set <b>replaces</b> the environment directory rather than merging with it.
     * Merging is the friendlier-looking choice and it reintroduces the exact defect the upload
     * exists to remove: the directory is per-executor, so a merged result differs between an
     * agent that has it and one that does not, and the SAST backlog resolves and reappears as
     * the two take turns. One authoritative source per scan is the property worth having.
     *
     * <p>With no set active, the directory still applies — it remains the right answer for a
     * single-instance deployment that already manages a volume, and withdrawing it would break
     * those.
     *
     * <h2>Failing is the point, again</h2>
     *
     * <p>A task naming a rule set whose content the executor cannot obtain <b>throws</b>.
     * Running with the bundled rule instead would exit cleanly with a shorter list, which reads
     * as "analysed, those issues are gone" — resolving everything the operator's rules had
     * found.
     */
    public boolean placeRuleSet(
            Workspace workspace, String contentHash, RuleSetProvider provider, String environmentDirectory) {

        if (contentHash == null || contentHash.isBlank()) {
            return placeOperatorRules(workspace, environmentDirectory);
        }
        if (provider == null) {
            throw new OperatorRulesUnavailableException("This scan requires uploaded rule set " + contentHash
                    + ", and this executor has no way to fetch it.");
        }

        List<RuleSet.StoredFile> files;
        try {
            files = provider.apply(contentHash);
        } catch (RuntimeException failure) {
            throw new OperatorRulesUnavailableException(
                    "Rule set " + contentHash + " could not be fetched: " + failure.getMessage());
        }
        if (files == null || files.isEmpty()) {
            throw new OperatorRulesUnavailableException("Rule set " + contentHash
                    + " came back empty; refusing to scan with the bundled rules alone.");
        }

        Path directory = operatorDirectory(workspace);
        try {
            Files.createDirectories(directory);
            for (RuleSet.StoredFile file : files) {
                // The **basename**, not the path as given. Zanshin generates these paths, but
                // this content arrives over HTTP on an agent, and a guard costing one call is
                // worth more than the argument that it cannot be hostile.
                Path name = Path.of(file.path()).getFileName();
                Files.writeString(directory.resolve(name), file.content());
            }
        } catch (IOException e) {
            throw new OperatorRulesUnavailableException(
                    "Rule set " + contentHash + " could not be written into the workspace: " + e.getMessage());
        }
        return true;
    }

    /** Where the operator's rules go: beside the bundled ones, never among them. */
    private static Path operatorDirectory(Workspace workspace) {
        return workspace.rules().resolve("semgrep").resolve(OPERATOR_SUBDIR);
    }

    private static void copyTree(Path from, Path to) {
        try (Stream<Path> paths = Files.walk(from)) {
            Files.createDirectories(to);
            for (Path path : paths.toList()) {
                Path target = to.resolve(from.relativize(path).toString());
                if (Files.isDirectory(path)) {
                    Files.createDirectories(target);
                } else {
                    Files.createDirectories(target.getParent());
                    Files.copy(path, target, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("could not place rules from " + from, e);
        }
    }

    /** The environment variable an operator sets to supply their own rules. */
    public static Optional<String> environmentDirectory() {
        return Optional.ofNullable(System.getenv("ZANSHIN_SEMGREP_RULES_DIR"));
    }
}
