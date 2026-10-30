package com.asmolabs.vectispire.core.scanning.internal;

import com.asmolabs.vectispire.common.scanning.BundledRules;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.GitClone;
import com.asmolabs.vectispire.common.scanning.RulePlacement;
import com.asmolabs.vectispire.common.scanning.ScanRunner;
import com.asmolabs.vectispire.common.scanning.scanners.PluginScanner;
import com.asmolabs.vectispire.common.scanning.scanners.ScannerImages;
import com.asmolabs.vectispire.core.scanning.ScanPlugins;
import com.asmolabs.vectispire.core.scanning.ScanRuleSets;
import com.asmolabs.vectispire.core.scanning.ScanningProperties;
import java.nio.file.Path;
import java.time.Clock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * What the built-in worker needs in order to actually scan.
 *
 * <p><b>Without this bean the worker is inert, and says nothing about it.</b> {@code
 * ScanDispatcher} takes an {@code Optional<ScanRunner>} and returns {@code NOTHING} when it is
 * empty — a deliberate guard, so that a control plane with no scanning capability declines to
 * claim work rather than claiming it and failing. But nothing ever supplied the runner, so the
 * guard was permanently on: every queued scan stayed {@code pending} for ever, no scan was ever
 * claimed, and not one log line was written, because the worker only reports a round in which
 * it claimed something. The NestJS original had no such hole — its dispatcher default-built a
 * runner in its constructor.
 *
 * <p>The condition is what keeps the guard meaningful: an operator who sets {@code
 * VECTISPIRE_EMBEDDED_WORKER=false} — a control plane served entirely by remote agents, with no
 * Docker socket — gets no runner, and the dispatcher's empty branch is reached for a real
 * reason instead of by omission.
 *
 * <p><b>In {@code services} and not in {@code config}</b>, because the layer rule says so: only
 * {@code services} and {@code api} may reach {@code scanning}, and a configuration class is not
 * exempt from a rule whose whole purpose is that nothing is. {@code WorkerProperties} and
 * {@code ScanningProperties} live here for the same reason.
 */
@Configuration
@ConditionalOnProperty(prefix = "vectispire.worker", name = "enabled", havingValue = "true", matchIfMissing = true)
public class ScanningConfiguration {

    /**
     * Where the scanners read Vectispire's own rules from.
     *
     * <p>Unpacked from the jar into a temporary directory, once, because the scanners run as
     * sibling containers and a bind mount cannot resolve a path inside a jar.
     */
    private static Path bundledRules(String override) {
        if (override != null && !override.isBlank()) {
            return Path.of(override);
        }
        return BundledRules.materialise();
    }

    /**
     * The same runner an agent builds, wired to the database instead of to HTTP.
     *
     * <p>The rule provider is the only difference between the two, and it is the reason {@code
     * ScanRunner} takes one: this side reads an uploaded set from its own tables, an agent
     * fetches it over the protocol, and the scanning code may know neither.
     *
     * <p>What each setting means is on {@link ScanningProperties}.
     */
    @Bean
    ScanRunner scanRunner(
            ScanRuleSets ruleSets,
            ScanPlugins plugins,
            Clock clock,
            ScanningProperties scanning) {
        RulePlacement.RuleSetProvider provider =
                ruleSets::filesOf;
        // The manifest a task names, read from this side's own tables; the runner checks its
        // digest, as it does for what an agent fetches over HTTP.
        com.asmolabs.vectispire.common.scanning.PluginProvider manifests = reference -> plugins.manifest(reference)
                .orElseThrow(() -> new IllegalStateException(
                        "No plugin " + reference.id() + " with manifest " + reference.digest() + " is registered."));

        return new ScanRunner(
                new ContainerRunner(),
                // Blank keeps the pinned digest — see ScannerImages.withOverrides.
                ScannerImages.PINNED.withOverrides(scanning.images().syft(), scanning.images().grype(),
                        scanning.images().gitleaks(), scanning.images().checkov(), scanning.images().semgrep()),
                bundledRules(scanning.bundledRules()),
                provider,
                manifests,
                new PluginScanner.Settings(scanning.pluginRegistry(), scanning.pluginSignatureRequired()),
                // Same policy as the agent: a changed host key blocks the scan rather than being
                // accepted, which is the whole point of recording it in the first place.
                new GitClone.HostKeyPolicy.AcceptNew(Path.of(System.getProperty("user.home"), ".ssh", "known_hosts")),
                scanning.hostSsh() ? GitClone.WithoutKey.HOST_SSH : GitClone.WithoutKey.NONE,
                clock,
                scanning.vulnerabilityDbDir().isBlank()
                        ? com.asmolabs.vectispire.common.scanning.scanners.VulnerabilityDatabase.defaultRoot()
                        : Path.of(scanning.vulnerabilityDbDir().trim()));
    }
}
