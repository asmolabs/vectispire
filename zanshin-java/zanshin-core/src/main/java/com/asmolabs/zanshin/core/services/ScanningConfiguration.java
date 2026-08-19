package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.scanning.ContainerRunner;
import com.asmolabs.zanshin.common.scanning.GitClone;
import com.asmolabs.zanshin.common.scanning.RulePlacement;
import com.asmolabs.zanshin.common.scanning.ScanRunner;
import com.asmolabs.zanshin.common.scanning.scanners.ScannerImages;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.beans.factory.annotation.Value;
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
 * ZANSHIN_EMBEDDED_WORKER=false} — a control plane served entirely by remote agents, with no
 * Docker socket — gets no runner, and the dispatcher's empty branch is reached for a real
 * reason instead of by omission.
 *
 * <p><b>In {@code services} and not in {@code config}</b>, because the layer rule says so: only
 * {@code services} and {@code api} may reach {@code scanning}, and a configuration class is not
 * exempt from a rule whose whole purpose is that nothing is. {@code WorkerProperties} and
 * {@code ScanningProperties} live here for the same reason.
 */
@Configuration
@ConditionalOnProperty(prefix = "zanshin.worker", name = "enabled", havingValue = "true", matchIfMissing = true)
public class ScanningConfiguration {

    /**
     * The same runner an agent builds, wired to the database instead of to HTTP.
     *
     * <p>The rule provider is the only difference between the two, and it is the reason {@code
     * ScanRunner} takes one: this side reads an uploaded set from its own tables, an agent
     * fetches it over the protocol, and the scanning code may know neither.
     *
     * @param bundledRules the tree Zanshin ships. Relative to the working directory, as for the
     *     agent; {@code ZANSHIN_SEMGREP_RULES_DIR} adds to it and is read by {@code
     *     RulePlacement} itself
     */
    @Bean
    ScanRunner scanRunner(
            RuleSetService ruleSets,
            Clock clock,
            @Value("${zanshin.scanning.bundled-rules:rules}") Path bundledRules) {
        RulePlacement.RuleSetProvider provider =
                contentHash -> ruleSets.byHash(contentHash).map(ruleSets::filesOf).orElse(List.of());

        return new ScanRunner(
                new ContainerRunner(),
                ScannerImages.PINNED,
                bundledRules,
                provider,
                // Same policy as the agent: a changed host key blocks the scan rather than being
                // accepted, which is the whole point of recording it in the first place.
                new GitClone.HostKeyPolicy.AcceptNew(Path.of(System.getProperty("user.home"), ".ssh", "known_hosts")),
                clock);
    }
}
