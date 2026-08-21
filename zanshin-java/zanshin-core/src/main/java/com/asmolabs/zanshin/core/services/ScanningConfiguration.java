package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.scanning.BundledRules;
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
     * Where the scanners read Zanshin's own rules from.
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
     * @param bundledRulesOverride a directory to use instead of the rules packaged in the jar.
     *     Empty by default and rarely wanted: the shipped tree is the one the tests cover, and
     *     the previous behaviour — a relative {@code rules} path resolved against the process
     *     working directory — pointed at nothing and failed every repository scan
     * @param hostSsh whether a repository with no deployment key falls back to this machine's
     *     own git access. <b>On by default, and to be turned off on a shared installation</b>:
     *     with it on, every target anybody adds to Zanshin is cloned with whatever the host's key
     *     can reach, so the per-repository scoping — a key attached to one target, encrypted at
     *     rest — stops meaning anything, and adding a URL is enough to have Zanshin clone it with
     *     an identity nobody attached to it. The default favours the single-team install, where
     *     the operator's {@code ~/.ssh} is already the credential that reaches every target and
     *     the alternative was re-declaring it once per repository. Set {@code ZANSHIN_HOST_SSH}
     *     to {@code false} where the people adding targets are not the people who own that key
     */
    @Bean
    ScanRunner scanRunner(
            RuleSetService ruleSets,
            Clock clock,
            @Value("${zanshin.scanning.bundled-rules:}") String bundledRulesOverride,
            @Value("${zanshin.scanning.host-ssh:true}") boolean hostSsh) {
        RulePlacement.RuleSetProvider provider =
                contentHash -> ruleSets.byHash(contentHash).map(ruleSets::filesOf).orElse(List.of());

        return new ScanRunner(
                new ContainerRunner(),
                ScannerImages.PINNED,
                bundledRules(bundledRulesOverride),
                provider,
                // Same policy as the agent: a changed host key blocks the scan rather than being
                // accepted, which is the whole point of recording it in the first place.
                new GitClone.HostKeyPolicy.AcceptNew(Path.of(System.getProperty("user.home"), ".ssh", "known_hosts")),
                hostSsh ? GitClone.WithoutKey.HOST_SSH : GitClone.WithoutKey.NONE,
                clock);
    }
}
