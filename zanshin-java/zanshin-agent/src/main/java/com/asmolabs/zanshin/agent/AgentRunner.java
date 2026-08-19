package com.asmolabs.zanshin.agent;

import com.asmolabs.zanshin.common.domain.crypto.SealedEnvelope;
import com.asmolabs.zanshin.common.scanning.ContainerRunner;
import com.asmolabs.zanshin.common.scanning.GitClone;
import com.asmolabs.zanshin.common.scanning.RulePlacement;
import com.asmolabs.zanshin.common.scanning.ScanRunner;
import com.asmolabs.zanshin.common.scanning.scanners.ScannerImages;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.time.Clock;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * The agent process: announce, then loop until told to stop.
 *
 * <p><b>No database access</b>, and that is what justifies its existence: taking the Docker
 * socket off the machine that serves the interface, reaching a repository routable only from
 * another segment, or adding capacity — without handing over the means to decrypt deployment
 * keys along the way.
 *
 * <p><b>It shares the runner with the built-in worker.</b> A result produced here is therefore
 * indistinguishable from a local one: same findings, same enrichment, same reconciliation. A
 * second execution path would have diverged at the first scanner added.
 */
@Component
public class AgentRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AgentRunner.class);

    private final AgentProperties properties;
    private final ObjectMapper json;
    private final Clock clock;
    private final AtomicBoolean stopping = new AtomicBoolean();

    public AgentRunner(AgentProperties properties, ObjectMapper json, Clock clock) {
        this.properties = properties;
        this.json = json;
        this.clock = clock;
    }

    @Override
    public void run(ApplicationArguments args) {
        // Refused at once and by name. An agent that starts with no configuration and loops on
        // 401s reads as a network problem, and the operator looks in the wrong place.
        if (properties.url().isEmpty()) {
            throw new IllegalStateException("zanshin.agent.url is required: the control plane's address.");
        }
        if (properties.token().isEmpty()) {
            throw new IllegalStateException(
                    "zanshin.agent.token is required: the API key shown once when the agent was created.");
        }
        if (!properties.url().startsWith("https://")) {
            // Warned and not refused: an agent in `local` mode receives no key, and a deployment
            // behind a reverse proxy legitimately sees HTTP. The control plane refuses to
            // delegate a clear key over a clear link — that is where the decision belongs,
            // because that is where what would be sent is known. A sealed key never travels in
            // the clear, so the requirement falls away by itself.
            log.warn("Unencrypted link to {}: only sealed keys will be delegated there.", properties.url());
        }

        // **Regenerated on every start, never written.** A restarted agent is a new recipient;
        // there is no key file to protect, rotate or forget, and nothing to recover from the disk
        // of a compromised scanning machine.
        SealedEnvelope.KeyPair keyPair = new SealedEnvelope().generateKeyPair();

        AgentProtocol protocol = new AgentProtocol(
                new AgentHttp(json, properties.url(), properties.token()), json, keyPair);

        AgentProtocol.Identity identity = protocol.hello(new AgentProtocol.Description(
                hostName(),
                System.getProperty("os.name") + " " + System.getProperty("os.version"),
                properties.version(),
                properties.scannerEngine()));

        log.info(
                "Agent \"{}\" announced — contract {}, credentials {}.",
                identity.name(),
                identity.contractVersion(),
                identity.credentialsMode());

        // **The rule provider, wired to the protocol.** Without it, an agent handed a task naming
        // an uploaded set would fail its SAST step — loudly and correctly, but with no way ever
        // to scan. The runner cannot speak HTTP itself: it is shared with the built-in worker,
        // which reads the database.
        RulePlacement.RuleSetProvider ruleSets = protocol::ruleSet;
        ScanRunner runner = new ScanRunner(
                new ContainerRunner(),
                ScannerImages.PINNED,
                Path.of("rules"),
                ruleSets,
                new GitClone.HostKeyPolicy.AcceptNew(Path.of(System.getProperty("user.home"), ".ssh", "known_hosts")),
                clock);

        AgentLoop loop = new AgentLoop(protocol, runner::run, properties);
        try {
            while (!stopping.get()) {
                try {
                    loop.runOnce();
                } catch (AgentProtocol.UnauthorizedException | AgentProtocol.ContractMismatchException fatal) {
                    // Neither is transitory: one is a wrong or revoked key, the other a version
                    // gap. Looping on either would fill a log with a symptom and never name the
                    // cause.
                    throw fatal;
                } catch (RuntimeException transitory) {
                    // Everything else is assumed transitory: a control plane restarting, a
                    // network hiccup. Looping is the right behaviour; going quiet is not.
                    log.warn("Agent turn failed: {}", transitory.getMessage());
                    sleep();
                }
            }
        } finally {
            loop.close();
        }
        log.info("Agent stopped.");
    }

    /**
     * <b>The scan in progress runs to the end.</b>
     *
     * <p>Killing it would leave a lease running until it lapses, and the work already done would
     * be lost for nothing.
     */
    @jakarta.annotation.PreDestroy
    public void stop() {
        if (stopping.compareAndSet(false, true)) {
            log.info("Shutdown requested: stopping after the current scan.");
        }
    }

    private void sleep() {
        try {
            Thread.sleep(properties.retryDelay().toMillis());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            stopping.set(true);
        }
    }

    private static String hostName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException unknown) {
            return "unknown-host";
        }
    }
}
