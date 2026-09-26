package com.asmolabs.vectispire.agent;

import com.asmolabs.vectispire.common.domain.agents.AgentConcurrency;
import com.asmolabs.vectispire.common.domain.agents.CredentialsMode;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.scanning.BundledRules;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.GitClone;
import com.asmolabs.vectispire.common.scanning.RulePlacement;
import com.asmolabs.vectispire.common.scanning.ScanRunner;
import com.asmolabs.vectispire.common.scanning.scanners.ScannerImages;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.info.BuildProperties;
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
    private final String version;
    private final AtomicBoolean stopping = new AtomicBoolean();

    /** The loop once it exists, for {@link #stop} to reach from the shutdown hook's thread. */
    private volatile AgentLoop current;

    /** Counted down when the loop has returned — every scan it started handed back. */
    private final CountDownLatch finished = new CountDownLatch(1);

    public AgentRunner(
            AgentProperties properties, ObjectMapper json, Clock clock, ObjectProvider<BuildProperties> build) {
        this.properties = properties;
        this.json = json;
        this.clock = clock;
        // **The agent's own build, not a setting.** It was `vectispire.agent.version`, read from
        // VECTISPIRE_VERSION with a default of "1": the agents screen showed "1" for every agent,
        // and the variable an operator sets to change the version stated in exported documents
        // changed what every agent claimed to be as well. Null when built without build-info; the
        // control plane records an agent that announces none as announcing none.
        BuildProperties info = build.getIfAvailable();
        this.version = info == null ? null : info.getVersion();
    }

    @Override
    public void run(ApplicationArguments args) {
        // Refused at once and by name. An agent that starts with no configuration and loops on
        // 401s reads as a network problem, and the operator looks in the wrong place.
        if (properties.url().isEmpty()) {
            throw new IllegalStateException("vectispire.agent.url is required: the control plane's address.");
        }
        if (properties.token().isEmpty()) {
            throw new IllegalStateException(
                    "vectispire.agent.token is required: the API key shown once when the agent was created.");
        }
        if (!properties.url().startsWith("https://")) {
            // Warned and not refused: an agent in `local` mode receives no key, and a deployment
            // behind a reverse proxy legitimately sees HTTP. A current control plane delegates a
            // credential only sealed, over any link (decision 0031); the warning stands for the
            // API key and the results, which still travel as they are.
            log.warn("Unencrypted link to {}: the API key and the results travel in the clear.", properties.url());
        }

        // **Regenerated on every start, never written.** A restarted agent is a new recipient;
        // there is no key file to protect, rotate or forget, and nothing to recover from the disk
        // of a compromised scanning machine.
        SealedEnvelope.KeyPair keyPair = new SealedEnvelope().generateKeyPair();

        AgentProtocol protocol = new AgentProtocol(
                new AgentHttp(json, properties.url(), properties.token()),
                json,
                keyPair,
                properties.signingKey(),
                // The pair's generation: the control plane keeps the newest it accepted, so a
                // restarted agent's key replaces the last one and a replayed older one does not.
                clock.millis());
        if (properties.signingKey().isEmpty()) {
            // Said once, at start, because the alternative is an operator who believes their
            // results are attested. The control plane cannot say it for them: an agent with no
            // pinned key is indistinguishable from one that simply has not been configured yet.
            log.info("No result-signing key configured — results are accepted on this agent's API key alone. "
                    + "Pin one from the agents administration screen to change that.");
        }

        AgentProtocol.Identity identity = announce(protocol, new AgentProtocol.Description(
                hostName(),
                System.getProperty("os.name") + " " + System.getProperty("os.version"),
                version,
                properties.scannerEngine()));

        // **The rule provider, wired to the protocol.** Without it, an agent handed a task naming
        // an uploaded set would fail its SAST step — loudly and correctly, but with no way ever
        // to scan. The runner cannot speak HTTP itself: it is shared with the built-in worker,
        // which reads the database.
        RulePlacement.RuleSetProvider ruleSets = protocol::ruleSet;
        ScanRunner runner = new ScanRunner(
                new ContainerRunner(),
                ScannerImages.PINNED.withOverrides(
                        properties.images().syft(),
                        properties.images().grype(),
                        properties.images().gitleaks(),
                        properties.images().checkov(),
                        properties.images().semgrep()),
                // Unpacked from the agent's own jar, for the same reason: `Path.of("rules")`
                // resolved against whatever directory the agent was started in, and no such
                // directory ships with it.
                BundledRules.materialise(),
                ruleSets,
                new GitClone.HostKeyPolicy.AcceptNew(Path.of(System.getProperty("user.home"), ".ssh", "known_hosts")),
                // **What `CredentialsMode.LOCAL` has always promised.** An agent in that mode
                // receives no deployment key, and until now the session was built with an empty
                // identity set — so the documented recommendation could not clone a private
                // repository at all. Falling back to the host's own git access is what the mode
                // means; an agent in DELEGATED still gets its key and never reaches this.
                GitClone.WithoutKey.HOST_SSH,
                clock);

        AgentLoop loop = new AgentLoop(protocol, runner::run, properties, identity.maxConcurrent());
        log.info("Up to {} scan(s) at once, as set on this agent's row.", AgentConcurrency.effective(identity.maxConcurrent()));
        current = loop;
        if (stopping.get()) {
            // Stopped between the hello and here: `stop()` found no loop to tell.
            loop.stop();
        }
        try {
            // Transitory failures are handled inside — a failed claim waits and retries. What
            // comes out is a refused key or a contract gap: neither is fixed by looping, and
            // looping would fill a log with a symptom and never name the cause.
            loop.serve();
        } finally {
            loop.close();
            finished.countDown();
        }
        log.info("Agent stopped.");
    }

    /**
     * <b>The scans in progress run to the end</b>, and this waits for them.
     *
     * <p>Killing them would leave their leases running until they lapse, and the work already done
     * would be lost for nothing — see {@link AgentLoop#stop}. <b>The wait is what makes that true.</b>
     * The loop runs on the thread that started the application, and the JVM halts as soon as its
     * shutdown hooks return: a stop that only raised a flag let the process exit mid-scan, the
     * opposite of what this used to promise. The bound on the wait is the orchestrator's grace
     * period, which is where an operator decides how long a scan may take to finish.
     */
    @jakarta.annotation.PreDestroy
    public void stop() {
        if (stopping.compareAndSet(false, true)) {
            log.info("Shutdown requested: no new scans; waiting for the running ones to be handed back.");
        }
        AgentLoop loop = current;
        if (loop == null) {
            // Never got as far as looping — refused at start, or still announcing. Nothing runs.
            return;
        }
        loop.stop();
        try {
            finished.await();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * The hello, then — for an agent that receives credentials — the signed sealing key.
     *
     * <p>Apart from {@link #run} so that the second call is tested where it is made: a sealing key
     * the runner never announced would leave every delegated scan withheld, on an agent whose every
     * other test passes.
     */
    static AgentProtocol.Identity announce(AgentProtocol protocol, AgentProtocol.Description description) {
        AgentProtocol.Identity identity = protocol.hello(description);

        log.info(
                "Agent \"{}\" announced — contract {}, credentials {}.",
                identity.name(),
                identity.contractVersion(),
                identity.credentialsMode());

        if (CredentialsMode.byWireName(identity.credentialsMode())
                .map(CredentialsMode::deliversCredentials)
                .orElse(false)) {
            announceSealingKey(protocol);
        }
        return identity;
    }

    /**
     * Announces the sealing key a delegated credential is sealed for, and says what the answer asks
     * of the operator.
     *
     * <p><b>Never fatal.</b> Whatever the answer, the agent runs: an image scan needs no credential,
     * and a repository scan whose credential is withheld fails its claim with the control plane's
     * reason, every time, in this log. Stopping here would trade one loud message for silence.
     */
    static AgentProtocol.SealingKeyOutcome announceSealingKey(AgentProtocol protocol) {
        AgentProtocol.SealingKeyOutcome outcome;
        try {
            outcome = protocol.announceSealingKey();
        } catch (AgentProtocol.UnauthorizedException refused) {
            throw refused;
        } catch (RuntimeException failed) {
            log.warn("The sealing key could not be announced ({}); delegated credentials are withheld until it is.",
                    failed.getMessage());
            return AgentProtocol.SealingKeyOutcome.UNSIGNABLE;
        }
        switch (outcome) {
            case ACCEPTED -> log.info("Sealing key verified by the control plane: delegated credentials are sealed "
                    + "for this process alone.");
            case NOT_SUPPORTED -> log.info("The control plane predates signed sealing keys; it seals for the key in "
                    + "the hello. Upgrade it to take a TLS-terminating proxy out of the trust boundary.");
            case NOT_PINNED -> log.warn("No signing key is pinned for this agent on the control plane, so it hands "
                    + "this agent no delegated credential. Pin one from the agents administration screen and set "
                    + "its private half as vectispire.agent.signing-key.");
            case REFUSED -> log.error("The control plane refused this agent's sealing key: vectispire.agent.signing-key "
                    + "is not the key pinned for it. No delegated credential will be handed to it.");
            case STALE -> log.error("The control plane holds a newer sealing key than this process made: this host's "
                    + "clock is behind. Correct it, or have an administrator reset this agent's sealing key.");
            case UNSIGNABLE -> log.warn("This agent receives delegated credentials but has no "
                    + "vectispire.agent.signing-key to sign its sealing key with: a current control plane hands it "
                    + "none. Pin a key from the agents administration screen and configure its private half.");
        }
        return outcome;
    }

    private static String hostName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException unknown) {
            return "unknown-host";
        }
    }
}
