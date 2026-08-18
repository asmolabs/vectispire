package com.asmolabs.zanshin.agent;

import com.asmolabs.zanshin.common.domain.agents.AgentContract;
import com.asmolabs.zanshin.common.domain.crypto.SealedEnvelope;
import com.asmolabs.zanshin.common.domain.rules.RuleSet.StoredFile;
import com.asmolabs.zanshin.common.scanning.ScanArtifacts;
import com.asmolabs.zanshin.common.scanning.ScanTask;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The agent protocol's client: four routes, and nothing else.
 *
 * <p><b>No database access, and that is a security property rather than a detail.</b> An agent
 * with a connection would also need the encryption key — that is, the means to decrypt
 * <em>every</em> deployment key Zanshin holds. It therefore knows the control plane only
 * through these four calls, authenticated by an API key bearing the {@code agent} scope, and it
 * opens no inbound port.
 *
 * <p>This class only speaks HTTP: what actually runs the scanners is the shared {@code
 * ScanRunner}. That sharing is what makes a result produced on another machine
 * indistinguishable from a local one — same findings, same enrichment, same reconciliation.
 */
public class AgentProtocol {

    /** The announcement's answer. */
    public record Identity(
            String id, String name, String contractVersion, int maxConcurrent, String credentialsMode) {}

    /** A received task: what the runner expects, plus the identifier to report against. */
    public record AssignedTask(long scanId, ScanTask task) {}

    /** What the agent says about itself. Purely informational, except the contract. */
    public record Description(String hostname, String platform, String version, String scannerEngine) {}

    /** The two failures whose fix is a deployment or a configuration change, not a retry. */
    public static class ContractMismatchException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public ContractMismatchException(String message) {
            super(message);
        }
    }

    public static class UnauthorizedException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public UnauthorizedException(String message) {
            super(message);
        }
    }

    private final AgentHttp http;
    private final ObjectMapper json;

    /**
     * This process's ephemeral pair, or empty to seal nothing.
     *
     * <p>Its private half is neither serialized nor written: it dies with the process, so there
     * is no key file to protect, rotate or forget.
     */
    private final Optional<SealedEnvelope.KeyPair> keyPair;

    private final SealedEnvelope envelopes = new SealedEnvelope();

    /** Keyed by hash, therefore never to invalidate — see {@link #ruleSet}. */
    private final Map<String, List<StoredFile>> ruleSetCache = new ConcurrentHashMap<>();

    public AgentProtocol(AgentHttp http, ObjectMapper json, SealedEnvelope.KeyPair keyPair) {
        this.http = http;
        this.json = json;
        this.keyPair = Optional.ofNullable(keyPair);
    }

    /**
     * The announcement, and <b>an operator's first diagnostic</b>.
     *
     * <p>If this call answers, the URL, the key, the scope and the agent row are all correct. A
     * contract disagreement is a distinct error because its fix is distinct: a deployment, not a
     * configuration change.
     */
    public Identity hello(Description description) {
        AgentHttp.Response response = http.call(
                "/api/v1/agent/hello",
                "POST",
                Map.of(
                        "contract_version", AgentContract.VERSION,
                        "hostname", description.hostname(),
                        "platform", description.platform(),
                        "version", description.version(),
                        "scanner_engine", description.scannerEngine(),
                        // Announced at every start and never persisted: the control plane seals
                        // for the living pair, not for a key kept from a previous life. An older
                        // control plane ignores the field, and the agent then receives the key in
                        // the clear — degraded, not broken.
                        "sealing_public_key", keyPair.map(SealedEnvelope.KeyPair::publicKey).orElse("")),
                Duration.ofSeconds(30));

        if (response.status() == 409) {
            throw new ContractMismatchException(response.messageOr("Incompatible contract."));
        }
        refuseIfUnauthorized(response);
        refuseIfFailed(response, "Announcement refused");

        return read(response.body(), Identity.class);
    }

    /**
     * Claims a task, or empty.
     *
     * <p>204 rather than an empty object: "is there work?" is read from the status code. The long
     * wait is the server's, so the agent does not poll in a tight loop.
     */
    public Optional<AssignedTask> claim(Duration wait) {
        AgentHttp.Response response = http.call(
                "/api/v1/agent/jobs?wait=" + wait.toSeconds(),
                "GET",
                null,
                // Longer than the wait we asked for: the server bounds it, and cutting flush
                // would time out every poll just before its answer.
                wait.plusSeconds(30));

        if (response.status() == 204) {
            return Optional.empty();
        }
        refuseIfUnauthorized(response);
        if (response.status() == 412) {
            // The link is not encrypted and this agent receives deployment keys. Refusing loudly
            // is the point: scanning without the key would produce a clone failure that looks
            // like a network problem.
            throw new IllegalStateException(response.messageOr(
                    "Unencrypted link refused for an agent with delegated credentials."));
        }
        refuseIfFailed(response, "Claim refused");

        return Optional.of(unseal(read(response.body(), AssignedTask.class)));
    }

    /**
     * Opens a task's deployment key, when it arrived sealed.
     *
     * <p><b>Throws rather than handing the task over as it stands.</b> An envelope nobody opens
     * is a string that looks like a key: it would be written to a file, handed to git, and the
     * failure would look like a repository or a permission problem. Failing here names the cause.
     */
    private AssignedTask unseal(AssignedTask assigned) {
        if (!(assigned.task().target() instanceof ScanTask.Target.Repository repository)
                || !SealedEnvelope.isSealed(repository.privateKey())) {
            return assigned;
        }
        if (keyPair.isEmpty()) {
            throw new IllegalStateException(
                    "A sealed key arrived although this agent announced none: the control plane sealed for "
                            + "somebody else.");
        }

        String plainText = envelopes.open(keyPair.get(), repository.privateKey())
                .orElseThrow(() -> new IllegalStateException(
                        "The sealed deployment key could not be opened: it is not addressed to this process, or it "
                                + "was altered on the way."));

        return new AssignedTask(
                assigned.scanId(),
                new ScanTask(
                        new ScanTask.Target.Repository(
                                repository.url(), repository.branch(), repository.subPath(), plainText),
                        assigned.task().rulesHash(),
                        assigned.task().steps()));
    }

    /**
     * A Semgrep rule set's content, cached by hash.
     *
     * <p><b>The cache needs no invalidation</b>, and that is the whole point of fetching by hash
     * rather than "the active set": a hash names a content, never a state. What the agent
     * downloaded once stays correct for ever, and a change of set simply produces a hash it does
     * not have.
     *
     * <p>In memory and not on disk: a restarted agent re-downloads a few megabytes once, which
     * is cheaper than a disk cache to purge, to lock between concurrent scans, and to protect
     * against a partial write.
     */
    public List<StoredFile> ruleSet(String contentHash) {
        return ruleSetCache.computeIfAbsent(contentHash, hash -> {
            AgentHttp.Response response =
                    http.call("/api/v1/agent/rules/" + hash, "GET", null, Duration.ofMinutes(2));
            // No fallback to the bundled rules: the caller places this inside the SAST step,
            // whose failure leaves the artifact absent. Scanning with fewer rules would hand back
            // a shorter list, which reads as "analyzed, those issues are gone".
            refuseIfFailed(response, "Rule set " + hash + " refused");

            JsonNode files = response.body().path("files");
            return json.convertValue(files, json.getTypeFactory()
                    .constructCollectionType(List.class, StoredFile.class));
        });
    }

    /**
     * The sign of life of an agent still working.
     *
     * <p>False when the lease was taken over: the agent must then <b>give up</b>, or its result
     * would overwrite its successor's.
     */
    public boolean heartbeat(long scanId) {
        AgentHttp.Response response =
                http.call("/api/v1/agent/jobs/" + scanId + "/heartbeat", "POST", null, Duration.ofSeconds(15));
        if (response.status() == 409) {
            return false;
        }
        refuseIfFailed(response, "Heartbeat refused");
        return true;
    }

    /** Hands back the result. False when the lease was taken over in the meantime. */
    public boolean submit(long scanId, ScanArtifacts artifacts) {
        AgentHttp.Response response = http.call(
                "/api/v1/agent/jobs/" + scanId + "/result",
                "POST",
                artifacts,
                // A SBOM weighs several megabytes: the timeout has to cover the upload, not only
                // the answer.
                Duration.ofMinutes(2));

        if (response.status() == 409) {
            return false;
        }
        refuseIfFailed(response, "Result refused");
        return true;
    }

    private <T> T read(JsonNode body, Class<T> type) {
        return json.convertValue(body, type);
    }

    private static void refuseIfUnauthorized(AgentHttp.Response response) {
        if (response.status() == 401 || response.status() == 403) {
            throw new UnauthorizedException(response.messageOr("API key refused."));
        }
    }

    private static void refuseIfFailed(AgentHttp.Response response, String what) {
        if (response.status() >= 400) {
            throw new IllegalStateException(response.messageOr(what + " (HTTP " + response.status() + ")."));
        }
    }
}
