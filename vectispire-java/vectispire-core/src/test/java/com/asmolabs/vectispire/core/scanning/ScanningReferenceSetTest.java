package com.asmolabs.vectispire.core.scanning;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.agents.CredentialsMode;
import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import com.asmolabs.vectispire.common.domain.crypto.ResultAttestation;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.common.domain.scans.FailureKind;
import com.asmolabs.vectispire.common.domain.scans.ScanQueue.Next;
import com.asmolabs.vectispire.common.domain.scans.ScanQueue.Policy;
import com.asmolabs.vectispire.common.domain.scheduling.Schedules;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.scanning.ScanTask;
import com.asmolabs.vectispire.core.RustReference;
import com.asmolabs.vectispire.core.agents.internal.AgentViews;
import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.crypto.internal.EncryptionProperties;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.scanning.internal.PlatformMetrics;
import com.asmolabs.vectispire.core.scanning.internal.ScanQueue;
import com.asmolabs.vectispire.core.scanning.internal.ScanningProperties;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.CloneCredentials;
import com.asmolabs.vectispire.core.targets.CronExpressions;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitTokenEntity;
import com.asmolabs.vectispire.core.targets.persistence.GitTokenRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * What the scheduling rule, the queue's rules and the dispatcher answer, for the Rust port of {@code scanning} (task
 * 2.7 of the control plane's port): {@code vectispire-rust/reference/scanning/java-answers.json}.
 *
 * <p><b>Written before the Rust code</b>, so that the port is held to Java rather than to itself. Five parts:
 *
 * <ul>
 *   <li>{@code schedules} — {@link Schedules#isDue}, {@link Schedules#inForce} and {@link Schedules#runsAtLeastEvery}
 *       over a row as {@code TargetSchedules.of} reads it, and the SplitMix slot of the default interval ({@link
 *       Schedules#offset}): a slot that moves by one second moves a whole estate's weekly round;
 *   <li>{@code queue} — {@code ScanQueue.afterFailure}: which attempt fails for good, how long a retry waits;
 *   <li>{@code sentences} — what a scan that could not run says, which the screen shows;
 *   <li>{@code columns} — the three columns a scan's page reads back ({@link DetectedLanguages}, {@link ExaminedTypes},
 *       {@link PluginOutcome});
 *   <li>{@code claims} — what {@link ScanDispatcher#claimForAgent} hands an agent, case by case: the task with each
 *       sealed credential replaced by the context it opens under and what it opens to, the refusal, the attempt ended,
 *       the audit entry, the rule languages recorded. The wiring is {@link ScanDispatcherTest}'s.
 * </ul>
 *
 * <p>Each case is one line, {@code "inputs": "answer"}, so that a difference reads as one changed line.
 */
class ScanningReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** The instant every schedule case is judged at: a fraction of a second, and no round number of anything. */
    private static final Instant NOW = Instant.parse("2026-10-18T12:34:56.789Z");

    @Test
    void theAnswersTheRustPortIsHeldTo() throws Exception {
        ObjectNode out = RustReference.object();
        out.put("now", NOW.toString());
        out.set("schedules", schedules());
        out.set("queue", queue());
        out.set("sentences", sentences());
        out.set("columns", columns());
        out.set("claims", claims());
        RustReference.expect("scanning/java-answers.json", out, ScanningReferenceSetTest.class);
    }

    // ── schedules ───────────────────────────────────────────────────────────────────────────────────────────────

    private static final String[] CRONS = {null, "   ", "0 2 * * *", "*/15 * * * *", "nonsense", "0 0 30 2 *"};
    private static final Integer[] INTERVALS = {null, 0, -5, 60, 1440};
    /** Seconds before {@link #NOW}; null is a target never picked up, a negative one a stamp in the future. */
    private static final Long[] LASTS = {null, 60L, 3_660L, 86_401L, 8 * 86_400L, -3_600L};
    private static final int[] DEFAULT_DAYS = {0, 1, 7};
    private static final long[] PERIODS = {3_600, 86_400, 7 * 86_400, 31 * 86_400};

    private static ObjectNode schedules() {
        ObjectNode schedules = JSON.createObjectNode();
        ObjectNode due = schedules.putObject("isDue");
        ObjectNode cadence = schedules.putObject("runsAtLeastEvery");
        for (boolean manual : new boolean[] {false, true}) {
            for (String cron : CRONS) {
                for (Integer interval : INTERVALS) {
                    for (int days : DEFAULT_DAYS) {
                        Duration defaultInterval = Duration.ofDays(days);
                        for (Long last : LASTS) {
                            Schedules.Schedulable target = schedulable(new ScanTarget.Repository(42), manual, cron,
                                    interval, last == null ? null : NOW.minusSeconds(last));
                            Schedules.InForce inForce = Schedules.inForce(target, defaultInterval);
                            due.put(key(manual, cron, interval, days, last), Schedules.isDue(target, defaultInterval, NOW)
                                    + "|" + inForce.mode().wireName() + "|"
                                    + inForce.interval().map(d -> String.valueOf(d.toMinutes())).orElse("~"));
                        }
                        Schedules.Schedulable target =
                                schedulable(new ScanTarget.Repository(42), manual, cron, interval, null);
                        for (long period : PERIODS) {
                            cadence.put(key(manual, cron, interval, days, period), Schedules.runsAtLeastEvery(
                                    target, defaultInterval, Duration.ofSeconds(period), NOW));
                        }
                    }
                }
            }
        }

        // Where in the default interval each target falls: kinds apart, consecutive identifiers far apart, the
        // multiplication by two wrapping past a long as Java's does, and an interval below a second read as one.
        ObjectNode slots = schedules.putObject("offsets");
        long[] ids = {0, 1, 2, 3, 7, 42, 1_000, 123_456_789, 4_611_686_018_427_387_904L, Long.MAX_VALUE, -1, Long.MIN_VALUE};
        long[] intervals = {0, 1, 59, 3_600, 86_400, 7 * 86_400, 7 * 86_400 + 1};
        for (long id : ids) {
            for (long interval : intervals) {
                for (ScanTarget target : new ScanTarget[] {new ScanTarget.Repository(id), new ScanTarget.Container(id)}) {
                    slots.put(targetKey(target) + "|" + interval,
                            Schedules.offset(target, Duration.ofSeconds(interval)).toSeconds());
                }
            }
        }

        // The default's own rule on its own: the slot reached since the last round, or not yet.
        ObjectNode defaults = schedules.putObject("defaultDue");
        long[] lasts = {1, 600, 3_600, 86_399, 86_400, 86_401, 6 * 86_400, 7 * 86_400, 7 * 86_400 + 1, 30 * 86_400};
        for (long id : new long[] {1, 2, 7, 1_000}) {
            for (ScanTarget target : new ScanTarget[] {new ScanTarget.Repository(id), new ScanTarget.Container(id)}) {
                for (int days : new int[] {1, 7}) {
                    for (long last : lasts) {
                        defaults.put(targetKey(target) + "|" + days + "|" + last, Schedules.defaultDue(
                                target, Duration.ofDays(days), NOW.minusSeconds(last), NOW));
                    }
                }
            }
        }
        return schedules;
    }

    /** {@code TargetSchedules.of}'s reading of a row's four columns. */
    private static Schedules.Schedulable schedulable(
            ScanTarget target, boolean manual, String cron, Integer interval, Instant last) {
        return new Schedules.Schedulable(target, manual, CronExpressions.parse(cron),
                interval == null ? Duration.ZERO : Duration.ofMinutes(interval), last);
    }

    private static String key(Object... parts) {
        return String.join("|", Arrays.stream(parts).map(part -> part == null ? "~" : part.toString()).toList());
    }

    private static String targetKey(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository -> "repo:" + repository.id();
            case ScanTarget.Container container -> "container:" + container.id();
        };
    }

    // ── queue ───────────────────────────────────────────────────────────────────────────────────────────────────

    private static ObjectNode queue() {
        List<Policy> policies = List.of(
                Policy.DEFAULT,
                new Policy(Duration.ofMinutes(20), 3, 12, List.of()),
                new Policy(Duration.ofMinutes(20), 5, 12, List.of(Duration.ofSeconds(30))),
                new Policy(Duration.ofMinutes(1), 1, 1, List.of(Duration.ofMinutes(1), Duration.ofMillis(2_500))));
        ObjectNode queue = JSON.createObjectNode();
        ArrayNode described = queue.putArray("policies");
        policies.forEach(policy -> described.add(policy.lease().toMillis() + "ms|" + policy.maxAttempts() + "|"
                + policy.retryDelays().stream().map(delay -> delay.toMillis() + "ms").toList()));
        ObjectNode after = queue.putObject("afterFailure");
        for (int index = 0; index < policies.size(); index++) {
            for (int attempt : new int[] {-1, 0, 1, 2, 3, 4, 5, 6, 10}) {
                for (FailureKind kind : FailureKind.values()) {
                    Next next = com.asmolabs.vectispire.common.domain.scans.ScanQueue.afterFailure(
                            attempt, kind, NOW, policies.get(index));
                    after.put(index + "|" + attempt + "|" + kind.name(), switch (next) {
                        case Next.Retry(Instant at) -> "retry:" + Duration.between(NOW, at).toMillis() + "ms";
                        case Next.Fail(boolean permanent) -> permanent ? "fail:permanent" : "fail:limit";
                    });
                }
            }
        }
        queue.put("leaseExhausted", com.asmolabs.vectispire.common.domain.scans.ScanQueue.LEASE_EXHAUSTED_MESSAGE);
        return queue;
    }

    // ── sentences ───────────────────────────────────────────────────────────────────────────────────────────────

    private static ObjectNode sentences() {
        ObjectNode sentences = JSON.createObjectNode();
        List<Next> nexts = List.of(
                new Next.Retry(NOW),
                new Next.Retry(Instant.parse("2026-10-18T12:35:56.000000001Z")),
                new Next.Retry(Instant.parse("2026-10-18T12:00:00Z")),
                new Next.Fail(true),
                new Next.Fail(false));
        for (int index = 0; index < nexts.size(); index++) {
            for (String where : new String[] {"on agent \"edge\"", "on the built-in worker"}) {
                ScanQueue.Abandoned outcome = new ScanQueue.Abandoned(nexts.get(index), 2, 3);
                sentences.put(index + "|" + where, ScanDispatcher.sentence(outcome, where, "clone refused: «é»"));
            }
        }
        sentences.put("withheld:notPinned", new CredentialWithheldException(true).getMessage());
        sentences.put("withheld:notProved", new CredentialWithheldException(false).getMessage());
        return sentences;
    }

    // ── columns ─────────────────────────────────────────────────────────────────────────────────────────────────

    private static ObjectNode columns() throws Exception {
        ObjectNode columns = JSON.createObjectNode();
        ObjectNode written = columns.putObject("languagesWritten");
        List<List<String>> sets = List.of(List.of(), List.of("java"), List.of("TypeScript ", "java", "go", "java"),
                List.of("cobol", "python"), List.of("Kotlin", "kotlin"), List.of(" "));
        for (List<String> set : sets) {
            written.put(String.join(",", set), String.valueOf(DetectedLanguages.write(Optional.of(set))));
        }
        ObjectNode read = columns.putObject("languagesRead");
        for (String column : new String[] {"", "java", "go,java", " java , python ,", "java,cobol", ",,", "JAVA"}) {
            read.put(column, DetectedLanguages.read(column)
                    .map(languages -> languages.stream().map(Language::wireName).toList().toString())
                    .orElse("~"));
        }
        ObjectNode examined = columns.putObject("examinedRead");
        for (String column : new String[] {"", "sast", "iac,sast,secret", " eol , license", "plugin,vulnerability", "x,,y"}) {
            examined.put(column, ExaminedTypes.read(column)
                    .map(types -> types.stream().map(FindingType::wireName).toList().toString())
                    .orElse("~"));
        }
        ObjectNode plugins = columns.putObject("pluginsRead");
        String[] stored = {
            "",
            "   ",
            "[]",
            "not json",
            "{}",
            "[{\"pluginId\":\"acme\",\"manifestDigest\":\"" + "a".repeat(64) + "\",\"state\":\"produced\",\"findings\":3,"
                    + "\"languages\":[],\"reason\":null,\"refusal\":null,\"signature\":\"verified\"}]",
            "[{\"pluginId\":\"acme\",\"state\":\"not_applicable\",\"languages\":[\"java\",\"go\"],\"extra\":1}]",
            "[{\"pluginId\":\"acme\",\"state\":\"refused\",\"reason\":\"no signer\",\"refusal\":\"unsigned\"},"
                    + "{\"pluginId\":\"other\",\"state\":\"absent\",\"reason\":\"crashed\"}]",
            "[{\"pluginId\":\"acme\",\"state\":\"a-later-state\",\"findings\":\"7\"}]",
            "[{\"pluginId\":\"acme\",\"languages\":\"java\"}]",
            "[null]",
            "[{\"findings\":2.9}]",
        };
        for (String column : stored) {
            // A null element is not one of Jackson's refusals: `List.copyOf` throws past the catch, and the scan's
            // page answers 500 for that row — a Java quirk the port reproduces rather than reads as no outcome.
            String answer;
            try {
                answer = JSON.writeValueAsString(PluginOutcome.read(column));
            } catch (RuntimeException thrown) {
                answer = "throws:" + thrown.getClass().getSimpleName();
            }
            plugins.put(column, answer);
        }
        return columns;
    }

    // ── claims ──────────────────────────────────────────────────────────────────────────────────────────────────

    private static final UUID KEY_ID = UUID.fromString("00000000-0000-0000-0000-0000000000aa");
    private static final UUID TOKEN_ID = UUID.fromString("00000000-0000-0000-0000-0000000000cc");
    private static final UUID AGENT_ID = UUID.fromString("00000000-0000-0000-0000-0000000000bb");
    private static final String PRIVATE_KEY = "test-ssh-private-key-material";
    private static final String TOKEN = "invented-https-token";
    /** An encryption key for the stored credentials, invented: what the Rust side configures too. */
    static final String ENCRYPTION_KEY = "cmVmZXJlbmNlLXNjYW5uaW5nLWtleS0zMi1ieXRlcyE="; // gitleaks:allow — a test fixture

    /** One case of the claim: the rows it starts from, and the agent that polls. */
    private static final class Claim {
        final String name;
        RepositoryEntity repository = repository();
        ContainerEntity container = null;
        ScanEntity scan = repositoryScan();
        boolean sshKeyStored = true;
        GitTokenEntity token = null;
        String mode = CredentialsMode.LOCAL.wireName();
        boolean sealingKey = false;
        boolean signingKey = false;
        boolean sast = false;
        String rulesHash = null;
        Set<Language> rulesLanguages = Set.of();
        List<PluginRef> plugins = List.of();
        String allowedHosts = "";
        /** The queue keeps repository 1 from an agent that cannot be handed a credential, as the real one does. */
        boolean exclusionHonoured = false;
        /** The agent already holds this many. */
        long held = 0;
        /** The repository gains its key between the selection and the delivery. */
        boolean scanHasKeyAtDelivery = false;

        Claim(String name, Consumer<Claim> setUp) {
            this.name = name;
            setUp.accept(this);
        }
    }

    private static List<Claim> claimCases() {
        return List.of(
                new Claim("local mode receives no key", c -> {}),
                new Claim("delegated with a verified sealing key receives the key sealed", c -> {
                    c.mode = "delegated";
                    c.sealingKey = true;
                }),
                new Claim("delegated, no signing key pinned", c -> {
                    c.mode = "delegated";
                    c.exclusionHonoured = true;
                }),
                new Claim("delegated, pinned but no sealing key proved", c -> {
                    c.mode = "delegated";
                    c.signingKey = true;
                    c.exclusionHonoured = true;
                }),
                new Claim("delegated and full is told nothing", c -> {
                    c.mode = "delegated";
                    c.exclusionHonoured = true;
                    c.held = 2;
                }),
                new Claim("a key added since the selection is put back refunded", c -> {
                    c.mode = "delegated";
                    c.repository.setSshKeyId(null);
                    c.scanHasKeyAtDelivery = true;
                }),
                new Claim("a key and a token, both sealed", c -> {
                    c.mode = "delegated";
                    c.sealingKey = true;
                    c.repository.setUrl("https://gitlab.example.com/team/service.git");
                    c.repository.setHttpsTokenId(TOKEN_ID);
                    c.token = token("gitlab.example.com", "oauth2");
                }),
                new Claim("a token alone, no user name", c -> {
                    c.mode = "delegated";
                    c.sealingKey = true;
                    c.repository.setUrl("https://gitlab.example.com/team/service.git");
                    c.repository.setSshKeyId(null);
                    c.repository.setHttpsTokenId(TOKEN_ID);
                    c.token = token("gitlab.example.com", null);
                }),
                new Claim("local mode never decrypts the token", c -> {
                    c.repository.setUrl("https://gitlab.example.com/team/service.git");
                    c.repository.setSshKeyId(null);
                    c.repository.setHttpsTokenId(TOKEN_ID);
                    c.token = token("gitlab.example.com", "oauth2");
                }),
                new Claim("an unreadable mode reads as local", c -> c.mode = "something-a-later-version-wrote"),
                new Claim("an image scan carries no key whatever the mode", c -> {
                    c.mode = "delegated";
                    c.container = container();
                    c.scan = imageScan();
                }),
                new Claim("SAST, the active rule set and its languages, a branch, a sub-path, plugins", c -> {
                    c.mode = "delegated";
                    c.sealingKey = true;
                    c.sast = true;
                    c.rulesHash = "f".repeat(64);
                    c.rulesLanguages = Set.of(Language.PYTHON, Language.JAVA);
                    c.repository.setSubPath("services/api");
                    c.scan.setBranch("release");
                    c.plugins = List.of(new PluginRef("acme-lint", "a".repeat(64)), new PluginRef("acme-sarif", "b".repeat(64)));
                }),
                new Claim("a blank branch on the scan reads the repository's", c -> c.scan.setBranch("  ")),
                new Claim("a deleted SSH key fails the scan for good", c -> {
                    c.mode = "delegated";
                    c.sealingKey = true;
                    c.sshKeyStored = false;
                }),
                new Claim("a deleted token fails the scan for good", c -> {
                    c.mode = "delegated";
                    c.sealingKey = true;
                    c.repository.setUrl("https://gitlab.example.com/team/service.git");
                    c.repository.setSshKeyId(null);
                    c.repository.setHttpsTokenId(TOKEN_ID);
                }),
                new Claim("a token no key opens fails the scan for good", c -> {
                    c.mode = "delegated";
                    c.sealingKey = true;
                    c.repository.setUrl("https://gitlab.example.com/team/service.git");
                    c.repository.setSshKeyId(null);
                    c.repository.setHttpsTokenId(TOKEN_ID);
                    c.token = token("gitlab.example.com", null);
                    c.token.setToken("v2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                }),
                new Claim("an ambiguous stored URL is refused", c -> {
                    c.repository.setUrl("https://forge.example#@elsewhere.example/team/service.git");
                    c.repository.setSshKeyId(null);
                }),
                new Claim("a host the allow-list does not name is refused", c -> c.allowedHosts = "gitlab.corp.example"),
                new Claim("a repository since deleted", c -> c.repository = null),
                new Claim("an image since deleted", c -> c.scan = imageScan()),
                new Claim("a scan naming no target", c -> {
                    c.scan = imageScan();
                    c.scan.setContainerId(null);
                }));
    }

    private static ArrayNode claims() throws Exception {
        ArrayNode claims = JSON.createArrayNode();
        for (Claim c : claimCases()) {
            claims.add(claim(c));
        }
        return claims;
    }

    private static ObjectNode claim(Claim c) throws Exception {
        ScanQueue queue = mock(ScanQueue.class);
        GitRepositoryRepository repositories = mock(GitRepositoryRepository.class);
        ContainerRepository containers = mock(ContainerRepository.class);
        SshKeyRepository sshKeys = mock(SshKeyRepository.class);
        GitTokenRepository gitTokens = mock(GitTokenRepository.class);
        SettingsService settings = mock(SettingsService.class);
        ScanRuleSets ruleSets = mock(ScanRuleSets.class);
        ScanPlugins plugins = mock(ScanPlugins.class);
        AuditLogService audit = mock(AuditLogService.class);
        SealedEnvelope envelopes = new SealedEnvelope();
        SealedEnvelope.KeyPair recipient = envelopes.generateKeyPair();

        when(ruleSets.activeHash()).thenReturn(Optional.ofNullable(c.rulesHash));
        when(ruleSets.languagesRead(any())).thenReturn(c.rulesLanguages);
        when(settings.isEnabled(Setting.SAST_ENABLED)).thenReturn(c.sast);
        when(plugins.forRepository(anyLong())).thenReturn(c.plugins);
        when(repositories.findById(1L)).thenReturn(Optional.ofNullable(c.repository));
        when(containers.findById(4L)).thenReturn(Optional.ofNullable(c.container));
        when(sshKeys.findById(KEY_ID)).thenReturn(c.sshKeyStored ? Optional.of(sshKey()) : Optional.empty());
        when(gitTokens.findById(TOKEN_ID)).thenReturn(Optional.ofNullable(c.token));
        when(queue.countHeld(anyString())).thenReturn(c.held);
        // The repository as the selection read it, and as the delivery reads it: the same row, except where a
        // case has a key arrive in between.
        when(repositories.findAllById(any())).thenAnswer(call -> c.repository == null ? List.of() : List.of(c.repository));
        when(queue.claimWithin(any(), anyInt(), any(), any())).thenAnswer(call -> {
            ScanQueue.Exclusion exclusion = call.getArgument(3);
            boolean kept = c.exclusionHonoured && exclusion.among(Set.of(1L)).contains(1L);
            if (kept) {
                return new ScanQueue.AgentClaim(Optional.empty(), true);
            }
            if (c.scanHasKeyAtDelivery) {
                c.repository.setSshKeyId(KEY_ID);
            }
            return new ScanQueue.AgentClaim(Optional.of(c.scan), false);
        });
        when(queue.requeueRefunded(anyLong(), anyString())).thenReturn(true);

        PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        ScanDispatcher dispatcher = new ScanDispatcher(
                queue,
                new TargetCatalog(repositories, containers),
                new CloneCredentials(gitTokens, sshKeys),
                mock(ScanIngestor.class),
                new EncryptionService(new EncryptionProperties(Optional.of(ENCRYPTION_KEY), List.of())),
                settings,
                ruleSets,
                plugins,
                envelopes,
                new ScanningProperties(Optional.of("linux/amd64")),
                Optional.empty(),
                audit,
                mock(PlatformMetrics.class),
                new TransactionTemplate(transactions),
                GitHostAllowlist.parse(c.allowedHosts),
                List.of());

        AgentEntity row = new AgentEntity();
        row.setId(AGENT_ID);
        row.setName("edge");
        row.setMaxConcurrent(2);
        row.setCredentialsMode(c.mode);
        if (c.sealingKey) {
            row.setSealingPublicKey(recipient.publicKey());
        }
        if (c.signingKey) {
            row.setSigningPublicKey(ResultAttestation.generate().publicKey());
        }

        ObjectNode answer = JSON.createObjectNode();
        answer.put("case", c.name);
        try {
            Optional<ScanDispatcher.AgentTask> task = dispatcher.claimForAgent(AgentViews.of(row));
            if (task.isPresent()) {
                answer.put("outcome", "task");
                answer.put("scanId", task.get().scanId());
                answer.put("attempt", task.get().attempt());
                answer.set("task", describe(task.get().task(), recipient, envelopes));
            } else {
                answer.put("outcome", "nothing");
            }
        } catch (CredentialWithheldException withheld) {
            answer.put("outcome", "withheld");
            answer.put("message", withheld.getMessage());
        }
        // What the queue was asked: the exclusion, the refund, the attempt ended — and the sentence it would store.
        @SuppressWarnings("unchecked")
        ArgumentCaptor<ScanQueue.Exclusion> exclusion = ArgumentCaptor.forClass(ScanQueue.Exclusion.class);
        verify(queue, atLeast(0)).claimWithin(any(), anyInt(), any(), exclusion.capture());
        answer.put("limit", 2);
        answer.put("excludes", exclusion.getAllValues().stream().anyMatch(value -> !value.excludesNothing()));
        answer.put("requeuedRefunded", invoked(queue, "requeueRefunded"));
        answer.put("abandoned", abandoned(queue));
        answer.put("sastLanguages", sastLanguages(queue));
        ArgumentCaptor<AuditLogService.Record> entries = ArgumentCaptor.forClass(AuditLogService.Record.class);
        verify(audit, atLeast(0)).record(entries.capture());
        ArrayNode audited = answer.putArray("audit");
        entries.getAllValues().forEach(entry -> audited.add(
                entry.operation().name() + "|" + entry.resourceId() + "|" + entry.userId() + "|" + entry.description()));
        return answer;
    }

    private static boolean invoked(Object mock, String method) {
        return mockingDetails(mock).getInvocations().stream().anyMatch(call -> call.getMethod().getName().equals(method));
    }

    /** The scan's attempt ended, as the queue was asked to end it: kind and the sentence for a failure for good. */
    @SuppressWarnings("unchecked")
    private static String abandoned(ScanQueue queue) {
        if (!invoked(queue, "abandon")) {
            return "~";
        }
        ArgumentCaptor<FailureKind> kind = ArgumentCaptor.forClass(FailureKind.class);
        ArgumentCaptor<Function<ScanQueue.Abandoned, String>> reason = ArgumentCaptor.forClass(Function.class);
        ArgumentCaptor<Integer> attempt = ArgumentCaptor.forClass(Integer.class);
        verify(queue).abandon(anyLong(), eq(AGENT_ID.toString()), attempt.capture(), kind.capture(), reason.capture());
        Next next = kind.getValue() == FailureKind.PERMANENT ? new Next.Fail(true) : new Next.Retry(NOW);
        return kind.getValue().name() + "|" + attempt.getValue() + "|"
                + reason.getValue().apply(new ScanQueue.Abandoned(next, attempt.getValue(), 3));
    }

    private static String sastLanguages(ScanQueue queue) {
        if (!invoked(queue, "recordSastLanguages")) {
            return "not recorded";
        }
        ArgumentCaptor<String> column = ArgumentCaptor.forClass(String.class);
        verify(queue).recordSastLanguages(anyLong(), column.capture());
        return String.valueOf(column.getValue());
    }

    private static ObjectNode describe(ScanTask task, SealedEnvelope.KeyPair recipient, SealedEnvelope envelopes) {
        ObjectNode out = JSON.createObjectNode();
        switch (task.target()) {
            case ScanTask.Target.Repository repository -> {
                out.put("kind", "repository");
                out.put("url", repository.url());
                out.put("branch", repository.branch());
                out.put("subPath", repository.subPath());
                out.put("privateKey", opened(repository.privateKey(), recipient, envelopes,
                        SealedEnvelope.Context.deploymentKey()));
                if (repository.https() == null) {
                    out.putNull("https");
                } else {
                    ObjectNode https = out.putObject("https");
                    https.put("host", repository.https().host());
                    https.put("username", repository.https().username());
                    https.put("token", opened(repository.https().token(), recipient, envelopes,
                            SealedEnvelope.Context.httpsToken(repository.https().host(), repository.https().username())));
                }
            }
            case ScanTask.Target.Image image -> {
                out.put("kind", "image");
                out.put("registry", image.reference().registry());
                out.put("imageName", image.reference().imageName());
                out.put("tag", image.reference().tag());
                out.put("platform", image.platform());
            }
        }
        out.put("rulesHash", task.rulesHash());
        ArrayNode steps = out.putArray("steps");
        Arrays.stream(ScanTask.Step.values()).filter(task.steps()::contains).forEach(step -> steps.add(step.name()));
        ArrayNode plugins = out.putArray("plugins");
        task.plugins().forEach(plugin -> plugins.add(plugin.id() + "@" + plugin.digest()));
        return out;
    }

    /** {@code null}, the context a sealed value opens under and what it opens to, or the clear value. */
    private static String opened(String value, SealedEnvelope.KeyPair recipient, SealedEnvelope envelopes,
            SealedEnvelope.Context context) {
        if (value == null) {
            return null;
        }
        if (!SealedEnvelope.isSealed(value)) {
            return "clear:" + value;
        }
        return envelopes.open(recipient, value, context)
                .map(plain -> "sealed:" + context.value() + ":" + plain)
                .orElse("sealed:unopened");
    }

    private static RepositoryEntity repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setId(1L);
        repository.setUrl("git@example.invalid:team/service.git");
        repository.setBranch("main");
        repository.setSshKeyId(KEY_ID);
        return repository;
    }

    private static ContainerEntity container() {
        ContainerEntity container = new ContainerEntity();
        container.setId(4L);
        container.setRegistry("registry.example.invalid");
        container.setImageName("team/service");
        container.setTag("1.4.0");
        return container;
    }

    private static ScanEntity repositoryScan() {
        ScanEntity scan = new ScanEntity();
        scan.setId(7L);
        scan.setRepoId(1L);
        scan.setBranch("main");
        scan.setAttempts(1);
        return scan;
    }

    private static ScanEntity imageScan() {
        ScanEntity scan = new ScanEntity();
        scan.setId(8L);
        scan.setContainerId(4L);
        scan.setBranch("n/a");
        scan.setAttempts(2);
        return scan;
    }

    private static SshKeyEntity sshKey() {
        SshKeyEntity key = new SshKeyEntity();
        key.setId(KEY_ID);
        key.setName("deploy");
        key.setPrivateKey(new SecretCipher().encrypt(
                EncryptionKey.derive(ENCRYPTION_KEY), PRIVATE_KEY, SecretCipher.privateKeyContext(KEY_ID.toString())));
        return key;
    }

    private static GitTokenEntity token(String host, String username) {
        GitTokenEntity token = new GitTokenEntity();
        token.setId(TOKEN_ID);
        token.setName("gitlab");
        token.setHost(host);
        token.setUsername(username);
        token.setToken(new SecretCipher().encrypt(
                EncryptionKey.derive(ENCRYPTION_KEY), TOKEN, SecretCipher.gitTokenContext(TOKEN_ID.toString())));
        return token;
    }

}
