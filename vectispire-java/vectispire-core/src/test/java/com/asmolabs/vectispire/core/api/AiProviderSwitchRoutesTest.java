package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.aireview.AiProvider;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.ai.AiReviewService;
import com.asmolabs.vectispire.core.compliance.internal.OwaspReportsAfterScans;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * The AI providers as integrations (decision 0040, lot I5), through the real routes, registry and database, with a
 * fake Ollama and a fake OpenAI on the loopback, both configured and both able to answer — so that "nothing was
 * asked" is read where a request would arrive, at either one.
 *
 * <p>Disabling the provider in use is accepted; every feature that reads it — the OWASP report from the button and
 * after a scan, the advisor's explanation and status, the settings' test — then answers 409 {@code
 * integration-disabled}, "AI unavailable — provider disabled", or asks nothing, and <b>never the other provider</b>.
 * Each refusal sits beside the same request answered with the provider on, or the test could not tell a refusal
 * from a fake that never answers.
 *
 * <p>{@code t_integration} is not emptied between tests; each case puts its rows back ({@link IntegrationRows}).
 */
@DisplayName("AI providers as integrations, through the routes")
class AiProviderSwitchRoutesTest extends ApiTestBase {

    private static final String DISABLED = "urn:vectispire:problem:integration-disabled";
    private static final Integration OLLAMA = Integration.of(AiProvider.OLLAMA);
    private static final Integration OPENAI = Integration.of(AiProvider.OPENAI);

    @Autowired
    private Integrations integrations;

    @Autowired
    private SettingsService settings;

    @Autowired
    private AiReviewService models;

    @Autowired
    private OwaspReportsAfterScans afterScans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private AiReviewResultRepository reports;

    @Autowired
    private JdbcTemplate jdbc;

    private IntegrationRows rows;
    private HttpServer ollama;
    private HttpServer openAi;
    private final List<String> askedOfOllama = new CopyOnWriteArrayList<>();
    private final List<String> askedOfOpenAi = new CopyOnWriteArrayList<>();
    private long repository;
    private long scan;
    private long issue;

    @BeforeEach
    void twoProvidersBothAnswering() throws Exception {
        rows = IntegrationRows.remember(jdbc);
        ollama = server(askedOfOllama, "{\"message\":{\"role\":\"assistant\",\"content\":\"## A06 from Ollama\"}}",
                "{\"models\":[{\"name\":\"gemma4:12b-it-qat\"}]}");
        openAi = server(askedOfOpenAi,
                "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"## A06 from OpenAI\"}}]}",
                "{\"data\":[{\"id\":\"gpt-5\"}]}");

        settings.set(Setting.AI_REVIEW_ENABLED, "true");
        settings.set(Setting.AI_REVIEW_PROVIDER, AiProvider.OLLAMA.wireName());
        settings.set(Setting.AI_REVIEW_OLLAMA_URL, "http://127.0.0.1:" + ollama.getAddress().getPort());
        settings.set(Setting.AI_REVIEW_OPENAI_URL, "http://127.0.0.1:" + openAi.getAddress().getPort());
        // OpenAI is fully configured, key included: a fallback to it would be able to send.
        models.setOpenAiKey("sk-test-not-a-real-key");

        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("https://example.invalid/ai-switch.git");
        entity.setName("ai-switch");
        entity.setBranch("main");
        repository = repositories.save(entity).getId();
        ScanEntity done = new ScanEntity();
        done.setRepoId(repository);
        done.setBranch("main");
        done.setStatus(ScanStatus.COMPLETED.wireName());
        done.setCreatedAt(Instant.now().minusSeconds(60));
        scan = scans.save(done).getId();
        IssueEntity found = new IssueEntity();
        found.setRepoId(repository);
        found.setFingerprint("fp-ai-switch");
        found.setType(FindingType.VULNERABILITY.wireName());
        found.setIdentifier("CVE-2026-4242");
        found.setSeverity(Severity.HIGH.wireName());
        found.setState(IssueState.OPEN.wireName());
        found.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        found.setPackageName("openssl");
        found.setPackageVersion("3.0.1");
        found.setFirstSeenAt(Instant.now());
        found.setLastSeenAt(Instant.now());
        found.setLastSeenScanId(scan);
        found.setTimesSeen(1);
        issue = issues.save(found).getId();
    }

    @AfterEach
    void putBack() {
        ollama.stop(0);
        openAi.stop(0);
        rows.putBack();
    }

    @Test
    @DisplayName("with the provider on, the report and the advice are the model's: the fakes answer, and only the configured one is asked")
    void theProviderOnAnswers() throws Exception {
        mvc.perform(authenticated(post("/api/v1/repositories/" + repository + "/owasp-review"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("completed"));
        mvc.perform(authenticated(post("/api/v1/ai-advisor/explain/issue/" + issue), asAdmin()))
                .andExpect(status().isOk());
        mvc.perform(authenticated(get("/api/v1/ai-advisor/status"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.providerEnabled").value(true))
                .andExpect(jsonPath("$.availableModels[0]").value("gemma4:12b-it-qat"));

        assertThat(askedOfOllama).hasSize(3);
        assertThat(askedOfOpenAi).isEmpty();
    }

    @Test
    @DisplayName("the provider in use is disabled: every feature answers 409 AI unavailable, nothing is recorded, and neither provider is asked")
    void aDisabledProviderIsAskedNothing() throws Exception {
        governorSwitches(OLLAMA, false).andExpect(status().isOk()).andExpect(jsonPath("$.enabled").value(false));

        assertUnavailable(mvc.perform(authenticated(post("/api/v1/repositories/" + repository + "/owasp-review"),
                asAdmin())), OLLAMA);
        assertThat(reports.findAll()).as("refused before a running row is written").isEmpty();

        assertUnavailable(mvc.perform(authenticated(post("/api/v1/ai-advisor/explain/issue/" + issue), asAdmin())),
                OLLAMA);
        assertUnavailable(mvc.perform(authenticated(post("/api/v1/settings/ollama-test"), asAdmin())), OLLAMA);

        // The status is read by every account and refuses nothing: it says the provider is off, and lists the
        // suggestions without asking it.
        mvc.perform(authenticated(get("/api/v1/ai-advisor/status"), asReader()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.providerEnabled").value(false));

        // After a scan: nothing held, so nothing written later either.
        settings.set(Setting.AI_REVIEW_OWASP_AFTER_SCAN, "true");
        assertThat(afterScans.offer(repository, scan)).isEqualTo(OwaspReportsAfterScans.Offer.PROVIDER_DISABLED);

        assertThat(askedOfOllama).as("the disabled provider").isEmpty();
        assertThat(askedOfOpenAi).as("never the other one in its place").isEmpty();
    }

    @Test
    @DisplayName("OpenAI disabled under a review configured for it: refused, and the Ollama beside it is not asked in its place")
    void theOtherWayRoundFallsBackNeither() throws Exception {
        settings.set(Setting.AI_REVIEW_PROVIDER, AiProvider.OPENAI.wireName());
        governorSwitches(OPENAI, false).andExpect(status().isOk());

        assertUnavailable(mvc.perform(authenticated(post("/api/v1/repositories/" + repository + "/owasp-review"),
                asAdmin())), OPENAI);
        assertUnavailable(mvc.perform(authenticated(post("/api/v1/ai-advisor/explain/issue/" + issue), asAdmin())),
                OPENAI);

        assertThat(askedOfOpenAi).isEmpty();
        assertThat(askedOfOllama).isEmpty();
    }

    @Test
    @DisplayName("every call to a model asks the registry itself, whoever calls it: a review asked past the features' checks is refused and sends nothing")
    void theCallItselfAsks() {
        jdbc.update("update t_integration set enabled = ? where integration_key = ?", false, OLLAMA.key());

        assertThatThrownBy(() -> models.reviewCode("findings", "prompt"))
                .isInstanceOfSatisfying(IntegrationDisabledException.class,
                        refused -> assertThat(refused.integration()).isEqualTo(OLLAMA))
                .hasMessageStartingWith(AiReviewService.UNAVAILABLE);
        assertThat(models.availableModels()).as("suggestions, nobody asked").isNotEmpty();

        assertThat(askedOfOllama).isEmpty();
        assertThat(askedOfOpenAi).isEmpty();
    }

    @Test
    @DisplayName("a disabled provider is not chosen, nor is model review turned on over one: 409 integration-disabled, nothing written")
    void aDisabledProviderIsNotChosen() throws Exception {
        governorSwitches(OPENAI, false).andExpect(status().isOk());

        ResultActions refused = save(Map.of(Setting.AI_REVIEW_PROVIDER.key(), "openai"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(DISABLED))
                .andExpect(jsonPath("$.integration").value("ai.openai"));
        assertThat(detailOf(refused.andReturn())).contains("\"ai.openai\" is disabled");
        assertThat(settings.get(Setting.AI_REVIEW_PROVIDER)).isEqualTo("ollama");

        // Review off, its provider disabled: turning it on is refused; the section sent back unchanged is not.
        settings.set(Setting.AI_REVIEW_ENABLED, "false");
        governorSwitches(OLLAMA, false).andExpect(status().isOk());
        save(Map.of(Setting.AI_REVIEW_ENABLED.key(), "true")).andExpect(status().isConflict())
                .andExpect(jsonPath("$.integration").value("ai.ollama"));
        assertThat(settings.get(Setting.AI_REVIEW_ENABLED)).isEqualTo("false");
        save(Map.of(Setting.AI_REVIEW_ENABLED.key(), "false", Setting.AI_REVIEW_PROVIDER.key(), "ollama"))
                .andExpect(status().isOk());

        // On again, the same choice goes through.
        governorSwitches(OPENAI, true).andExpect(status().isOk());
        save(Map.of(Setting.AI_REVIEW_PROVIDER.key(), "openai")).andExpect(status().isOk());
        assertThat(settings.get(Setting.AI_REVIEW_PROVIDER)).isEqualTo("openai");
    }

    private void assertUnavailable(ResultActions answer, Integration provider) throws Exception {
        MvcResult result = answer.andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(DISABLED))
                .andExpect(jsonPath("$.integration").value(provider.key()))
                .andReturn();
        assertThat(detailOf(result)).startsWith("AI unavailable — provider disabled.")
                .contains("\"" + provider.key() + "\" is disabled on this installation");
    }

    private ResultActions governorSwitches(Integration integration, boolean enabled) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/integrations/" + integration.key() + "/enabled"),
                        tokenFor("governor-" + System.nanoTime(), com.asmolabs.vectispire.common.domain.users.Role.SUPERUSER,
                                false))
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("enabled", enabled))));
    }

    private ResultActions save(Map<String, String> body) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    /** A model on the loopback: every request it receives is recorded, chats and catalogues alike. */
    private static HttpServer server(List<String> asked, String chatAnswer, String catalogue) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            asked.add(path + " " + new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] body = (path.endsWith("/tags") || path.endsWith("/models") ? catalogue : chatAnswer)
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        return server;
    }
}
