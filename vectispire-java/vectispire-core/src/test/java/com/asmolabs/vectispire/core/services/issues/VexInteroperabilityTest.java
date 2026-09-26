package com.asmolabs.vectispire.core.services.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.exports.VexGeneratorService;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Clock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Whether this product can read an OpenVEX document — including its own.
 *
 * <h2>The defect, and why nothing said a word about it</h2>
 *
 * <p>OpenVEX v0.2.0 defines a statement's {@code products} as an array of <em>objects</em>:
 * {@code [{"@id": "pkg:apk/wolfi/git@2.39.0-r1"}]}. The ingest path modelled it as an array of
 * strings, so Jackson refuses the document outright — and {@code VexIngestorService} wraps every
 * attempt in {@code catch (Exception ignored)} before returning "nothing ingested".
 *
 * <p>The operator who uploads a VEX file therefore gets <b>200 and zero statements</b>. No error,
 * no log, nothing to look up. It is not a Vectispire-specific problem either: every conformant
 * producer emits the object form, so the endpoint silently ignored all of them.
 *
 * <p>And the product could not read its own output. {@code /api/v1/targets/{kind}/{id}/vex} emits
 * the object form through a second, unrelated OpenVEX model; {@code /api/v1/vex/ingest} expected
 * the string form. Two routes of one product, disagreeing about one standard.
 *
 * <h2>Why these two cases and not more</h2>
 *
 * <p>The first is the specification's own example shape, so it fails for a reason no downstream
 * consumer would call ours. The second is the round trip, which is the only assertion that keeps
 * two serialisations of one standard from drifting apart again — and the drift, not the shape, is
 * what took a year to notice.
 */
@DisplayName("reading an OpenVEX document")
class VexInteroperabilityTest extends VectispireContextTest {

    @Autowired
    private VexIngestorService ingestor;

    @Autowired
    private VexGeneratorService generator;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private Clock clock;

    /** The products shape the v0.2.0 specification shows, as any conformant producer emits it. */
    private static final String CONFORMANT = """
            {
              "@context": "https://openvex.dev/ns/v0.2.0",
              "@id": "https://example.invalid/vex/1",
              "author": "Example Corp",
              "version": 1,
              "statements": [
                {
                  "vulnerability": {"name": "CVE-2026-0001"},
                  "products": [{"@id": "pkg:maven/org.example/lib@1.0.0"}],
                  "status": "not_affected",
                  "justification": "vulnerable_code_not_in_execute_path"
                }
              ]
            }""";

    @Test
    @DisplayName("accepts the shape the specification shows")
    void readsAConformantDocument() {
        excepted("CVE-2026-0001", "pkg:maven/org.example/lib@1.0.0");

        VexIngestorService.IngestionResult result = ingestor.ingestPayload(CONFORMANT, ciso());

        assertThat(result.statementsProcessed())
                .as("every conformant producer emits products as objects; refusing them silently "
                        + "makes the endpoint useless and says nothing about why")
                .isEqualTo(1);
        assertThat(result.matchedIssues()).isEqualTo(1);
    }

    @Test
    @DisplayName("still accepts the older shape, because documents in the wild carry it")
    void readsTheOlderStringShape() {
        excepted("CVE-2026-0002", "pkg:maven/org.example/other@2.0.0");

        String olderForm = CONFORMANT
                .replace("CVE-2026-0001", "CVE-2026-0002")
                .replace("[{\"@id\": \"pkg:maven/org.example/lib@1.0.0\"}]",
                        "[\"pkg:maven/org.example/other@2.0.0\"]");

        assertThat(ingestor.ingestPayload(olderForm, ciso()).statementsProcessed())
                .as("Vectispire emitted this form itself for a long time; refusing it now would "
                        + "reject the documents it taught its own users to keep")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("reads back what it writes")
    void roundTripsItsOwnDocument() {
        long repoId = excepted("CVE-2026-0003", "pkg:maven/org.example/round@3.0.0");

        String emitted = serialise(generator.generateAggregate(
                com.asmolabs.vectispire.common.domain.access.Visibility.everything()));

        assertThat(ingestor.ingestPayload(emitted, ciso()).statementsProcessed())
                .as("two serialisations of one standard inside one product is how the two come to "
                        + "disagree, and this is the assertion that notices")
                .isPositive();
        assertThat(repoId).isPositive();
    }

    /** The import takes decisions in its caller's name; these tests are about the format, not who. */
    private static IssueDecisionService.Caller ciso() {
        com.asmolabs.vectispire.core.access.persistence.UserEntity user = new com.asmolabs.vectispire.core.access.persistence.UserEntity();
        user.setUsername("ciso");
        user.setRole(com.asmolabs.vectispire.common.domain.users.Role.CISO.name());
        return new IssueDecisionService.Caller(
                java.util.Optional.of(com.asmolabs.vectispire.core.access.UserView.of(user)),
                com.asmolabs.vectispire.common.domain.access.Visibility.everything(),
                "192.0.2.1",
                "test");
    }

    private String serialise(Object document) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper()
                    .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                    .disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                    .writeValueAsString(document);
        } catch (Exception failed) {
            throw new AssertionError(failed);
        }
    }

    /** One issue somebody has already excepted, so a statement about it has something to match. */
    private long excepted(String cve, String purl) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("ssh://git@example.invalid/team/" + cve + ".git");
        repository.setName("app");
        repository.setBranch("main");
        long repoId = repositories.save(repository).getId();

        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-" + cve);
        issue.setIdentifier(cve);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setPurl(purl);
        issue.setIsKev(false);
        issue.setFirstSeenAt(clock.instant());
        issue.setLastSeenAt(clock.instant());
        issue.setTimesSeen(1);
        issues.save(issue);
        return repoId;
    }
}
