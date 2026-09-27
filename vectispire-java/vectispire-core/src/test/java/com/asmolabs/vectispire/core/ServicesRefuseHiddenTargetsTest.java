package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.compliance.CertifiedScopeService;
import com.asmolabs.vectispire.core.exports.AttestationService;
import com.asmolabs.vectispire.core.exports.CsafGeneratorService;
import com.asmolabs.vectispire.core.exports.CycloneDxGeneratorService;
import com.asmolabs.vectispire.core.exports.VexGeneratorService;
import com.asmolabs.vectispire.core.inventory.SbomDiffService;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.posture.AttackPathService;
import com.asmolabs.vectispire.core.posture.SecurityScorecardService;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.tickets.TicketLinkService;
import java.time.Instant;
import java.util.List;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The services that serve one target refuse a hidden one themselves, in the words an absent one gets.
 *
 * <p><b>Why at the service and not only through the routes.</b> Twenty routes refused the target and
 * then called a service by its bare id, and {@code VisibilityRoutesTest} proved each route — which is
 * exactly what let the services trust their callers: the attack-path graph reached the API inventory
 * that way, the evidence bundle the attestation. What this pins is that the method refuses whoever
 * calls it, so a second route, a task or a neighbouring service reaching it is refused too.
 *
 * <p>Each case also asks for something the caller may see and expects an answer, so a service that
 * refused everything would fail here rather than pass.
 */
@DisplayName("a service serving one target refuses a hidden one, whoever calls it")
class ServicesRefuseHiddenTargetsTest extends VectispireContextTest {

    private static final RequestActor ACTOR = new RequestActor("visibility-test", null, null);

    @Autowired
    private SecurityScorecardService scorecards;

    @Autowired
    private AttackPathService attackPaths;

    @Autowired
    private CertifiedScopeService scope;

    @Autowired
    private TicketLinkService tickets;

    @Autowired
    private AttestationService attestations;

    @Autowired
    private VexGeneratorService vex;

    @Autowired
    private CsafGeneratorService csaf;

    @Autowired
    private CycloneDxGeneratorService cycloneDx;

    @Autowired
    private SbomDiffService sbomDiff;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private IssueRepository issues;

    private long seenRepository;
    private long hiddenRepository;
    private long hiddenContainer;
    private long seenScan;
    private long hiddenScan;
    private long seenIssue;
    private long hiddenIssue;
    private Visibility allowed;

    @BeforeEach
    void estate() {
        seenRepository = repository("https://example.invalid/seen.git", "seen");
        hiddenRepository = repository("https://example.invalid/hidden.git", "hidden");
        ContainerEntity container = new ContainerEntity();
        container.setImageName("registry.example.invalid/hidden");
        container.setTag("1.0.0");
        hiddenContainer = containers.save(container).getId();
        seenScan = scan(seenRepository);
        hiddenScan = scan(hiddenRepository);
        seenIssue = issue(seenRepository, "seen-issue");
        hiddenIssue = issue(hiddenRepository, "hidden-issue");
        allowed = Visibility.only(List.of(new ScanTarget.Repository(seenRepository)));
    }

    @Test
    @DisplayName("a scorecard: hidden repository and image refused as absent ones are")
    void scorecards() {
        assertThat(scorecards.getRepositoryScorecard(seenRepository, allowed)).isPresent();
        refusedAs("Target not found.", () -> scorecards.getRepositoryScorecard(hiddenRepository, allowed));
        refusedAs("Target not found.", () -> scorecards.getRepositoryScorecard(hiddenRepository + 1000, allowed));
        refusedAs("Target not found.", () -> scorecards.getContainerScorecard(hiddenContainer, allowed));
    }

    @Test
    @DisplayName("an attack-path graph: a hidden repository refused before its API inventory is read")
    void attackPath() {
        assertThat(attackPaths.getAttackPathGraph(seenRepository, allowed)).isPresent();
        refusedAs("Target not found.", () -> attackPaths.getAttackPathGraph(hiddenRepository, allowed));
    }

    @Test
    @DisplayName("the certified scope: a hidden target is neither moved nor told apart from an absent one")
    void certifiedScope() {
        refusedAs("Target not found.",
                () -> scope.setInScope(new ScanTarget.Repository(hiddenRepository), allowed, true, ACTOR));
        assertThat(scope.inScope(Visibility.everything())).doesNotContain(new ScanTarget.Repository(hiddenRepository));

        assertThat(scope.setInScope(new ScanTarget.Repository(seenRepository), allowed, true, ACTOR)).isTrue();
    }

    @Test
    @DisplayName("a ticket: a hidden issue is refused before its missing fields are, so no 400 confirms it")
    void ticket() {
        refusedAs("Issue not found.", () -> tickets.attach(hiddenIssue, allowed, null, null, null, ACTOR));
        assertThatThrownBy(() -> tickets.attach(seenIssue, allowed, null, null, null, ACTOR))
                .isInstanceOf(InvalidInputException.class)
                .hasMessage("Provider, ticket key and URL are required.");
    }

    @Test
    @DisplayName("a scan's documents: every format refuses a hidden scan in the words of an absent one")
    void scanDocuments() {
        assertThat(vex.generateForScan(seenScan, allowed)).isPresent();
        assertThat(csaf.generateForScan(seenScan, allowed)).isPresent();
        assertThat(cycloneDx.generateForScan(seenScan, allowed)).isPresent();

        refusedAs("Scan not found.", () -> vex.generateForScan(hiddenScan, allowed));
        refusedAs("Scan not found.", () -> csaf.generateForScan(hiddenScan, allowed));
        refusedAs("Scan not found.", () -> cycloneDx.generateForScan(hiddenScan, allowed));
        refusedAs("Scan not found.", () -> attestations.generateAttestation(hiddenScan, allowed));
        refusedAs("Scan not found.", () -> attestations.generateAttestation(hiddenScan + 1000, allowed));
    }

    @Test
    @DisplayName("an SBOM diff: either end hidden is refused, so a visible scan cannot read a hidden one")
    void sbomDiff() {
        assertThat(sbomDiff.diff(seenScan, seenScan, allowed)).isPresent();
        refusedAs("Scan not found.", () -> sbomDiff.diff(seenScan, hiddenScan, allowed));
        refusedAs("Scan not found.", () -> sbomDiff.diff(hiddenScan, seenScan, allowed));
    }

    private static void refusedAs(String sentence, ThrowingCallable call) {
        assertThatThrownBy(call).isInstanceOf(NotFoundException.class).hasMessage(sentence);
    }

    private long repository(String url, String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private long scan(long repoId) {
        ScanEntity entity = new ScanEntity();
        entity.setRepoId(repoId);
        entity.setStatus(ScanStatus.COMPLETED.wireName());
        entity.setBranch("main");
        entity.setCreatedAt(Instant.now());
        return scans.save(entity).getId();
    }

    private long issue(long repoId, String fingerprint) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(fingerprint);
        issue.setIdentifier(fingerprint.toUpperCase(java.util.Locale.ROOT));
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setIsKev(false);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }
}
