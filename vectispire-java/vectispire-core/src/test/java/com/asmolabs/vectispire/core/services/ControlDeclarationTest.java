package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Applicability;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Declaration;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Divergence;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.EvidenceSource;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Implementation;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Statement;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.repositories.AuditLog;
import com.asmolabs.vectispire.core.repositories.ControlDeclarations;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Storing a claim, and what the store refuses to accept as one.
 *
 * <p>The reconciliation rules are covered against the pure model, without a database. What is
 * asserted here is the half that needs one: that a line survives a round trip intact, that
 * revising it does not leave contradictory fields behind, that the two malformed declarations the
 * standard forbids are refused rather than stored, and that writing a claim under somebody's name
 * reaches the audit log — a declaration whose author cannot be established is not evidence.
 */
@DisplayName("declaring a control")
class ControlDeclarationTest extends VectispireContextTest {

    private static final ComplianceFramework ISO = ComplianceFramework.ISO_27001;
    private static final String VULN = "ISO-A.8.8";

    @Autowired
    private StatementOfApplicabilityService soa;

    @Autowired
    private ControlDeclarations declarations;

    @Autowired
    private AuditLog auditLog;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("keeps the line, and the claim reads back as it was written")
    void roundTrips() {
        soa.declare(ISO, VULN, applicable(Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE), "c.moreau");

        Statement statement = soa.statement(ISO, Visibility.everything());
        Declaration stored = lineFor(statement, VULN).declaration();

        assertThat(stored).isNotNull();
        assertThat(stored.applicability()).isEqualTo(Applicability.APPLICABLE);
        assertThat(stored.implementation()).isEqualTo(Implementation.IMPLEMENTED);
        assertThat(stored.evidenceSource()).isEqualTo(EvidenceSource.VECTISPIRE);
        assertThat(stored.decidedBy())
                .as("an unattributed claim is not evidence of anything")
                .isEqualTo("c.moreau");
        assertThat(stored.reviewedAt()).isNotNull();
    }

    @Test
    @DisplayName("revises the existing line rather than adding a second one")
    void revisesInPlace() {
        soa.declare(ISO, VULN, applicable(Implementation.PLANNED, EvidenceSource.VECTISPIRE), "c.moreau");
        soa.declare(ISO, VULN, applicable(Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE), "n.faure");

        assertThat(declarations.findByFramework(ISO.name()))
                .as("the same control declared twice is a contradiction, not a history")
                .hasSize(1);
        assertThat(lineFor(soa.statement(ISO, Visibility.everything()), VULN).declaration())
                .satisfies(line -> {
                    assertThat(line.implementation()).isEqualTo(Implementation.IMPLEMENTED);
                    assertThat(line.decidedBy()).isEqualTo("n.faure");
                });
    }

    @Test
    @DisplayName("drops the implementation when a line is switched to excluded")
    void exclusionClearsTheImplementation() {
        soa.declare(ISO, VULN, applicable(Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE), "c.moreau");

        soa.declare(
                ISO,
                VULN,
                new StatementOfApplicabilityService.Submission(
                        Applicability.EXCLUDED,
                        "No software development inside the certified scope.",
                        Implementation.IMPLEMENTED,
                        EvidenceSource.EXTERNAL,
                        "Scope statement SC-2026-01",
                        "n.faure",
                        null),
                "n.faure");

        Declaration stored = lineFor(soa.statement(ISO, Visibility.everything()), VULN).declaration();

        assertThat(stored.implementation())
                .as("an implementation left on an excluded line reads as a claim that was withdrawn")
                .isNull();
        assertThat(lineFor(soa.statement(ISO, Visibility.everything()), VULN).divergence())
                .isEqualTo(Divergence.NOT_APPLICABLE);
    }

    @Test
    @DisplayName("refuses an exclusion carrying no justification")
    void refusesBareExclusion() {
        assertThatThrownBy(() -> soa.declare(
                        ISO,
                        VULN,
                        new StatementOfApplicabilityService.Submission(
                                Applicability.EXCLUDED, "   ", null, EvidenceSource.EXTERNAL, "elsewhere",
                                "n.faure", null),
                        "n.faure"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("6.1.3");

        assertThat(declarations.findByFramework(ISO.name())).isEmpty();
    }

    @Test
    @DisplayName("refuses evidence held elsewhere that names nowhere")
    void refusesUnlocatedExternalEvidence() {
        assertThatThrownBy(() -> soa.declare(
                        ISO,
                        VULN,
                        new StatementOfApplicabilityService.Submission(
                                Applicability.APPLICABLE, "In scope.", Implementation.IMPLEMENTED,
                                EvidenceSource.EXTERNAL, "  ", "n.faure", null),
                        "n.faure"))
                .as("a line that opts out of the measurement and names nothing in its stead is a blank")
                .isInstanceOf(IllegalArgumentException.class);

        assertThat(declarations.findByFramework(ISO.name())).isEmpty();
    }

    @Test
    @DisplayName("refuses an applicable control with nothing said about its implementation")
    void refusesApplicableWithoutImplementation() {
        assertThatThrownBy(() -> soa.declare(
                        ISO,
                        VULN,
                        new StatementOfApplicabilityService.Submission(
                                Applicability.APPLICABLE, "In scope.", null, EvidenceSource.VECTISPIRE,
                                null, "n.faure", null),
                        "n.faure"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("writes the claim to the audit log under its author")
    void writesToTheAuditLog() {
        soa.declare(ISO, VULN, applicable(Implementation.IMPLEMENTED, EvidenceSource.VECTISPIRE), "c.moreau");

        assertThat(auditLog.findAllByOrderByTimestampAscIdAsc())
                .filteredOn(entry -> AuditOperation.CONTROL_DECLARED.wireName().equals(entry.getOperationType()))
                .singleElement()
                .satisfies(entry -> {
                    assertThat(entry.getUserId()).isEqualTo("c.moreau");
                    assertThat(entry.getResourceId()).contains(VULN);
                });
    }

    @Test
    @DisplayName("lists a lapsed review across frameworks")
    void listsLapsedReviews() {
        soa.declare(
                ISO,
                VULN,
                new StatementOfApplicabilityService.Submission(
                        Applicability.APPLICABLE, "In scope.", Implementation.IMPLEMENTED,
                        EvidenceSource.VECTISPIRE, null, "n.faure",
                        clock.instant().minusSeconds(86_400)),
                "n.faure");

        assertThat(soa.reviewOverdue())
                .singleElement()
                .satisfies(line -> assertThat(line.controlId()).isEqualTo(VULN));
    }

    @Test
    @DisplayName("reports every unaddressed control, so an empty document is not a clean one")
    void emptyDocumentIsIncomplete() {
        Statement statement = soa.statement(ISO, Visibility.everything());

        assertThat(statement.complete()).isFalse();
        assertThat(statement.declared()).isZero();
        assertThat(statement.findings())
                .as("clause 6.1.3 d asks for every control addressed; silence is the gap")
                .isEqualTo(statement.total());
    }

    private static StatementOfApplicabilityService.Submission applicable(
            Implementation implementation, EvidenceSource source) {
        return new StatementOfApplicabilityService.Submission(
                Applicability.APPLICABLE,
                "In scope.",
                implementation,
                source,
                source == EvidenceSource.VECTISPIRE ? null : "Named elsewhere",
                "n.faure",
                null);
    }

    private static com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Line lineFor(
            Statement statement, String controlId) {
        return statement.lines().stream()
                .filter(line -> line.control().id().equals(controlId))
                .findFirst()
                .orElseThrow();
    }
}
