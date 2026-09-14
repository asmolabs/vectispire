package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceControl;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEvaluation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Components;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Clock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * What the supply-chain control actually counts.
 *
 * <h2>The defect, and why nothing could see it</h2>
 *
 * <p><b>The control was handed the observed-target count under the name {@code targetsWithSbom}.</b>
 * Both are ints, both arrive in the same constructor, and the two are equal on any estate where
 * every scan happens to produce an inventory — which is most of them. So the assessment printed
 * "31/31 monitored targets have an active Software Bill of Materials" whenever thirty-one targets
 * had been scanned, and the sentence went into the evidence bundle as written.
 *
 * <p>The case below is the one that separates them and the one nothing exercised: a target that
 * was scanned, successfully, and produced no components.
 */
@DisplayName("the supply-chain control")
class SupplyChainCoverageTest extends VectispireContextTest {

    @Autowired
    private ComplianceService compliance;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private Components components;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("does not count a scanned target that produced no inventory")
    void aScanIsNotAnInventory() {
        long withInventory = repository("has-sbom");
        long withoutInventory = repository("no-sbom");
        component(scan(withInventory), "pkg:maven/org.example/lib@1.0.0");
        scan(withoutInventory);

        assertThat(score())
                .as("a scan that yielded nothing is not evidence of an inventory")
                .isEqualTo(50);
        assertThat(details())
                .as("the sentence an assessor reads out of the bundle")
                .contains("1/2");
    }

    @Test
    @DisplayName("counts a target whose inventory was recorded, whatever the raw payload's age")
    void inventorySurvivesTheRetentionWindow() {
        long target = repository("old-but-inventoried");
        ScanEntity old = new ScanEntity();
        old.setRepoId(target);
        old.setBranch("main");
        old.setStatus("completed");
        // Older than any retention window: the sbom blob would have been purged long ago.
        old.setCreatedAt(clock.instant().minusSeconds(500L * 86_400));
        component(scans.save(old).getId(), "pkg:npm/left-pad@1.3.0");

        assertThat(score())
                .as("components are the durable projection; reading the purgeable blob would decay this")
                .isEqualTo(100);
    }

    @Test
    @DisplayName("counts a never-scanned target against the estate without a coverage cap")
    void neverScannedLandsInTheDenominator() {
        long inventoried = repository("scanned");
        repository("never-scanned");
        component(scan(inventoried), "pkg:maven/org.example/lib@1.0.0");

        assertThat(score())
                .as("scored on a presence, which is the one shape that reads a never-scanned target right")
                .isEqualTo(50);
    }

    private int score() {
        return assessment().scorePercentage();
    }

    private String details() {
        return assessment().details();
    }

    private ComplianceEvaluation.ControlAssessment assessment() {
        return compliance.getEvaluation(ComplianceFramework.NIS_2, Visibility.everything()).controls().stream()
                .filter(control -> control.control().category() == ComplianceControl.Category.SUPPLY_CHAIN)
                .findFirst()
                .orElseThrow();
    }

    private long repository(String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("ssh://git@example.com/team/" + name + ".git");
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private long scan(long repoId) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(clock.instant());
        return scans.save(scan).getId();
    }

    private void component(long scanId, String purl) {
        ComponentEntity component = new ComponentEntity();
        component.setScanId(scanId);
        component.setPurl(purl);
        component.setName(purl);
        components.save(component);
    }
}
