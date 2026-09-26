package com.asmolabs.vectispire.core.services.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.compliance.ScopeCoverage;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.shared.SettingsService;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * How much of the certified scope carries current evidence.
 *
 * <h2>The defect this guards is that the product cannot see it</h2>
 *
 * <p><b>A tool measuring its own coverage always reports full coverage.</b> Every figure in this
 * product is computed over the targets somebody registered; an asset inside the certified scope
 * that was never registered has no row to be missing from. An estate of thirty-one targets, all
 * scanned, reads as complete evidence for a scope covering forty — and no query can notice.
 *
 * <p>So the assertions below are mostly about the declared count, which is the only input that
 * cannot be derived, and about the two ways a missing number can be misread: as a gap of zero, or
 * as a coverage of a hundred per cent.
 */
@DisplayName("the certified scope")
class CertifiedScopeTest extends VectispireContextTest {

    @Autowired
    private CertifiedScopeService scope;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private SettingsService settings;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("names the assets the scope claims that this instance holds no row for")
    void reportsWhatItCannotSee() {
        settings.set(Setting.ISMS_SCOPE_ASSETS, "40");
        inScope(repository("a"));
        inScope(repository("b"));

        ScopeCoverage coverage = scope.coverage(Visibility.everything());

        assertThat(coverage.inScope()).isEqualTo(2);
        assertThat(coverage.unaccountedFor())
                .as("the sentence an assessment opens with, and the one no query can derive")
                .isEqualTo(38);
    }

    @Test
    @DisplayName("reports an undeclared scope as undeclared, never as complete")
    void undeclaredIsNotComplete() {
        inScope(repository("a"));

        ScopeCoverage coverage = scope.coverage(Visibility.everything());

        assertThat(coverage.declared()).isFalse();
        assertThat(coverage.unaccountedFor())
                .as("zero here means nobody said, which is why declared() has to be read first")
                .isZero();
        assertThat(coverage.freshShareOfScope())
                .as("a percentage against an unknown denominator will be quoted, so it must not exist")
                .isEmpty();
    }

    @Test
    @DisplayName("computes the fresh share against the declared scope, not against what it holds")
    void freshShareIsAgainstTheDeclaredScope() {
        settings.set(Setting.ISMS_SCOPE_ASSETS, "10");
        long fresh = repository("fresh");
        inScope(fresh);
        scanned(fresh, 0);

        assertThat(scope.coverage(Visibility.everything()).freshShareOfScope())
                .as("dividing by what the instance holds is how a tool reports 100% on a tenth of an estate")
                .hasValue(10);
    }

    @Test
    @DisplayName("separates a target never scanned from one scanned long ago")
    void neverScannedIsNotStale() {
        settings.set(Setting.COMPLIANCE_FRESHNESS_DAYS, "30");
        long never = repository("never");
        long old = repository("old");
        long recent = repository("recent");
        inScope(never);
        inScope(old);
        inScope(recent);
        scanned(old, 400);
        scanned(recent, 1);

        ScopeCoverage coverage = scope.coverage(Visibility.everything());

        assertThat(coverage.neverScanned())
                .as("a target scanned a year ago produced evidence once; one never scanned never has")
                .isEqualTo(1);
        assertThat(coverage.stale()).isEqualTo(1);
        assertThat(coverage.scannedRecently()).isEqualTo(1);
    }

    @Test
    @DisplayName("leaves a target out of the scope until somebody puts it in")
    void nothingIsInScopeByDefault() {
        repository("unmarked");

        assertThat(scope.coverage(Visibility.everything()).inScope())
                .as("a scope nobody has drawn is an undrawn scope, not the whole estate")
                .isZero();
    }

    @Test
    @DisplayName("shows a restricted reader their slice against the whole declared scope")
    void restrictedReaderSeesTheirSlice() {
        settings.set(Setting.ISMS_SCOPE_ASSETS, "10");
        long mine = repository("mine");
        long theirs = repository("theirs");
        inScope(mine);
        inScope(theirs);

        ScopeCoverage slice =
                scope.coverage(Visibility.only(List.of(new ScanTarget.Repository(mine))));

        assertThat(slice.inScope()).isEqualTo(1);
        assertThat(slice.declaredAssets())
                .as("the scope statement covers what it covers, whoever is looking")
                .isEqualTo(10);
        assertThat(slice.unaccountedFor())
                .as("a reader who cannot see the rest has not been told the rest is fine")
                .isEqualTo(9);
    }

    private void inScope(long repoId) {
        assertThat(scope.setInScope(new ScanTarget.Repository(repoId), true)).isTrue();
    }

    private long repository(String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("ssh://git@example.com/team/" + name + ".git");
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private void scanned(long repoId, int daysAgo) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(clock.instant().minusSeconds(daysAgo * 86_400L));
        scans.save(scan);
    }
}
