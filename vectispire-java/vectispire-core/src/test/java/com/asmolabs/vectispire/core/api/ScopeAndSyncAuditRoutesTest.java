package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Two gestures that wrote no audit entry: the EPSS screen's feed synchronisation, and putting a
 * target in or out of the certified scope.
 *
 * <p>The first ran the same outbound call and the same re-evaluation of the backlog as the threat
 * intelligence screen's sync, which was audited; the second moves the denominator of the coverage an
 * assessment reads, and left the flag changed on the target's row with nobody named.
 */
@DisplayName("the certified scope and the feed synchronisation, in the audit log")
class ScopeAndSyncAuditRoutesTest extends ApiTestBase {

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Test
    @DisplayName("the EPSS screen's sync is recorded, under the lead who asked, like the threat intelligence screen's")
    void bothSyncsAreRecorded() throws Exception {
        String lead = "lead-" + System.nanoTime();
        String token = tokenFor(lead, Role.CISO, false);

        mvc.perform(authenticated(post("/api/v1/epss/sync"), token)).andExpect(status().isOk());
        mvc.perform(authenticated(post("/api/v1/threat-intel/sync"), token)).andExpect(status().isOk());

        assertThat(entries(AuditOperation.THREAT_INTEL_SYNCED, "threat_intel"))
                .filteredOn(entry -> lead.equals(entry.getUserId()))
                .extracting(AuditLogEntity::getDescription)
                .hasSize(2)
                .anySatisfy(epss -> assertThat(epss).contains("from the EPSS screen").contains("KEV="))
                .anySatisfy(intel -> assertThat(intel).contains("from the threat intelligence screen"));
    }

    @Test
    @DisplayName("putting a repository or an image in or out of the certified scope is recorded, and a no-op is not")
    void scopeChangesAreRecorded() throws Exception {
        String lead = "scope-lead-" + System.nanoTime();
        String token = tokenFor(lead, Role.CISO, false);
        long repository = repository();
        long image = container();

        scope(token, "repositories", repository, true);
        scope(token, "repositories", repository, true);
        scope(token, "repositories", repository, false);
        scope(token, "containers", image, true);

        // A repository and an image may share an id; the entry names the kind in its words.
        assertThat(entries(AuditOperation.CERTIFIED_SCOPE_CHANGED, String.valueOf(repository)))
                .filteredOn(entry -> entry.getDescription().startsWith("Repository "))
                .as("in, then out — the second \"in\" changed nothing")
                .allSatisfy(entry -> assertThat(entry.getUserId()).isEqualTo(lead))
                .extracting(AuditLogEntity::getDescription)
                .containsExactlyInAnyOrder(
                        "Repository " + repository + " put in the certified scope",
                        "Repository " + repository + " taken out of the certified scope");
        assertThat(entries(AuditOperation.CERTIFIED_SCOPE_CHANGED, String.valueOf(image)))
                .filteredOn(entry -> entry.getDescription().startsWith("Image "))
                .extracting(AuditLogEntity::getDescription)
                .containsExactly("Image " + image + " put in the certified scope");
    }

    @Test
    @DisplayName("a reader's attempt changes nothing and records no scope change")
    void aReaderIsRefused() throws Exception {
        long repository = repository();

        mvc.perform(authenticated(put("/api/v1/compliance/scope/repositories/" + repository)
                                .param("in_scope", "true"), asReader()))
                .andExpect(status().isForbidden());

        assertThat(entries(AuditOperation.CERTIFIED_SCOPE_CHANGED, String.valueOf(repository))).isEmpty();
        assertThat(repositories.findById(repository).orElseThrow().isInCertifiedScope()).isFalse();
    }

    @Test
    @DisplayName("an id nobody registered is refused as a hidden one is — 404, \"Target not found.\" — and records nothing")
    void anAbsentTargetIsNotFound() throws Exception {
        // `false` used to mean both "unchanged" and "absent", so the route answered 200 for a
        // write to nothing. A repository and an image are asked separately: each kind has its row.
        String token = tokenFor("scope-absent-" + System.nanoTime(), Role.CISO, false);
        long absent = Long.MAX_VALUE - 7;

        for (String kind : List.of("repositories", "containers")) {
            mvc.perform(authenticated(put("/api/v1/compliance/scope/" + kind + "/" + absent)
                                    .param("in_scope", "true"), token))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.detail").value("Target not found."));
        }
        assertThat(entries(AuditOperation.CERTIFIED_SCOPE_CHANGED, String.valueOf(absent))).isEmpty();
    }

    private void scope(String token, String kind, long id, boolean inScope) throws Exception {
        mvc.perform(authenticated(put("/api/v1/compliance/scope/" + kind + "/" + id)
                                .param("in_scope", String.valueOf(inScope)), token))
                .andExpect(status().isOk());
    }

    /** The entries of one operation about one resource. The order is the chain's, not asserted here. */
    private List<AuditLogEntity> entries(AuditOperation operation, String resourceId) {
        return auditLog.findAll().stream()
                .filter(entry -> operation.wireName().equals(entry.getOperationType()))
                .filter(entry -> resourceId.equals(entry.getResourceId()))
                .toList();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/scope-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long container() {
        ContainerEntity image = new ContainerEntity();
        image.setImageName("team/scope-" + System.nanoTime());
        image.setTag("latest");
        return containers.save(image).getId();
    }
}
