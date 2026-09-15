package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.AuditLog;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Rattacher un ticket existant à un constat.
 *
 * <h2>Pourquoi ce point d'entrée existe</h2>
 *
 * <p><b>La balayeuse ouvrait des tickets, et personne d'autre ne pouvait en rattacher un.</b>
 * Elle ne s'occupe que des constats qui violent la barrière, avec le traqueur configuré
 * globalement. Une équipe qui suit un constat dans {@code SEC-1234} n'avait aucun moyen de le
 * dire — et le webhook de fermeture, qui cherche le constat <em>par sa référence</em>, ne pouvait
 * donc pas la reconnaître.
 *
 * <p>Les cas portent sur le champ visé autant que sur l'écriture : c'est {@code ticketRef} que la
 * liste affiche, que le webhook cherche et que la balayeuse lit. Une seconde table existe pour
 * cela, avec son propre point d'entrée, et rien ne la lit — y écrire aurait livré un rattachement
 * que la synchronisation ignore.
 */
@DisplayName("le rattachement d'un ticket")
class AttachTicketRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private AuditLog auditLogs;

    @Test
    @DisplayName("écrit la référence que le webhook cherchera, et la rend")
    void attachesTheReferenceTheWebhookLooksFor() throws Exception {
        long id = seedIssue();

        mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "SEC-1234", "url", "https://tracker.invalid/SEC-1234"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticketRef").value("SEC-1234"));

        // Le champ, et non la seconde table : c'est celui-là que `findByTicketRefOrIid` cherche.
        assertThat(issues.findByTicketRefOrIid("SEC-1234"))
                .as("le webhook du traqueur doit pouvoir retrouver ce constat par sa référence")
                .isPresent()
                .get()
                .satisfies(issue -> assertThat(issue.getId()).isEqualTo(id));
    }

    @Test
    @DisplayName("accepte une référence sans URL, parce qu'un traqueur interne n'en a pas toujours")
    void theUrlIsOptional() throws Exception {
        long id = seedIssue();

        mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "#87"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticketRef").value("#87"));

        // Exiger une URL ferait de la référence seule une saisie refusée, alors que la liste sait
        // déjà l'afficher sans lien.
        assertThat(issues.findById(id).orElseThrow().getTicketUrl()).isNull();
    }

    @Test
    @DisplayName("refuse une référence vide plutôt que d'effacer celle qui existe")
    void anEmptyReferenceIsRefused() throws Exception {
        long id = seedIssue();
        issues.attachTicket(id, "SEC-1", "https://tracker.invalid/SEC-1");

        mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "   "))))
                .andExpect(status().isBadRequest());

        // Un champ vidé par mégarde rendrait le constat invisible au webhook *et* rouvrirait la
        // porte à un second ticket de la balayeuse, sans que rien ne le dise.
        assertThat(issues.findById(id).orElseThrow().getTicketRef()).isEqualTo("SEC-1");
    }

    @Test
    @DisplayName("laisse un humain corriger sa faute de frappe, et l'écrit au journal")
    void aHumanMayCorrectTheReference() throws Exception {
        long id = seedIssue();
        issues.attachTicket(id, "SEC-1233", null);

        mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "SEC-1234"))))
                .andExpect(status().isOk());

        assertThat(issues.findById(id).orElseThrow().getTicketRef()).isEqualTo("SEC-1234");

        // Remplacer la référence change qui peut refermer ce constat depuis l'extérieur : c'est
        // une décision, et elle se trace comme telle.
        assertThat(auditLogs.findAll())
                .anySatisfy(entry -> assertThat(entry.getDescription())
                        .contains("changed from SEC-1233 to SEC-1234"));
    }

    @Test
    @DisplayName("refuse un compte qui ne peut rien changer")
    void anAuditorMayNotAttach() throws Exception {
        long id = seedIssue();

        mvc.perform(authenticated(put("/api/v1/issues/" + id + "/ticket"), asAuditor())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "SEC-1234"))))
                .andExpect(status().isForbidden());

        assertThat(issues.findById(id).orElseThrow().getTicketRef()).isNull();
    }

    @Test
    @DisplayName("répond 404 sur un constat qui n'existe pas")
    void anAbsentIssueIsNotFound() throws Exception {
        mvc.perform(authenticated(put("/api/v1/issues/999999/ticket"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("reference", "SEC-1234"))))
                .andExpect(status().isNotFound());
    }

    private long seedIssue() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/tickets.git");
        repository.setBranch("main");
        long repoId = repositories.save(repository).getId();

        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-ticket-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-4242");
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.parse("2026-09-01T10:00:00Z"));
        issue.setLastSeenAt(Instant.parse("2026-09-01T10:00:00Z"));
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }
}
