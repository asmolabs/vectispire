package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.SettingsService;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Une porte anonyme ne règle pas un triage.
 *
 * <p><b>Le défaut que ceci ferme, reproduit avant d'être corrigé.</b> Un {@code POST} sans le
 * moindre identifiant — la route est {@code permitAll} dans la chaîne de filtres, le gestionnaire
 * porte {@code @OpenToAnonymous}, et aucun secret n'est configuré par défaut — faisait passer un
 * CVE critique en {@code not_affected} avec la justification
 * {@code vulnerable_code_not_in_execute_path}. La seule barrière était de deviner une référence de
 * ticket, du genre {@code SEC-1234}.
 *
 * <p><b>Ce que cela touchait.</b> Pas un écran : {@code CycloneDxGeneratorService.mapAnalysis}
 * rend {@code not_affected} en {@code analysis.state} de même nom, avec sa justification, dans des
 * documents CycloneDX, OpenVEX et CSAF signés et remis à des tiers. C'est exactement l'affirmation
 * que ce dépôt a déjà retirée une fois en rendant l'analyseur d'atteignabilité unidirectionnel,
 * et l'invariant est réécrit en commentaire juste au-dessus de cette fonction : « le triage vide
 * un composant ; l'atteignabilité, non ». Cette porte était le trou dedans.
 *
 * <p><b>Pourquoi ce cas ne se confond pas avec {@code TicketWebhookAuthRoutesTest}.</b> Celui-là
 * éprouve qui peut entrer, et affirme — à raison — que sans secret la porte reste ouverte, parce
 * que la fermer arrêterait la synchronisation de tous les déploiements existants. Il était juste
 * et muet sur ce qui comptait. Celui-ci éprouve ce qu'on peut faire une fois entré, et c'est lui
 * qui rend le 200 de l'autre acceptable.
 */
@DisplayName("un webhook anonyme ne peut pas clore un triage")
class TicketWebhookCannotSettleTest extends ApiTestBase {

    @Autowired
    private Issues issues;

    @Autowired
    private SettingsService settings;

    private static final String FALSE_POSITIVE = """
            {"issue":{"key":"%s","fields":{
                "status":{"name":"Closed"},
                "resolution":{"name":"False Positive"}}},
             "user":{"displayName":"Responsable Securite"},
             "webhookEvent":"jira:issue_updated"}""";

    @Test
    @DisplayName("sans secret, la décision part en approbation et jamais en « non affecté »")
    void anonymousCannotSettle() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "");
        IssueEntity issue = critical("fp-webhook-settle", "SEC-1234");

        mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(FALSE_POSITIVE.formatted("SEC-1234")))
                .andExpect(status().isOk());

        IssueEntity after = issues.findById(issue.getId()).orElseThrow();

        // **`pending_approval`, et non `not_affected`.** Les deux ne se ressemblent que dans une
        // table : le second se rend en `analysis.state = not_affected` dans les documents signés,
        // le premier s'y rend « en cours d'examen ». C'est toute la différence entre enregistrer
        // ce qu'un tracker dit et le publier à la place d'un humain.
        assertThat(after.getTriageStatus())
                .as("un appel anonyme ne peut pas produire une déclaration « non affecté »")
                .isEqualTo("pending_approval");

        // **L'auteur est l'intégration, pas ce que l'appelant a écrit.** Le nom venait de la
        // charge utile et finissait dans le journal d'audit — inviolable, jamais purgé — comme
        // l'identité de qui a décidé. La chaîne de hachage protège cette entrée d'une
        // modification ultérieure ; elle ne la protège pas d'un mensonge qu'on lui a dicté.
        assertThat(after.getTriagedBy())
                .as("le nom annoncé par l'appelant ne doit pas devenir une identité")
                .isEqualTo("JIRA_webhook");

        // Il reste écrit, parce qu'il est utile à qui enquête — mais comme une donnée rapportée.
        assertThat(after.getTriageComment()).contains("Responsable Securite");
    }

    @Test
    @DisplayName("même avec un secret vérifié : un tracker n'est pas un approbateur")
    void aVerifiedTrackerIsStillNotAnApprover() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "s3cr3t-partage");
        IssueEntity issue = critical("fp-webhook-verified", "SEC-9876");

        // **Le secret authentifie, il n'autorise pas.** Il établit que l'appel vient bien du
        // tracker ; il n'établit pas que quelqu'un a regardé la vulnérabilité. Faire dépendre la
        // clôture du secret aurait déplacé la question au lieu de la trancher — et un tracker
        // dont les transitions sont ouvertes à toute une entreprise n'est pas un contrôle.
        mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .header("X-Vectispire-Token", "s3cr3t-partage")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(FALSE_POSITIVE.formatted("SEC-9876")))
                .andExpect(status().isOk());

        assertThat(issues.findById(issue.getId()).orElseThrow().getTriageStatus())
                .isEqualTo("pending_approval");
    }

    private IssueEntity critical(String fingerprint, String ticketRef) {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint(fingerprint);
        issue.setIdentifier("CVE-2021-44228");
        issue.setType("vulnerability");
        issue.setSeverity("CRITICAL");
        issue.setState("open");
        issue.setTriageStatus("under_review");
        issue.setTicketRef(ticketRef);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue);
    }
}
