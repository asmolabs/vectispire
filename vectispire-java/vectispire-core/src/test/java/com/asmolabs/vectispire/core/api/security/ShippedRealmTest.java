package com.asmolabs.vectispire.core.api.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Le realm que le profil {@code sso} importe.
 *
 * <p><b>Deux réglages y cassent en silence, et ce sont ceux que l'on rate en configurant Keycloak
 * à la main.</b> Le fichier est livré précisément pour éviter cette configuration manuelle ; s'il
 * porte lui-même l'erreur, il la répand au lieu de l'épargner, et rien ne le dit — la connexion
 * réussit, les équipes restent vides, et personne ne sait pourquoi.
 *
 * <p>Ce cas ne démarre pas Keycloak : {@code SingleSignOnIntegrationTest} conduit le flux complet
 * contre un vrai serveur, avec son propre realm à URI joker parce qu'il tourne sur un port
 * aléatoire. Celui-ci garde le contenu du fichier expédié, ce que l'autre ne peut pas faire.
 */
@DisplayName("le realm livré avec le profil sso")
class ShippedRealmTest {

    /** Depuis le répertoire du module, la racine du dépôt est deux crans plus haut. */
    private static final Path REALM = Path.of("../../ci/keycloak/vectispire-realm.json");

    private static JsonNode realm() throws Exception {
        assertThat(Files.exists(REALM))
                .as("le realm livré est introuvable en %s — un test qui ne trouve pas son sujet "
                        + "passerait pour toujours", REALM.toAbsolutePath().normalize())
                .isTrue();
        return new ObjectMapper().readTree(Files.readString(REALM));
    }

    @Test
    @DisplayName("le mapper de groupes émet des noms simples, pas des chemins")
    void theGroupMapperEmitsPlainNames() throws Exception {
        JsonNode mapper = realm().at("/clients/0/protocolMappers/0/config");

        // **Le piège numéro un.** `ExternalIdentityService.syncGroups` apparie la valeur reçue au
        // nom d'équipe. Chemin complet activé, Keycloak émet « /AppSec », aucune équipe ne
        // s'appelle ainsi, et la synchronisation ne fait rien — sans erreur, sans journal, sans
        // rien qui permette de deviner.
        assertThat(mapper.path("full.path").asText())
                .as("chemin complet = aucune équipe ne correspond jamais")
                .isEqualTo("false");
        assertThat(mapper.path("claim.name").asText()).isEqualTo("groups");
        assertThat(mapper.path("id.token.claim").asText())
                .as("la revendication est lue sur le jeton d'identité")
                .isEqualTo("true");
    }

    @Test
    @DisplayName("l'URI de redirection est celle que Spring Security écoute")
    void theRedirectUriMatchesTheFilterChain() throws Exception {
        // **Le piège numéro deux.** Le chemin n'est pas au choix : c'est celui du filtre
        // `oauth2Login`. Une URI approchante donne un « invalid redirect_uri » que l'on passe une
        // demi-journée à imputer au client, au secret ou à l'issuer.
        assertThat(realm().at("/clients/0/redirectUris"))
                .allSatisfy(uri -> assertThat(uri.asText()).endsWith("/login/oauth2/code/oidc"));
    }

    @Test
    @DisplayName("le compte du realm porte le nom que l'amorçage crée par défaut")
    void theRealmUserMatchesTheBootstrapAccount() throws Exception {
        // Aucun compte n'est créé à la connexion : la première liaison se fait sur le nom
        // d'utilisateur. Si les deux ne coïncident pas, personne n'entre une fois le mot de passe
        // fermé — et c'est au moment de le fermer qu'on s'en aperçoit.
        assertThat(realm().at("/users/0/username").asText())
                .as("doit valoir le défaut de VECTISPIRE_BOOTSTRAP_USERNAME dans docker-compose.yml")
                .isEqualTo("admin");
    }
}
