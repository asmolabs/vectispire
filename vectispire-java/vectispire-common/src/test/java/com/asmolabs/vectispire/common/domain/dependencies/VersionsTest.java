package com.asmolabs.vectispire.common.domain.dependencies;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("comparer des versions")
class VersionsTest {

    @Test
    @DisplayName("range 2.17.1 après 2.9.0, ce qu'un tri de chaînes fait à l'envers")
    void numbersAreNumbers() {
        // **Le cas qui justifie la classe.** Lexicographiquement « 2.9.0 » passe après
        // « 2.17.1 », et l'écran de remédiation conseillerait alors une version qui laisse la
        // faille ouverte — un conseil faux est pire qu'une absence de conseil.
        assertThat(Versions.compare("2.17.1", "2.9.0")).isPositive();
        assertThat(Versions.compare("1.10", "1.9")).isPositive();
        assertThat(Versions.compare("1.0.0", "1.0.0")).isZero();
    }

    @Test
    @DisplayName("lit 2.17 et 2.17.0 comme la même version")
    void missingSegmentsAreZero() {
        assertThat(Versions.compare("2.17", "2.17.0")).isZero();
        assertThat(Versions.compare("2.17.0.0", "2.17")).isZero();
        assertThat(Versions.compare("2.17.1", "2.17")).isPositive();
    }

    @Test
    @DisplayName("préfère un chiffre à un mot, dans le sens sûr")
    void digitsOutrankWords() {
        // Conseiller une version un cran trop haute est sans danger ; conseiller une
        // pré-version à la place de la version finale laisse la faille.
        assertThat(Versions.compare("2.0", "2.rc1")).isPositive();
        assertThat(Versions.compare("1.0.0", "1.0.0-alpha")).isPositive();
    }

    @Test
    @DisplayName("choisit la plus haute d'une liste, et ne choisit rien quand il n'y a rien")
    void highestOfMany() {
        assertThat(Versions.highest(List.of("2.12.2", "2.3.2", "2.17.1"))).contains("2.17.1");
        assertThat(Versions.highest(List.of("  2.17.1  ", ""))).contains("2.17.1");

        // **Vide, et non un texte de remplacement.** « Aucune version corrigée publiée » et
        // « passez à celle-ci » sont deux réponses différentes ; le champ portait la chaîne
        // « latest-patch », affichée derrière une flèche sur le tableau de bord.
        assertThat(Versions.highest(List.of())).isEmpty();
        assertThat(Versions.highest(List.of("", "   "))).isEmpty();
        assertThat(Versions.highest(null)).isEqualTo(Optional.empty());
    }

    @Test
    @DisplayName("découpe la liste que les scanners remontent")
    void splitsWhatScannersReport() {
        // `fix_versions` n'est pas une version mais une énumération : une branche de maintenance
        // corrigée en même temps que la principale y met les deux.
        assertThat(Versions.split("2.12.2, 2.3.2,2.17.1"))
                .containsExactly("2.12.2", "2.3.2", "2.17.1");
        assertThat(Versions.split(null)).isEmpty();
        assertThat(Versions.split("  ")).isEmpty();
    }

    @Test
    @DisplayName("ne lève pas sur un segment plus grand qu'un long")
    void absurdSegmentsDoNotThrow() {
        // Des identifiants de build compactés dépassent la capacité d'un long ; la comparaison
        // retombe alors sur la longueur puis le texte, et surtout ne casse pas l'écran.
        assertThat(Versions.compare("1.99999999999999999999", "1.2")).isPositive();
        assertThat(Versions.highest(List.of("1.99999999999999999999", "1.2")))
                .contains("1.99999999999999999999");
    }
}
