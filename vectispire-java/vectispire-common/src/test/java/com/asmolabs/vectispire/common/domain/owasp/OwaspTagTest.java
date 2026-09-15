package com.asmolabs.vectispire.common.domain.owasp;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Lire la catégorie qu'une règle déclare, sans la deviner.
 *
 * <p>Le cas qui porte tout ce fichier est le troisième : <b>{@code A01:2017} est Injection et
 * {@code A01:2021} est Broken Access Control</b>, et les règles amont portent les deux éditions
 * côte à côte. Un motif lisant {@code A\d\d} rangerait donc les injections sous le contrôle
 * d'accès — une réponse fausse qui a l'air juste, dans le seul document qu'un évaluateur lit
 * catégorie par catégorie.
 */
@DisplayName("la catégorie OWASP déclarée par une règle")
class OwaspTagTest {

    @Test
    @DisplayName("lit la forme en bloc, qui est celle des règles amont")
    void theBlockForm() {
        String rule = """
                rules:
                  - id: python.lang.security.eval
                    metadata:
                      category: security
                      owasp:
                        - A03:2021 - Injection
                      cwe:
                        - CWE-95
                """;

        assertThat(OwaspTag.declaredIn(rule)).containsExactly("A03");
    }

    @Test
    @DisplayName("lit la forme sur une seule ligne")
    void theInlineForm() {
        assertThat(OwaspTag.declaredIn("    metadata:\n      owasp: A10:2021 - Server-Side Request Forgery\n"))
                .containsExactly("A10");
    }

    @Test
    @DisplayName("ne retient que l'édition 2021, parce que les deux partagent les lettres")
    void theEditionsDoNotShareMeaning() {
        String bothEditions = """
                    metadata:
                      owasp:
                        - A01:2017 - Injection
                        - A03:2021 - Injection
                """;

        // A01:2017 est Injection ; A01:2021 est Broken Access Control. Accepter le premier
        // rangerait une injection sous le contrôle d'accès, et la grille l'annoncerait comme
        // mesurée.
        assertThat(OwaspTag.declaredIn(bothEditions))
                .as("l'édition 2017 ne se convertit pas, elle s'ignore")
                .containsExactly("A03");
    }

    @Test
    @DisplayName("ne déclare rien quand la règle ne connaît que l'édition 2017")
    void onlyTheOldEdition() {
        assertThat(OwaspTag.declaredIn("      owasp:\n        - A1:2017 - Injection\n")).isEmpty();
    }

    @Test
    @DisplayName("ignore une catégorie citée en prose, hors du bloc de métadonnées")
    void proseIsNotADeclaration() {
        String rule = """
                rules:
                  - id: something
                    message: >-
                      This is the kind of thing A03:2021 talks about, but this rule does not
                      declare it.
                    metadata:
                      category: security
                """;

        // Une règle dont le message cite une catégorie serait comptée comme la déclarant, et la
        // grille annoncerait une couverture que les règles installées ne produisent pas.
        assertThat(OwaspTag.declaredIn(rule)).isEmpty();
    }

    @Test
    @DisplayName("lit plusieurs règles d'un même fichier, et garde l'ordre du fichier")
    void severalRulesInOneFile() {
        String file = """
                rules:
                  - id: one
                    metadata:
                      owasp:
                        - A03:2021 - Injection
                  - id: two
                    metadata:
                      owasp:
                        - A01:2021 - Broken Access Control
                        - A03:2021 - Injection
                """;

        // Un ensemble ordonné : deux lectures du même corpus doivent produire la même liste,
        // sans quoi la grille d'aujourd'hui ne se compare pas à celle d'hier.
        assertThat(OwaspTag.declaredIn(file)).containsExactly("A03", "A01");
    }

    @Test
    @DisplayName("un fichier vide, absent ou sans métadonnées ne déclare rien")
    void nothingDeclared() {
        assertThat(OwaspTag.declaredIn(null)).isEmpty();
        assertThat(OwaspTag.declaredIn("")).isEmpty();
        assertThat(OwaspTag.declaredIn("rules:\n  - id: x\n    severity: ERROR\n")).isEmpty();
    }

    @Test
    @DisplayName("la valeur d'un constat donne une catégorie, ou rien")
    void oneFindingsValue() {
        assertThat(OwaspTag.categoryOf("A03:2021 - Injection")).contains("A03");
        assertThat(OwaspTag.categoryOf("A01:2017 - Injection")).isEmpty();
        assertThat(OwaspTag.categoryOf("")).isEmpty();
        assertThat(OwaspTag.categoryOf(null)).isEmpty();
    }
}
