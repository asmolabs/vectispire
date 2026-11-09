package com.asmolabs.vectispire.common.domain.owasp;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Reading the category a rule declares, without guessing it.
 *
 * <p>The case that carries this whole file is the third: <b>{@code A01:2017} is Injection and
 * {@code A01:2021} is Broken Access Control</b>, and the upstream rules carry both editions side
 * by side. A pattern reading {@code A\d\d} would therefore file injections under access control —
 * a wrong answer that looks right, in the one document an assessor reads category by category.
 */
@DisplayName("the OWASP category a rule declares")
class OwaspTagTest {

    @Test
    @DisplayName("reads the block form, which is the upstream rules'")
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
    @DisplayName("keeps only the 2021 edition, because the two share their letters")
    void theEditionsDoNotShareMeaning() {
        String bothEditions = """
                    metadata:
                      owasp:
                        - A01:2017 - Injection
                        - A03:2021 - Injection
                """;

        // A01:2017 is Injection; A01:2021 is Broken Access Control. Accepting the first would file
        // an injection under access control, and the grid would announce it as measured.
        assertThat(OwaspTag.declaredIn(bothEditions))
                .as("the 2017 edition is not converted, it is ignored")
                .containsExactly("A03");
    }

    @Test
    @DisplayName("declares nothing when the rule knows only the 2017 edition")
    void onlyTheOldEdition() {
        assertThat(OwaspTag.declaredIn("      owasp:\n        - A1:2017 - Injection\n")).isEmpty();
    }

    @Test
    @DisplayName("ignores a category quoted in prose, outside the metadata block")
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

        // A rule whose message quotes a category would be counted as declaring it, and the grid
        // would announce a coverage the installed rules do not produce.
        assertThat(OwaspTag.declaredIn(rule)).isEmpty();
    }

    @Test
    @DisplayName("reads several rules from one file, and keeps the file's order")
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

        // An ordered set: two readings of the same corpus must produce the same list, without
        // which today's grid does not compare with yesterday's.
        assertThat(OwaspTag.declaredIn(file)).containsExactly("A03", "A01");
    }

    @Test
    @DisplayName("an empty, absent or metadata-less file declares nothing")
    void nothingDeclared() {
        assertThat(OwaspTag.declaredIn(null)).isEmpty();
        assertThat(OwaspTag.declaredIn("")).isEmpty();
        assertThat(OwaspTag.declaredIn("rules:\n  - id: x\n    severity: ERROR\n")).isEmpty();
    }

    @Test
    @DisplayName("a finding's value gives a category, or nothing")
    void oneFindingsValue() {
        assertThat(OwaspTag.categoryOf("A03:2021 - Injection")).contains("A03");
        assertThat(OwaspTag.categoryOf("A01:2017 - Injection")).isEmpty();
        assertThat(OwaspTag.categoryOf("")).isEmpty();
        assertThat(OwaspTag.categoryOf(null)).isEmpty();
    }

    @Test
    @DisplayName("a rule tagged with the 2025 edition alone places nothing, and says why")
    void the2025EditionIsNamedNotPlaced() {
        String only2025 = """
                rules:
                  - id: team.access
                    metadata:
                      owasp:
                        - A01:2025 - Broken Access Control
                """;

        // Decision 0046: 2021 for 1.0. A01:2025 is not translated into a 2021 letter — the editions
        // share letters, not meanings — but the rule must not vanish without a word either.
        assertThat(OwaspTag.declaredIn(only2025)).isEmpty();
        assertThat(OwaspTag.untaggedReasonOf(only2025)).contains(OwaspTag.Untagged.ONLY_2025_EDITION);
        assertThat(OwaspTag.untaggedReasonOf("      owasp: A10:2025 - Mishandling of Exceptional Conditions\n"))
                .as("the inline form too")
                .contains(OwaspTag.Untagged.ONLY_2025_EDITION);
    }

    @Test
    @DisplayName("names why a rule is untagged: the 2021 edition beside 2025 is tagged, 2017 alone and nothing are not")
    void untaggedReasons() {
        assertThat(OwaspTag.untaggedReasonOf("      owasp:\n        - A01:2025 - X\n        - A01:2021 - X\n"))
                .as("a 2021 declaration places the rule, whatever else it names")
                .isEmpty();
        assertThat(OwaspTag.untaggedReasonOf("      owasp:\n        - A1:2017 - Injection\n"))
                .contains(OwaspTag.Untagged.ONLY_2017_EDITION);
        assertThat(OwaspTag.untaggedReasonOf("      owasp:\n        - A1:2017 - X\n        - A03:2025 - X\n"))
                .as("the newer edition is the one named")
                .contains(OwaspTag.Untagged.ONLY_2025_EDITION);
        assertThat(OwaspTag.untaggedReasonOf("rules:\n  - id: x\n    message: see A01:2025\n"))
                .as("prose is no declaration, of any edition")
                .contains(OwaspTag.Untagged.NOT_DECLARED);
        assertThat(OwaspTag.untaggedReasonOf(null)).contains(OwaspTag.Untagged.NOT_DECLARED);
    }

    @Test
    @DisplayName("counts the rule files, tagged and untagged by reason, in the reasons' order")
    void theTally() {
        OwaspTag.OwaspTagging tagging = OwaspTag.tally(List.of(
                "      owasp:\n        - A03:2021 - Injection\n",
                "rules: []\n",
                "      owasp:\n        - A05:2025 - Injection\n",
                "      owasp:\n        - A02:2025 - Security Misconfiguration\n"));

        assertThat(tagging.ruleFiles()).isEqualTo(4);
        assertThat(tagging.tagged()).isEqualTo(1);
        assertThat(tagging.byCwe()).isZero();
        assertThat(tagging.untagged()).containsExactly(
                new OwaspTag.OwaspUntaggedCount(OwaspTag.Untagged.ONLY_2025_EDITION, 2),
                new OwaspTag.OwaspUntaggedCount(OwaspTag.Untagged.NOT_DECLARED, 1));
    }

    @Test
    @DisplayName("places a rule declaring no 2021 category by its CWE, and its own category first")
    void placedByItsCwe() {
        String cweOnly = """
                rules:
                  - id: java.sqli
                    metadata:
                      cwe:
                        - "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
                """;
        String both = """
                    metadata:
                      owasp:
                        - A01:2021 - Broken Access Control
                      cwe:
                        - "CWE-89: SQL injection"
                """;

        assertThat(OwaspTag.declaredIn(cweOnly)).as("declared, it is not").isEmpty();
        assertThat(OwaspTag.placedIn(cweOnly)).containsExactly("A03");
        assertThat(OwaspTag.placedIn(both)).as("the rule's own category is the first word").containsExactly("A01");
        assertThat(OwaspTag.placedIn("      cwe: CWE-1078\n")).as("a CWE no list holds").isEmpty();
        assertThat(OwaspTag.placedIn("    message: see CWE-89\n")).as("prose is no declaration").isEmpty();
    }

    @Test
    @DisplayName("counts a rule placed by its CWE apart from the tagged and the untagged")
    void theTallyCountsTheCwe() {
        OwaspTag.OwaspTagging tagging = OwaspTag.tally(List.of(
                "      owasp:\n        - A03:2021 - Injection\n",
                "      owasp:\n        - A10:2025 - X\n      cwe:\n        - CWE-918\n",
                "      owasp:\n        - A10:2025 - X\n"));

        assertThat(tagging.tagged()).isEqualTo(1);
        assertThat(tagging.byCwe()).as("a 2025 tag beside a CWE that maps: placed").isEqualTo(1);
        assertThat(tagging.untagged()).containsExactly(
                new OwaspTag.OwaspUntaggedCount(OwaspTag.Untagged.ONLY_2025_EDITION, 1));
    }
}
