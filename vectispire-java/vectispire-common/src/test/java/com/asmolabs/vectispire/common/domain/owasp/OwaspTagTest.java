package com.asmolabs.vectispire.common.domain.owasp;

import static org.assertj.core.api.Assertions.assertThat;

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
}
