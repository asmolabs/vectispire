package com.asmolabs.vectispire.common.domain.owasp;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The OWASP Top 10 2021 category of a CWE, by the standard's own "List of Mapped CWEs".
 *
 * <p>The first case is the one that keeps the table honest: each category's page states how many CWEs
 * it maps ("CWEs Mapped"), and a list copied short or long — or a CWE filed under two categories, so a
 * finding counted twice — shows here as a count that is not the page's.
 */
@DisplayName("the OWASP 2021 category of a CWE")
class OwaspCweTest {

    @Test
    @DisplayName("maps as many CWEs to each category as its page says it maps")
    void theListsAreTheStandards() {
        Map<String, Long> stated = new LinkedHashMap<>();
        stated.put("A01", 34L);
        stated.put("A02", 29L);
        stated.put("A03", 33L);
        stated.put("A04", 40L);
        stated.put("A05", 20L);
        stated.put("A06", 3L);
        stated.put("A07", 22L);
        stated.put("A08", 10L);
        stated.put("A09", 4L);
        stated.put("A10", 1L);

        stated.forEach((category, count) -> assertThat(OwaspCwe.mappedTo(category)).as(category).isEqualTo(count));
    }

    @Test
    @DisplayName("files the hard-coded password under A07, which counts it, and not A02, which only lists it")
    void theOneCweTwoListsName() {
        assertThat(OwaspCwe.categoryOf(259)).contains("A07");
        // The same category as a hard-coded credential (CWE-798) and as a secret the scanner finds.
        assertThat(OwaspCwe.categoryOf(798)).contains("A07");
    }

    @Test
    @DisplayName("reads the declaration as the upstream rules write it")
    void theDeclaration() {
        assertThat(OwaspCwe.categoryOfDeclaration("CWE-89: Improper Neutralization of Special Elements used in an SQL Command"))
                .contains("A03");
        assertThat(OwaspCwe.categoryOfDeclaration("cwe-918")).contains("A10");
        assertThat(OwaspCwe.categoryOfDeclaration("CWE-1078, then CWE-22")).as("the first that maps").contains("A01");
        assertThat(OwaspCwe.categoryOfDeclaration("CWE-1078: Inappropriate Source Code Style")).isEmpty();
        assertThat(OwaspCwe.categoryOfDeclaration("CWE-99999999999")).as("a number no int holds").isEmpty();
        assertThat(OwaspCwe.categoryOfDeclaration(null)).isEmpty();
        assertThat(OwaspCwe.categoryOfDeclaration("ACWE-89")).as("a word, not a CWE").isEmpty();
    }
}
