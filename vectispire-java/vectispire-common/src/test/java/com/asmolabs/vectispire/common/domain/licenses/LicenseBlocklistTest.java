package com.asmolabs.vectispire.common.domain.licenses;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.sbom.Sbom;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("license blocklist")
class LicenseBlocklistTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Sbom sbom(String json) {
        try {
            return new Sbom(MAPPER.readTree(json));
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static final Sbom TWO_PACKAGES = sbom("""
            {"artifacts": [
              {"name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0", "licenses": ["MIT"]},
              {"name": "lib-b", "version": "2.0", "purl": "pkg:npm/lib-b@2.0",
               "licenses": [{"value": "GPL-3.0-only"}]}
            ]}""");

    @Test
    @DisplayName("reports the components whose license is forbidden")
    void reportsForbiddenLicenses() {
        assertThat(LicenseBlocklist.parse("GPL-3.0-only").violations(TWO_PACKAGES))
                .containsExactly(new LicenseBlocklist.Violation("GPL-3.0-only", "lib-b", "2.0", "pkg:npm/lib-b@2.0"));
    }

    @Test
    @DisplayName("compares without regard to case, and reports the SBOM's own spelling")
    void comparisonIsCaseInsensitive() {
        // The violation carries the license as the component declared it, not as the list did:
        // the operator reads the declaration, and normalizing it would hide a mismatch worth
        // seeing.
        assertThat(LicenseBlocklist.parse("gpl-3.0-ONLY").violations(TWO_PACKAGES))
                .singleElement()
                .satisfies(v -> assertThat(v.license()).isEqualTo("GPL-3.0-only"));
    }

    @Test
    @DisplayName("reports nothing while no list is configured")
    void silentWithoutAList() {
        // Which licenses are forbidden is an organizational decision. A default would impose a
        // legal judgement in the operator's place.
        assertThat(LicenseBlocklist.parse("").violations(TWO_PACKAGES)).isEmpty();
        assertThat(LicenseBlocklist.parse(null).isEmpty()).isTrue();
    }

    @Test
    @DisplayName("accepts both shapes Syft has used for a license")
    void acceptsBothSyftShapes() {
        // Syft emitted plain strings, then objects. Supporting one shape silences the rule at
        // the next version bump — with no error, and with nobody noticing.
        Sbom mixed = sbom("""
                {"artifacts": [
                  {"name": "a", "licenses": ["MIT"]},
                  {"name": "b", "licenses": [{"value": "MIT", "spdxExpression": "MIT"}]},
                  {"name": "c", "licenses": [{"spdxExpression": "MIT"}]}
                ]}""");

        assertThat(LicenseBlocklist.parse("MIT").violations(mixed)).hasSize(3);
    }

    @Test
    @DisplayName("discards entries carrying no value at all")
    void discardsEmptyEntries() {
        Sbom noisy = sbom("""
                {"artifacts": [{"name": "a", "licenses": [{}, "", null, 42]}]}""");

        assertThat(LicenseBlocklist.parse("MIT").violations(noisy)).isEmpty();
    }

    @Test
    @DisplayName("an unreadable SBOM costs this rule, not the scan")
    void unreadableSbomIsEmpty() {
        assertThat(LicenseBlocklist.parse("MIT").violations(sbom("{}"))).isEmpty();
        assertThat(LicenseBlocklist.parse("MIT").violations(sbom("{\"artifacts\": \"unexpected\"}"))).isEmpty();
    }

    @Test
    @DisplayName("parses and normalizes the configured list")
    void parsesTheList() {
        assertThat(LicenseBlocklist.parse(" gpl-3.0-only , AGPL-3.0-only ,").forbidden())
                .containsExactlyInAnyOrder("GPL-3.0-ONLY", "AGPL-3.0-ONLY");
    }
}
