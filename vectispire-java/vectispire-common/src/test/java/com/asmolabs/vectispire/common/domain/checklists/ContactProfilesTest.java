package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.checklists.ContactProfiles.Profile;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the profiles a template's contact column names")
class ContactProfilesTest {

    @Test
    @DisplayName("every value the column holds is a profile, as first written, each once")
    void everyValueIsAProfile() {
        // The column of a real template's second version, in invented order: two spellings of one profile,
        // a shared line, and a profile no closed list of PO, BA and architect would have named.
        List<Profile> profiles = ContactProfiles.of(Arrays.asList("PO", "Arch", "PO / BA", "SII", "ARCH ", "po"));

        assertThat(profiles).containsExactly(
                new Profile("PO", "PO"), new Profile("ARCH", "Arch"), new Profile("BA", "BA"), new Profile("SII", "SII"));
    }

    @Test
    @DisplayName("a line Vectispire measures names no profile, in any case")
    void automaticIsNoProfile() {
        assertThat(ContactProfiles.of(Arrays.asList("AUTO", "auto", " Auto "))).isEmpty();
        assertThat(ContactProfiles.keysOf("AUTO / PO")).containsExactly("PO");
    }

    @Test
    @DisplayName("a blank cell names nobody, and neither do empty parts")
    void blanksNameNobody() {
        assertThat(ContactProfiles.of(Arrays.asList("", "  ", null, " / ", "PO //"))).containsExactly(new Profile("PO", "PO"));
        assertThat(ContactProfiles.keysOf(null)).isEmpty();
    }

    @Test
    @DisplayName("a shared line is each of its profiles' line")
    void aSharedLineIsBoth() {
        assertThat(ContactProfiles.keysOf("PO / BA")).containsExactly("PO", "BA");
        assertThat(ContactProfiles.keysOf("PO/po")).containsExactly("PO");
    }

    @Test
    @DisplayName("spacing inside a name is one space, and the comparison ignores it at the edges")
    void spacing() {
        assertThat(ContactProfiles.of("  Team   lead ")).containsExactly(new Profile("TEAM LEAD", "Team lead"));
        assertThat(ContactProfiles.keyOf("team lead")).isEqualTo("TEAM LEAD");
    }

    @Test
    @DisplayName("a name from a request is keyed like the column's, and one naming two profiles is none")
    void keyOfARequest() {
        assertThat(ContactProfiles.keyOf(" arch ")).isEqualTo("ARCH");
        assertThat(ContactProfiles.keyOf("PO / BA")).isEmpty();
        assertThat(ContactProfiles.keyOf("  ")).isEmpty();
        assertThat(ContactProfiles.keyOf(null)).isEmpty();
    }
}
