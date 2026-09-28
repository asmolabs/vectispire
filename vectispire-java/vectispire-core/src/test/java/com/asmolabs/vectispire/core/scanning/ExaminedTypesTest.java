package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import java.util.EnumSet;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The three answers {@code examined_types} holds — a set, the empty set, and "nobody recorded it" —
 * kept apart through the column and back.
 */
@DisplayName("the types a scan examined, as the scan keeps them")
class ExaminedTypesTest {

    @Test
    @DisplayName("a scan from before the column reads as unknown, never as 'examined nothing'")
    void unrecordedIsUnknown() {
        ScanEntity before = new ScanEntity();

        assertThat(ExaminedTypes.read(null)).isEmpty();
        assertThat(ScanView.of(before).examinedTypes()).isEmpty();
    }

    @Test
    @DisplayName("the empty set is recorded as such, and reads back as a recorded empty set")
    void emptyIsRecorded() {
        assertThat(ExaminedTypes.write(Set.of())).isEmpty();
        assertThat(ExaminedTypes.read("")).contains(Set.of());
    }

    @Test
    @DisplayName("the wire names, sorted, and back")
    void roundTrip() {
        Set<FindingType> examined = EnumSet.of(FindingType.SECRET, FindingType.IAC, FindingType.VULNERABILITY);

        assertThat(ExaminedTypes.write(examined)).isEqualTo("iac,secret,vulnerability");
        assertThat(ExaminedTypes.read("iac,secret,vulnerability")).contains(examined);
    }

    @Test
    @DisplayName("a name this version does not know is left out, and the rest still read")
    void unknownNamesAreSkipped() {
        assertThat(ExaminedTypes.read("iac,from_a_later_version")).contains(Set.of(FindingType.IAC));
    }

    @Test
    @DisplayName("the pattern matches one whole name, never a name containing it")
    void patternMatchesWholeNames() {
        // What the query does with it: the column wrapped in commas, then `like`.
        String column = "," + "quality,sast" + ",";
        String sast = ExaminedTypes.pattern(FindingType.SAST);

        assertThat(sast).isEqualTo("%,sast,%");
        assertThat(column.matches(sast.replace("%", ".*"))).isTrue();
        assertThat(",sastx,".matches(sast.replace("%", ".*"))).isFalse();
    }

    @Test
    @DisplayName("no built-in wire name holds a character `like` would read as a wildcard")
    void builtInNamesNeedNoEscaping() {
        // `ai_review` would: `_` matches any character. It is no step of a scan, and the catalogue
        // refuses every type outside this set.
        assertThat(ExaminedTypes.BUILT_IN).allSatisfy(type -> assertThat(type.wireName()).doesNotContain("_", "%"));
        assertThat(ExaminedTypes.BUILT_IN).noneMatch(FindingType::toolScoped);
    }
}
