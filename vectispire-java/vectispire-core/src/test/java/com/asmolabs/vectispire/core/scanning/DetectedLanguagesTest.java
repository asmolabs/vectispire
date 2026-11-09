package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** The three answers {@code detected_languages} holds, kept apart through the column and back. */
@DisplayName("the languages a scan found, as the scan keeps them")
class DetectedLanguagesTest {

    @Test
    @DisplayName("a scan from before the column reads as unknown, never as 'no language'")
    void unrecordedIsUnknown() {
        assertThat(DetectedLanguages.read(null)).isEmpty();
        assertThat(ScanView.of(new ScanEntity()).detectedLanguages()).isEmpty();
        assertThat(DetectedLanguages.write(Optional.empty())).isNull();
    }

    @Test
    @DisplayName("a census that saw no language is recorded, and reads back as the empty set")
    void emptyIsRecorded() {
        assertThat(DetectedLanguages.write(Optional.of(Set.of()))).isEmpty();
        assertThat(DetectedLanguages.read("")).contains(Set.of());
    }

    @Test
    @DisplayName("the manifests' wire names, normalised and sorted, and back; a name this version does not know is dropped")
    void normalised() {
        assertThat(DetectedLanguages.write(Optional.of(List.of("typescript", " Java ", "zig", "java"))))
                .isEqualTo("java,typescript");
        assertThat(DetectedLanguages.read("java,typescript,cobol"))
                .contains(Set.of(Language.JAVA, Language.TYPESCRIPT));
    }
}
