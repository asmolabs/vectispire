package com.asmolabs.vectispire.common.domain.reportplugins;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the project export's bounds")
class ProjectExportBoundsTest {

    @Test
    @DisplayName("the decision's figures: 64 MiB of JSON, 100,000 issues, 100,000 components")
    void standard() {
        assertThat(ProjectExportBounds.STANDARD)
                .isEqualTo(new ProjectExportBounds(64L * 1024 * 1024, 100_000, 100_000));
    }

    @Test
    @DisplayName("a count at the bound passes, one over it names the part, the figure and the bound")
    void counts() {
        ProjectExportBounds bounds = new ProjectExportBounds(10, 3, 5);
        assertThat(bounds.issues(3)).isEmpty();
        assertThat(bounds.issues(4)).contains(new ProjectExportBounds.Exceeded("issues", 4, 3));
        assertThat(bounds.components(5)).isEmpty();
        assertThat(bounds.components(6)).contains(new ProjectExportBounds.Exceeded("inventory.components", 6, 5));
    }

    @Test
    @DisplayName("the buffer holds up to its bound and refuses the write that would cross it")
    void buffer() throws Exception {
        ProjectExportBounds.BoundedBuffer buffer = new ProjectExportBounds(4, 1, 1).buffer();
        buffer.write(new byte[] {1, 2, 3});
        buffer.write(4);
        assertThat(buffer.toByteArray()).containsExactly(1, 2, 3, 4);
        assertThatThrownBy(() -> buffer.write(5))
                .isInstanceOfSatisfying(ProjectExportBounds.TooLarge.class, refused ->
                        assertThat(refused.exceeded()).isEqualTo(new ProjectExportBounds.Exceeded("json_bytes", 5, 4)));
        assertThat(buffer.toByteArray()).as("nothing past the bound was kept").hasSize(4);
    }
}
