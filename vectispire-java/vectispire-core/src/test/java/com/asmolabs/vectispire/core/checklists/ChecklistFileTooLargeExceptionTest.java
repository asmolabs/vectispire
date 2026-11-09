package com.asmolabs.vectispire.core.checklists;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.access.web.security.RequestBodyTooLargeException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a proof over the ceiling")
class ChecklistFileTooLargeExceptionTest {

    @Test
    @DisplayName("is refused in the body filter's words, whichever of the two found it")
    void oneSentenceForOne413() {
        // The filter answers a declared or counted body past the ceiling first; the service holds the same
        // limit where the bytes are stored. A client, the interface included, reads one `detail` for one 413.
        long ceiling = 26_214_400;
        assertThat(new ChecklistFileTooLargeException(ceiling).getMessage())
                .isEqualTo(new RequestBodyTooLargeException(ceiling).getMessage());
    }
}
