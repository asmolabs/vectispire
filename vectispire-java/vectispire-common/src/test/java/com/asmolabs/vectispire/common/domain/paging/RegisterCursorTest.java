package com.asmolabs.vectispire.common.domain.paging;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The value a register hands back so a reader can ask for the next page.
 *
 * <p>The round trip is the whole contract, and the precision is the part that can go wrong
 * quietly: a cursor encoded finer than the column it points at falls between two rows, and the
 * reader loses one without anything saying so.
 */
@DisplayName("a register cursor")
class RegisterCursorTest {

    @Test
    @DisplayName("survives the round trip a client puts it through")
    void roundTrips() {
        RegisterCursor cursor = new RegisterCursor(Instant.parse("2026-09-14T08:00:00.123Z"), "41");

        assertThat(RegisterCursor.parse(cursor.encoded())).contains(cursor);
    }

    @Test
    @DisplayName("keeps an identifier carrying the separator")
    void identifierMayCarryTheSeparator() {
        // A UUID cannot, but nothing says the next register's key will be one, and a cursor that
        // silently truncates an id points at a row that does not exist.
        RegisterCursor cursor = new RegisterCursor(Instant.EPOCH, "a:b:c");

        assertThat(RegisterCursor.parse(cursor.encoded())).contains(cursor);
    }

    @Test
    @DisplayName("encodes no more precision than the stores keep")
    void encodesMilliseconds() {
        // SQLite holds an Instant as integer epoch millis. A cursor carrying microseconds would
        // point between two rows: the engine returns neither, and the page after it is short by
        // however many shared that millisecond.
        RegisterCursor cursor = new RegisterCursor(Instant.parse("2026-09-14T08:00:00.123456Z"), "41");

        assertThat(RegisterCursor.parse(cursor.encoded()).orElseThrow().at())
                .isEqualTo(Instant.parse("2026-09-14T08:00:00.123Z"));
    }

    @Test
    @DisplayName("reads an unusable value as absent rather than refusing the request")
    void unreadableIsAbsent() {
        // The client never composed these: it echoed back what the server handed it. Refusing
        // trades a first page for an error over a value nobody chose.
        assertThat(RegisterCursor.parse(null)).isEmpty();
        assertThat(RegisterCursor.parse("  ")).isEmpty();
        assertThat(RegisterCursor.parse("not-a-cursor")).isEmpty();
        assertThat(RegisterCursor.parse("abc:41")).isEmpty();
        assertThat(RegisterCursor.parse(":41")).isEmpty();
        assertThat(RegisterCursor.parse("1757836800000:")).isEmpty();
    }
}
