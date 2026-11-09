package com.asmolabs.vectispire.common.domain.forges;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the namespaces a discovery could not read, as stored")
class UnreadableNamespaceTest {

    @Test
    @DisplayName("read back as written, an unnamed one included; nothing stored for none")
    void roundTrip() {
        List<UnreadableNamespace> written = List.of(new UnreadableNamespace("secure", "single sign-on (HTTP 403)"),
                new UnreadableNamespace(null, "GitHub left out 2 organisations"));

        assertThat(UnreadableNamespace.decode(UnreadableNamespace.encode(written))).isEqualTo(written);
        assertThat(UnreadableNamespace.encode(List.of())).isNull();
        assertThat(UnreadableNamespace.decode(null)).isEmpty();
    }

    @Test
    @DisplayName("a tab or a line break in what the forge wrote cannot split one entry into two")
    void flattened() {
        UnreadableNamespace odd = new UnreadableNamespace("a\tb", "first line\nsecond\tline");

        assertThat(UnreadableNamespace.decode(UnreadableNamespace.encode(List.of(odd)))).singleElement()
                .isEqualTo(new UnreadableNamespace("a b", "first line second line"));
    }

    @Test
    @DisplayName("bounded: a hundred kept, the rest counted in the last one's place; a reason clipped")
    void bounded() {
        List<UnreadableNamespace> many = IntStream.range(0, 150)
                .mapToObj(i -> new UnreadableNamespace("org-" + i, "refused")).toList();

        List<UnreadableNamespace> read = UnreadableNamespace.decode(UnreadableNamespace.encode(many));

        assertThat(read).hasSize(UnreadableNamespace.MAX_RECORDED);
        assertThat(read.getLast().path()).isNull();
        assertThat(read.getLast().reason()).startsWith("51 more namespaces");
        assertThat(new UnreadableNamespace("x", "r".repeat(2000)).reason())
                .hasSizeLessThanOrEqualTo(UnreadableNamespace.REASON_LENGTH);
    }
}
