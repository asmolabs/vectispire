package com.asmolabs.vectispire.common.domain.plugins;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a plugin manifest")
class PluginManifestTest {

    static final String DIGEST = "sha256:" + "a".repeat(64);
    static final String IMAGE = "registry.acme.internal/sec/acme-lint@" + DIGEST;

    static PluginManifest manifest() {
        return new PluginManifest("acme-lint", "ACME house rules", IMAGE, Set.of(Language.JAVA, Language.KOTLIN),
                List.of("--sarif", "{output}", "{source}"), "results.sarif", Set.of(0), false, null, 600);
    }

    @Test
    @DisplayName("a well-formed manifest is accepted as it is")
    void valid() {
        assertThat(manifest().validated()).isEqualTo(manifest());
    }

    @Test
    @DisplayName("absent parts take the closed defaults: exit code 0, the default output, no network")
    void defaults() {
        PluginManifest bare = new PluginManifest("x1", "X", IMAGE, Set.of(Language.GO), null, null, null, false, " ", null);

        assertThat(bare.exitCodes()).containsExactly(0);
        assertThat(bare.output()).isEqualTo(PluginManifest.DEFAULT_OUTPUT);
        assertThat(bare.arguments()).isEmpty();
        assertThat(bare.networkJustification()).isNull();
        assertThat(bare.validated()).isEqualTo(bare);
    }

    @Test
    @DisplayName("the digest moves with anything an executor would do differently, and only with that")
    void digest() {
        String base = manifest().digest();

        assertThat(manifest().digest()).isEqualTo(base);
        assertThat(new PluginManifest("acme-lint", "ACME house rules", IMAGE, Set.of(Language.KOTLIN, Language.JAVA),
                        List.of("--sarif", "{output}", "{source}"), "results.sarif", Set.of(0), false, null, 600).digest())
                .as("a set is a set: the order it was written in is not a new version")
                .isEqualTo(base);
        assertThat(withImage("registry.acme.internal/sec/acme-lint@sha256:" + "b".repeat(64)).digest()).isNotEqualTo(base);
        assertThat(new PluginManifest("acme-lint", "ACME house rules", IMAGE, Set.of(Language.JAVA, Language.KOTLIN),
                        List.of("--sarif", "{output}"), "results.sarif", Set.of(0), false, null, 600).digest())
                .isNotEqualTo(base);
        assertThat(new PluginManifest("acme-lint", "ACME house rules", IMAGE, Set.of(Language.JAVA, Language.KOTLIN),
                        List.of("--sarif", "{output}", "{source}"), "results.sarif", Set.of(0), true,
                        "reaches the internal Maven mirror to resolve types", 600).digest())
                .isNotEqualTo(base);
        assertThat(new PluginManifest("acme-lint", "ACME house rules", IMAGE, Set.of(Language.JAVA, Language.KOTLIN),
                        List.of("--sarif {output}", "{source}"), "results.sarif", Set.of(0), false, null, 600).digest())
                .as("two arguments are not one argument with a space")
                .isNotEqualTo(base);
        assertThat(new PluginManifest("acme-lint", "ACME house rules", IMAGE, Set.of(Language.JAVA, Language.KOTLIN),
                        List.of("--sarif", "{output}", "{source}"), "results.sarif", Set.of(0), true, null, 600).digest())
                .as("the network flag is in the digest by itself, not only through its justification")
                .isNotEqualTo(base);
    }

    @Test
    @DisplayName("the arguments are a list with the two placeholders replaced, never a shell line")
    void command() {
        assertThat(manifest().command("/repo/source", "/repo/output/results.sarif"))
                .containsExactly("--sarif", "/repo/output/results.sarif", "/repo/source");
    }

    @Test
    @DisplayName("the image is pinned by digest: a tag, a tag beside a digest, a short digest are refused")
    void imageIsPinned() {
        for (String image : List.of("acme/lint:latest", "acme/lint", "acme/lint:4.2@" + DIGEST,
                "acme/lint@sha256:abc", "acme/lint@sha256:" + "A".repeat(64), "Acme/Lint@" + DIGEST)) {
            assertThatThrownBy(() -> withImage(image).validated())
                    .as(image)
                    .isInstanceOf(InvalidPluginException.class);
        }
        assertThat(withImage("localhost:5000/lint@" + DIGEST).validated()).isNotNull();
    }

    @Test
    @DisplayName("a network is a declared exception: no justification, no network, and none without one")
    void networkNeedsAReason() {
        assertThatThrownBy(() -> new PluginManifest("x1", "X", IMAGE, Set.of(Language.GO), List.of(), null, null,
                        true, "because", null).validated())
                .isInstanceOf(InvalidPluginException.class)
                .hasMessageContaining("says why");
        assertThatThrownBy(() -> new PluginManifest("x1", "X", IMAGE, Set.of(Language.GO), List.of(), null, null,
                        false, "reaches the internal Maven mirror to resolve types", null).validated())
                .isInstanceOf(InvalidPluginException.class);
        assertThat(new PluginManifest("x1", "X", IMAGE, Set.of(Language.GO), List.of(), null, null,
                        true, "reaches the internal Maven mirror to resolve types", null).validated().network())
                .isTrue();
    }

    @Test
    @DisplayName("a plugin may ask for less time than a scanner, never more")
    void timeout() {
        assertThatThrownBy(() -> withTimeout(PluginManifest.MAX_TIMEOUT_SECONDS + 1).validated())
                .isInstanceOf(InvalidPluginException.class);
        assertThatThrownBy(() -> withTimeout(1).validated()).isInstanceOf(InvalidPluginException.class);
        assertThat(withTimeout(PluginManifest.MAX_TIMEOUT_SECONDS).validated()).isNotNull();
    }

    @Test
    @DisplayName("the id is a slug, since it enters every fingerprint; the output is a bare file name")
    void idAndOutput() {
        for (String id : List.of("A", "-lint", "lint-", "li nt", "lint_x", "x".repeat(41), "é")) {
            assertThatThrownBy(() -> PluginManifest.requireId(id)).as(id).isInstanceOf(InvalidPluginException.class);
        }
        assertThat(PluginManifest.requireId("acme-lint-2")).isEqualTo("acme-lint-2");
        for (String output : List.of("../x.sarif", "out/x.sarif", ".hidden", "x y")) {
            assertThatThrownBy(() -> new PluginManifest("x1", "X", IMAGE, Set.of(Language.GO), List.of(), output, null,
                            false, null, null).validated())
                    .as(output)
                    .isInstanceOf(InvalidPluginException.class);
        }
    }

    @Test
    @DisplayName("a plugin declares at least one language, and exit codes a process can return")
    void languagesAndExitCodes() {
        assertThatThrownBy(() -> new PluginManifest("x1", "X", IMAGE, Set.of(), List.of(), null, null, false, null, null)
                        .validated())
                .isInstanceOf(InvalidPluginException.class)
                .hasMessageContaining("languages");
        assertThatThrownBy(() -> new PluginManifest("x1", "X", IMAGE, Set.of(Language.GO), List.of(), null, Set.of(256),
                        false, null, null).validated())
                .isInstanceOf(InvalidPluginException.class);
    }

    @Test
    @DisplayName("an argument carrying a control character is refused")
    void controlCharacters() {
        assertThatThrownBy(() -> new PluginManifest("x1", "X", IMAGE, Set.of(Language.GO), List.of("a\nb"), null, null,
                        false, null, null).validated())
                .isInstanceOf(InvalidPluginException.class);
    }

    @Test
    @DisplayName("the JSON form is snake_case with languages by wire name, and reads back to the same digest")
    void json() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(manifest());

        assertThat(json).contains("\"exit_codes\"", "\"timeout_seconds\"", "\"java\"").doesNotContain("\"digest\"");
        assertThat(mapper.readValue(json, PluginManifest.class).digest()).isEqualTo(manifest().digest());
    }

    private static PluginManifest withImage(String image) {
        PluginManifest m = manifest();
        return new PluginManifest(m.id(), m.name(), image, m.languages(), m.arguments(), m.output(), m.exitCodes(),
                m.network(), m.networkJustification(), m.timeoutSeconds());
    }

    private static PluginManifest withTimeout(int seconds) {
        PluginManifest m = manifest();
        return new PluginManifest(m.id(), m.name(), m.image(), m.languages(), m.arguments(), m.output(), m.exitCodes(),
                m.network(), m.networkJustification(), seconds);
    }
}
