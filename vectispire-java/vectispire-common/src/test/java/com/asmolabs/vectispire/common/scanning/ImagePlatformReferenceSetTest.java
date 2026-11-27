package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What the save of an image asks for and what the check of its archive answers, for the cases in
 * {@code container/image-platform/inputs.json} — the answers the Rust agent's {@code image_archive} is held to.
 *
 * <p>Each case's archive is built here, by {@link TarBuilder}, and written into the answers as it was read, so the
 * Rust side reads the same bytes: the tar reader is held to the set along with the platform rules. A platform
 * asked for and the image's own are normalized, compared, and the refusal worded, the same way on both sides; a
 * difference is an agent that scans an architecture the other refuses.
 */
class ImagePlatformReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void theAnswersTheRustCheckIsHeldTo(@TempDir Path directory) throws Exception {
        JsonNode inputs = JSON.readTree(ReferenceSet.read("container/image-platform/inputs.json"));
        ArrayNode answers = JSON.createArrayNode();
        for (JsonNode input : inputs) {
            String name = input.path("name").asText();
            String reference = input.path("reference").asText();
            String platform = input.path("platform").isNull() ? null : input.path("platform").asText();
            byte[] archive = archive(input);
            Path file = directory.resolve(name + ".tar");
            Files.write(file, archive);

            ObjectNode answer = answers.addObject().put("name", name);
            answer.put("archive", Base64.getEncoder().encodeToString(archive));
            Optional<ImagePlatform.Platform> requested;
            try {
                requested = ImagePlatform.requested(platform);
            } catch (IllegalStateException malformed) {
                answer.putNull("query");
                answer.put("refusal", malformed.getMessage());
                continue;
            }
            answer.put("query", requested.map(ImagePlatform.Platform::saveQuery).orElse(null));
            answer.put("refusal", requested.flatMap(asked -> ImagePlatform.refusal(
                            reference, platform, asked, (entry, limit) -> ImageArchive.entry(file, entry, limit)))
                    .orElse(null));
        }
        ReferenceSet.expect("container/image-platform/java-answers.json", JSON.writeValueAsString(answers) + "\n");
    }

    /** The defect itself, read off the set: an arm64 image is refused where amd64 was asked. */
    @Test
    void anotherArchitectureIsRefusedNotScanned() throws Exception {
        JsonNode answers = JSON.readTree(ReferenceSet.read("container/image-platform/java-answers.json"));
        JsonNode defect = null;
        for (JsonNode answer : answers) {
            if (answer.path("name").asText().equals("amd64-asked-arm64-found")) {
                defect = answer;
            }
        }
        assertThat(defect).isNotNull();
        assertThat(defect.path("query").asText()).isEqualTo("{\"os\":\"linux\",\"architecture\":\"amd64\"}");
        assertThat(defect.path("refusal").asText())
                .contains("as linux/arm64 where linux/amd64 was asked")
                .contains("another architecture is not scanned");
    }

    static byte[] archive(JsonNode input) {
        TarBuilder tar = new TarBuilder();
        for (JsonNode entry : input.path("entries")) {
            String type = entry.path("type").asText("0");
            tar.add(entry.path("name").asText(),
                    entry.path("text").asText().getBytes(StandardCharsets.UTF_8),
                    TarBuilder.Form.of(entry.path("form").isMissingNode() ? null : entry.path("form").asText()),
                    type.equals("NUL") ? 0 : (byte) type.charAt(0));
        }
        return switch (input.path("damage").asText("")) {
            case "" -> tar.build();
            case "no-end" -> tar.withoutEnd();
            case "checksum" -> {
                byte[] bytes = tar.build();
                bytes[0] ^= 0x01;
                yield bytes;
            }
            case "truncate" -> Arrays.copyOf(tar.build(), 512 + 100);
            case "empty" -> new byte[0];
            case "garbage" -> "this is not a tar archive\n".repeat(30).getBytes(StandardCharsets.US_ASCII);
            default -> throw new IllegalArgumentException("unknown damage " + input.path("damage"));
        };
    }
}
