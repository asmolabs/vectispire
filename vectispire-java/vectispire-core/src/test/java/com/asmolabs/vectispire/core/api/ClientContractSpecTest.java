package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The OpenAPI document the Angular client is generated from, kept in step with the routes.
 *
 * <h2>Why this exists</h2>
 *
 * <p><b>{@code npm run generate:api} names a file that is not in the repository.</b> The script
 * reads {@code vectispire-angular/openapi.json} and writes {@code src/app/core/api.generated.ts};
 * the input has never existed, so the command has never run and the client's types are
 * hand-written. The contract of a hundred and sixty-three routes was therefore an intention: a
 * renamed response field broke a screen, and the first thing that noticed was a person looking
 * at it.
 *
 * <p>Generating the file once would fix nothing — nobody re-runs a command after renaming a
 * field. So the file is committed <em>and</em> this test compares it to what the routes actually
 * produce. Changing a route's shape then fails here, with the command to run, and the diff of the
 * regenerated document is the review of the contract change. It is the shape {@code c4-drift}
 * uses for the diagrams and {@code check-doc-facts} for the numeric claims: the artefact is
 * committed, and something small proves it is still true.
 *
 * <h2>Regenerating</h2>
 *
 * <pre>
 *   cd vectispire-java
 *   ./gradlew :vectispire-core:test --tests '*ClientContractSpecTest*' -Dvectispire.openapi.write=true
 * </pre>
 *
 * <p>Then {@code npm run generate:api} turns the result into the client's types, and both files
 * are committed together.
 *
 * <h2>Why the document is normalised before comparing</h2>
 *
 * <p>Springdoc builds the specification by scanning, and a scan's order is not a contract: the
 * same routes can serialise their paths and schemas in a different order on another JVM. Sorting
 * every key makes the committed file a function of the routes alone, so a diff on it is always a
 * diff of the API and never of the walk that found it.
 */
@DisplayName("the client's OpenAPI contract")
class ClientContractSpecTest extends ApiTestBase {

    /** Where the Angular workspace expects it — {@code generate:api} reads exactly this path. */
    private static final String COMMITTED = "vectispire-angular/openapi.json";

    private static final String WRITE_FLAG = "vectispire.openapi.write";

    private static final ObjectMapper NORMALISING = new ObjectMapper()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    @DisplayName("is the one committed for the Angular client to generate from")
    void is_the_one_committed_for_the_client() throws Exception {
        String served = normalise(mvc.perform(authenticated(get("/v3/api-docs"), asReader()))
                .andReturn()
                .getResponse()
                .getContentAsString());

        Path committed = repositoryRoot().resolve(COMMITTED);

        if (Boolean.getBoolean(WRITE_FLAG)) {
            Files.createDirectories(committed.getParent());
            Files.writeString(committed, served, StandardCharsets.UTF_8);
            System.out.println("openapi.json rewritten: " + committed);
            return;
        }

        assertThat(committed)
                .as(
                        """
                        %s is missing. Generate it:
                          ./gradlew :vectispire-core:test --tests '*ClientContractSpecTest*' -D%s=true""",
                        COMMITTED,
                        WRITE_FLAG)
                .exists();

        assertThat(normalise(Files.readString(committed, StandardCharsets.UTF_8)))
                .as(
                        """
                        The routes no longer match %s.

                        If the change is intended, regenerate and commit both files:
                          ./gradlew :vectispire-core:test --tests '*ClientContractSpecTest*' -D%s=true
                          npm run generate:api

                        The diff on the regenerated document is the contract change, and is worth
                        reading as one: a renamed field is a client that stops compiling here
                        rather than a screen that stops working in front of somebody.""",
                        COMMITTED,
                        WRITE_FLAG)
                .isEqualTo(served);
    }

    /** Key-sorted and indented, so the file is a function of the routes and not of the scan. */
    private static String normalise(String json) throws IOException {
        return NORMALISING.writeValueAsString(NORMALISING.readValue(json, Map.class));
    }

    /**
     * The repository root, found rather than assumed.
     *
     * <p>Gradle runs a test from its project directory, so the path from here is
     * {@code ../../}. Walking up to the directory that holds both workspaces says what is being
     * looked for instead of counting on that, and fails with the reason rather than with a file
     * that is not there.
     */
    private static Path repositoryRoot() {
        Path directory = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while (directory != null) {
            if (Files.isDirectory(directory.resolve("vectispire-angular"))
                    && Files.isDirectory(directory.resolve("vectispire-java"))) {
                return directory;
            }
            directory = directory.getParent();
        }
        throw new AssertionError(
                "no directory above " + System.getProperty("user.dir") + " holds both workspaces");
    }
}
