package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Every route the reference documents still exists.
 *
 * <h2>Why this and not the other direction</h2>
 *
 * <p>The reference is <b>curated</b> — forty-eight routes out of roughly two hundred — and
 * deliberately so: it is what somebody reads before writing a client, not an inventory. Asserting
 * that every route appears would turn it into one, and the answer to a failing test would be to
 * paste a row nobody wrote for a reader.
 *
 * <p>The other direction has no such excuse. A row naming a route that no longer answers is worse
 * than a missing row: the reader writes the call, gets a 404, and has no way to tell whether they
 * or the document is wrong. Renames are where this bites — nine records were renamed in this
 * codebase in one commit, and a documented path is renamed just as quietly.
 *
 * <p>Both language editions are checked. They drift apart for the ordinary reason: somebody adds a
 * route to the one they read.
 */
@DisplayName("the REST reference")
class ApiReferenceTest {

    private static final List<Path> EDITIONS = List.of(
            Path.of("../../docs/en/api/rest_api_reference.md"),
            Path.of("../../docs/fr/api/rest_api_reference.md"));

    private static final Path CONTRACT = Path.of("../../vectispire-angular/openapi.json");

    /** A table row: {@code | **Domain** | `GET` | `/api/v1/…` | Auth | prose |}. */
    private static final Pattern ROW = Pattern.compile("\\| `([A-Z]+)` \\| `(/api/v1/[^`]+)`");

    @Test
    @DisplayName("documents no route the API does not answer")
    void everyDocumentedRouteExists() throws Exception {
        List<String> paths = contractPaths();
        assertThat(paths).as("the contract could not be read, so this rule would pass over nothing")
                .isNotEmpty();

        for (Path edition : EDITIONS) {
            List<String> documented = documentedPaths(edition);
            assertThat(documented)
                    .as("%s documents no route at all, which means the table moved", edition)
                    .isNotEmpty();

            assertThat(documented.stream().filter(path -> paths.stream().noneMatch(known -> matches(path, known))).toList())
                    .as("%s names routes the API no longer answers. A reader who writes one of these "
                            + "calls gets a 404 and cannot tell whether they or the document is wrong",
                            edition)
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("says the same thing in both languages")
    void bothEditionsCoverTheSameRoutes() throws Exception {
        assertThat(documentedPaths(EDITIONS.get(1)))
                .as("the two editions drift for the ordinary reason: somebody adds a route to the "
                        + "one they read")
                .containsExactlyInAnyOrderElementsOf(documentedPaths(EDITIONS.getFirst()));
    }

    /**
     * Whether a documented path names the same route as one in the contract.
     *
     * <p>Placeholders are compared by position and not by name: the reference writes
     * {@code {issueId}} where the contract writes {@code {id}}, and a reader does not care.
     */
    private static boolean matches(String documented, String contract) {
        String[] left = documented.split("/");
        String[] right = contract.split("/");
        if (left.length != right.length) {
            return false;
        }
        return Stream.iterate(0, index -> index + 1)
                .limit(left.length)
                .allMatch(index -> left[index].equals(right[index])
                        || (left[index].startsWith("{") && right[index].startsWith("{")));
    }

    private static List<String> documentedPaths(Path edition) throws Exception {
        Matcher matcher = ROW.matcher(Files.readString(edition, StandardCharsets.UTF_8));
        List<String> paths = new ArrayList<>();
        while (matcher.find()) {
            paths.add(matcher.group(2));
        }
        return paths;
    }

    private static List<String> contractPaths() throws Exception {
        JsonNode paths = new ObjectMapper()
                .readTree(Files.readString(CONTRACT, StandardCharsets.UTF_8))
                .path("paths");
        List<String> known = new ArrayList<>();
        for (Iterator<String> names = paths.fieldNames(); names.hasNext(); ) {
            known.add(names.next());
        }
        return known;
    }
}
