package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * La liste de gravités recopiée dans {@link RemediationDistributionView}, tenue à jour de force.
 *
 * <p><b>Un accesseur qui rend une {@code String} ne laisse rien à énumérer à springdoc</b>, donc
 * les six valeurs sont écrites à la main dans {@code @Schema} pour que le document garde son
 * énumération. Une liste recopiée dérive : le jour où {@link Severity} gagne une constante, ce
 * document annoncerait un ensemble de valeurs que le serveur peut dépasser, et un client aurait
 * raison de s'y fier.
 *
 * <p>Ce test est la contrepartie de la recopie. Il ne vérifie pas que la liste est « correcte » au
 * sens d'une opinion : il vérifie qu'elle est exactement l'énumération du domaine, dans la forme
 * que cette API emploie.
 */
@DisplayName("les gravités que la distribution publie")
class RemediationSeverityWireTest extends ApiTestBase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    @DisplayName("sont l'énumération du domaine, en minuscules, sur les deux champs")
    void match_the_domain_enum() throws Exception {
        JsonNode schemas = MAPPER.readTree(mvc.perform(authenticated(get("/v3/api-docs"), asReader()))
                        .andReturn()
                        .getResponse()
                        .getContentAsString())
                .get("components")
                .get("schemas");

        List<String> expected =
                Arrays.stream(Severity.values()).map(Severity::wireName).toList();

        assertThat(enumOf(schemas, "BySeverityView", "severity"))
                .as("la gravité d'une ligne")
                .containsExactlyInAnyOrderElementsOf(expected);
        assertThat(enumOf(schemas, "RemediationDistributionView", "oldestOpenSeverity"))
                .as("la gravité du plus ancien élément ouvert")
                .containsExactlyInAnyOrderElementsOf(expected);
    }

    /**
     * <b>Minuscules, et le dire séparément.</b> L'assertion ci-dessus passerait encore si les deux
     * listes étaient en majuscules et {@code wireName()} avec — or c'est précisément l'orthographe
     * qui était fausse sur cette route, et elle seule.
     */
    @Test
    @DisplayName("sont en minuscules, comme partout ailleurs dans cette API")
    void are_lowercase() {
        assertThat(Arrays.stream(Severity.values()).map(Severity::wireName))
                .allSatisfy(name -> assertThat(name).isEqualTo(name.toLowerCase(java.util.Locale.ROOT)));
    }

    private static List<String> enumOf(JsonNode schemas, String schema, String property) {
        JsonNode values = schemas.get(schema).get("properties").get(property).get("enum");
        assertThat(values).as("%s.%s publie une énumération", schema, property).isNotNull();
        List<String> names = new ArrayList<>();
        values.forEach(value -> names.add(value.asText()));
        return names;
    }
}
