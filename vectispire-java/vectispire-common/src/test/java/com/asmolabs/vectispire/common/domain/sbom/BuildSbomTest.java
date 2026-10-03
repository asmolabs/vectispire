package com.asmolabs.vectispire.common.domain.sbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.reports.InvalidReportException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("reading a build's CycloneDX SBOM")
class BuildSbomTest {

    private static final long CAP = 1_000_000;

    private static BuildSbom read(String json) {
        return BuildSbom.read(json.getBytes(StandardCharsets.UTF_8), CAP);
    }

    private static String bom(String spec, String components) {
        return "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"" + spec + "\",\"version\":1,"
                + "\"metadata\":{\"tools\":{\"components\":[{\"type\":\"application\",\"group\":\"org.cyclonedx\","
                + "\"name\":\"cyclonedx-maven-plugin\",\"version\":\"2.9.1\"}]},"
                + "\"component\":{\"type\":\"application\",\"name\":\"ledger\",\"version\":\"1.4.0\"}},"
                + "\"components\":" + components + "}";
    }

    @Test
    @DisplayName("keeps each component's name, stated version, canonical purl, type and declared licences — nested ones too")
    void reads() {
        BuildSbom sbom = read(bom("1.6", """
                [{"type":"library","group":"org.springframework","name":"spring-core","version":"6.1.14",
                  "purl":"pkg:maven/org.springframework/spring-core@6.1.14?type=jar",
                  "licenses":[{"license":{"id":"Apache-2.0"}}],
                  "externalReferences":[{"type":"bom","url":"https://example.invalid/never-fetched.json"}],
                  "components":[{"type":"library","name":"shaded-asm","version":"9.7",
                                 "purl":"pkg:maven/org.ow2.asm/asm@9.7?classifier=shaded&type=jar"}]},
                 {"type":"library","name":"logback-classic","version":"1.5.8",
                  "purl":"pkg:maven/ch.qos.logback/logback-classic@1.5.8?type=jar",
                  "licenses":[{"license":{"id":"EPL-1.0"}},{"license":{"name":"GNU Lesser General Public License"}}]},
                 {"type":"library","name":"internal-tool","licenses":[{"expression":"MIT OR Apache-2.0"}]}]"""));

        assertThat(sbom.specVersion()).isEqualTo("1.6");
        assertThat(sbom.tool()).contains("org.cyclonedx cyclonedx-maven-plugin 2.9.1");
        assertThat(sbom.components()).containsExactly(
                new BuildSbom.Component("spring-core", "6.1.14", "pkg:maven/org.springframework/spring-core@6.1.14",
                        "library", "Apache-2.0"),
                // A classifier names another artifact: only the default type goes.
                new BuildSbom.Component("shaded-asm", "9.7", "pkg:maven/org.ow2.asm/asm@9.7?classifier=shaded",
                        "library", null),
                new BuildSbom.Component("logback-classic", "1.5.8", "pkg:maven/ch.qos.logback/logback-classic@1.5.8",
                        "library", "EPL-1.0 OR GNU Lesser General Public License"),
                new BuildSbom.Component("internal-tool", null, null, "library", "MIT OR Apache-2.0"));
    }

    @Test
    @DisplayName("reads 1.4's tool array and 1.5; a package listed twice is one component")
    void olderShapes() {
        String doc = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.4\",\"metadata\":{\"tools\":[{\"vendor\":\"CycloneDX\","
                + "\"name\":\"cyclonedx-gradle-plugin\",\"version\":\"1.10.0\"}]},\"components\":["
                + "{\"name\":\"a\",\"version\":\"1\",\"purl\":\"pkg:maven/g/a@1\"},"
                + "{\"name\":\"a\",\"version\":\"1\",\"purl\":\"pkg:maven/g/a@1?type=jar\"}]}";
        BuildSbom sbom = read(doc);
        assertThat(sbom.tool()).contains("CycloneDX cyclonedx-gradle-plugin 1.10.0");
        assertThat(sbom.components()).hasSize(1);
        assertThat(read(bom("1.5", "[]")).components()).isEmpty();
    }

    @Test
    @DisplayName("refuses what is not CycloneDX JSON 1.4–1.6, in words")
    void notCycloneDx() {
        assertThatThrownBy(() -> read("{\"artifacts\":[],\"schema\":{\"version\":\"16.0.0\"}}"))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("Only CycloneDX JSON is read");
        assertThatThrownBy(() -> read("{\"spdxVersion\":\"SPDX-2.3\"}"))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("bomFormat");
        assertThatThrownBy(() -> read(bom("1.3", "[]")))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("specVersion \"1.3\"");
        assertThatThrownBy(() -> read(bom("2.0", "[]"))).isInstanceOf(InvalidReportException.class);
        assertThatThrownBy(() -> read("<bom xmlns=\"http://cyclonedx.org/schema/bom/1.6\"/>"))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("not readable JSON");
        assertThatThrownBy(() -> read("[]")).isInstanceOf(InvalidReportException.class)
                .hasMessageContaining("JSON object");
    }

    @Test
    @DisplayName("refuses a BOM that lists nothing — absent is not empty — and a component without a name")
    void absentIsNotEmpty() {
        assertThatThrownBy(() -> read("{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\"}"))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("no \"components\"");
        assertThatThrownBy(() -> read(bom("1.6", "{}")))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("are an array");
        assertThatThrownBy(() -> read(bom("1.6", "[{\"version\":\"1\"}]")))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("components[0] has no name");
    }

    @Test
    @DisplayName("refuses past the ceilings: bytes, components, a column's width, a duplicate key, trailing content")
    void guards() {
        String doc = bom("1.6", "[]");
        assertThatThrownBy(() -> BuildSbom.read(doc.getBytes(StandardCharsets.UTF_8), 10))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("larger than the 10 bytes");

        StringBuilder many = new StringBuilder("[");
        for (int i = 0; i <= BuildSbom.MAX_COMPONENTS; i++) {
            many.append(i == 0 ? "" : ",").append("{\"name\":\"c").append(i).append("\"}");
        }
        assertThatThrownBy(() -> BuildSbom.read(bom("1.6", many.append("]").toString())
                        .getBytes(StandardCharsets.UTF_8), 100_000_000))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("more than 50000 components");

        assertThatThrownBy(() -> read(bom("1.6", "[{\"name\":\"" + "n".repeat(256) + "\"}]")))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("longer than 255");
        assertThatThrownBy(() -> read(bom("1.6", "[{\"name\":\"a\",\"purl\":\"pkg:npm/" + "p".repeat(500) + "\"}]")))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("purl is longer than 500");
        assertThatThrownBy(() -> read(bom("1.6", "[{\"name\":\"a\",\"purl\":\"https://example.invalid/a\"}]")))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("pkg:");
        assertThatThrownBy(() -> read(bom("1.6", "[{\"name\":\"a\\u0000b\"}]")))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("control character");
        assertThatThrownBy(() -> read("{\"bomFormat\":\"CycloneDX\",\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\","
                        + "\"components\":[]}"))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("not readable JSON");
        assertThatThrownBy(() -> read(doc + "{}"))
                .isInstanceOf(InvalidReportException.class).hasMessageContaining("after its end");
        assertThatThrownBy(() -> read("")).isInstanceOf(InvalidReportException.class).hasMessageContaining("empty");
    }
}
