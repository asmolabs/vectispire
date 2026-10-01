package com.asmolabs.vectispire.common.domain.siem;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The event catalogue a SOC writes its rules from is the one the code emits.
 *
 * <p>The published table is the only list a SOC reads; a constant added without its row is an event
 * nobody writes a rule for, and a row left behind by a retired constant is a rule written for an alarm
 * that cannot fire — what the first catalogue was, seven events declared and one sent. Both pages,
 * since the French one is read as the contract too. The name column is compared as well: it is the
 * CEF {@code Name} the collector receives, in English on both pages.
 */
@DisplayName("the SIEM event catalogue in the guide")
class SecurityEventCatalogueDocsTest {

    private static final Path PAGES = Path.of("../../docs-site/integrations");

    /** A table row: {@code | `VECTI-SEC-nnn` | Name | severity | …}. */
    private static final Pattern ROW = Pattern.compile("(?m)^\\| `(VECTI-SEC-\\d{3})` \\| ([^|]+) \\| (\\d+) \\|");

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"siem.md", "siem.fr.md"})
    void listsExactlyWhatIsEmitted(String page) throws IOException {
        Map<String, String> documented = new LinkedHashMap<>();
        Map<String, Integer> severities = new LinkedHashMap<>();
        Matcher row = ROW.matcher(Files.readString(PAGES.resolve(page)));
        while (row.find()) {
            documented.put(row.group(1), row.group(2).trim());
            severities.put(row.group(1), Integer.parseInt(row.group(3)));
        }

        Map<String, String> emitted = Arrays.stream(SecurityEventType.values()).collect(Collectors.toMap(
                SecurityEventType::signatureId, SecurityEventType::description, (a, b) -> a, LinkedHashMap::new));
        assertThat(documented).containsExactlyInAnyOrderEntriesOf(emitted);
        assertThat(severities).containsExactlyInAnyOrderEntriesOf(Arrays.stream(SecurityEventType.values())
                .collect(Collectors.toMap(SecurityEventType::signatureId, SecurityEventType::cefSeverity)));
    }
}
