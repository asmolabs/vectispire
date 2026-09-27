package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Every operation the server records has words on the audit log screen, in both languages.
 *
 * <p><b>The defect this closes.</b> The screen's label table is open — an unknown type is shown raw
 * rather than hidden, which is right for a log — so a type the server starts recording reads as
 * {@code THREAT_INTEL_SYNCED} until somebody adds it, and nothing fails. Forty-four of the
 * enum's fifty-two operations had never been labelled, {@code CERTIFIED_SCOPE_CHANGED} and {@code
 * THREAT_INTEL_SYNCED} the latest of them. The keys are not literal calls either, so the front end's
 * i18n check cannot see a missing translation.
 *
 * <p><b>Here, like {@code RoleSetsMatchTheEnumTest}</b>: the enum is authoritative and is here, and a
 * front-end spec would have to copy it in order to compare — a third list to drift. The three files
 * are declared inputs of the {@code test} task, or Gradle would replay a stale success.
 */
@DisplayName("the audit log screen's operation labels")
class AuditOperationLabelsTest {

    private static final Path UI = Path.of("../../vectispire-angular");
    private static final Path PAGE = UI.resolve("src/app/pages/audit-log/audit-log.ts");

    @Test
    @DisplayName("name every AuditOperation, and each key resolves in English and in French")
    void everyOperationIsLabelled() throws IOException {
        Map<String, String> table = operationKeys(Files.readString(PAGE));
        List<String> operations = Arrays.stream(AuditOperation.values()).map(AuditOperation::wireName).toList();

        assertThat(table.keySet()).as("OPERATION_KEYS in audit-log.ts").containsAll(operations);
        for (String language : List.of("en", "fr")) {
            JsonNode dictionary = new ObjectMapper().readTree(UI.resolve("public/i18n/" + language + ".json").toFile());
            for (String operation : operations) {
                String key = table.get(operation);
                assertThat(resolve(dictionary, key))
                        .as("%s's label %s in %s.json", operation, key, language)
                        .isNotBlank();
            }
        }
    }

    /** The literal entries of {@code OPERATION_KEYS}: {@code NAME: 'dotted.key'}. */
    private static Map<String, String> operationKeys(String source) {
        Matcher block = Pattern.compile("const OPERATION_KEYS[^=]*=\\s*\\{(.*?)\\};", Pattern.DOTALL).matcher(source);
        assertThat(block.find()).as("OPERATION_KEYS must be declared in audit-log.ts").isTrue();
        Map<String, String> entries = new LinkedHashMap<>();
        Pattern.compile("([A-Z_]+):\\s*'([a-z_.]+)'")
                .matcher(block.group(1))
                .results()
                .forEach(entry -> entries.put(entry.group(1), entry.group(2)));
        return entries;
    }

    private static String resolve(JsonNode dictionary, String dottedKey) {
        JsonNode node = dictionary;
        for (String segment : dottedKey.split("\\.")) {
            node = node.path(segment);
        }
        return node.isTextual() ? node.asText() : "";
    }
}
