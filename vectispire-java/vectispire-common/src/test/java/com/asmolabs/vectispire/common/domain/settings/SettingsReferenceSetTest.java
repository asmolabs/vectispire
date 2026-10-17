package com.asmolabs.vectispire.common.domain.settings;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The settings catalog as this side defines it, and what it accepts, for the control plane's Rust port
 * (`vectispire-rust/crates/cp-settings`) — see {@code ReferenceSet}.
 *
 * <p><b>Every setting, every answer the catalog gives about it.</b> The key and the default decide what a
 * stored row means; the label and the help are what the screen shows; and the rest decides who may write
 * it and whether the SOC hears of it: {@code administratorOnly}, {@code governorOnly}, {@code
 * governsSecurity}, the sensitivity. A Rust catalog that drifted on one of those would let a role write a
 * setting it may not, or keep a security change from the SIEM, with nothing to show for it.
 */
class SettingsReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private static String sensitivity(Setting setting) {
        return setting.isEncrypted() ? "ENCRYPTED" : setting.isSecret() ? "SECRET" : "PLAIN";
    }

    @Test
    void theCatalog() throws Exception {
        ArrayNode catalog = JSON.createArrayNode();
        for (Setting setting : Setting.values()) {
            ObjectNode node = catalog.addObject();
            node.put("name", setting.name());
            node.put("key", setting.key());
            node.put("type", setting.type().name());
            node.put("section", setting.section().name());
            node.put("sectionLabel", setting.section().label());
            node.put("label", setting.label());
            node.put("help", setting.help());
            node.put("defaultValue", setting.defaultValue());
            node.put("sensitivity", sensitivity(setting));
            node.put("isSecret", setting.isSecret());
            node.put("isEncrypted", setting.isEncrypted());
            node.put("directsCredential", setting.directsCredential().map(Setting::name).orElse(null));
            node.put("administratorOnly", setting.administratorOnly());
            node.put("governorOnly", setting.governorOnly());
            node.put("governsSecurity", setting.governsSecurity());
        }
        ReferenceSet.expect("settings/catalog.json", JSON.writeValueAsString(catalog) + "\n");
    }

    /** The values a setting's validation is asked about: every type's edges, and the tracker URL's. */
    private static List<String> inputs() {
        List<String> inputs = new ArrayList<>(Arrays.asList(
                null, "", " ", "true", "false", "TRUE", "True", " true", "yes", "1",
                "0", "7", " 7 ", "\t7\n", "+5", "-1", "-0", "007", "1.5", "1e3", "abc", "2147483647", "2147483648",
                "١٢", // Arabic-Indic digits, which Integer.parseInt reads
                "critical", "high", "medium", "low", "negligible", "unknown", "Critical", " high",
                "https://jira.example.com", "https://jira.example.com/", "https://user:token@jira.example.com",
                "https://user@jira.example.com", " https://user@jira.example.com ", "HTTP://U@H", "ssh://git@host/x",
                "ssh://git:pw@host/x", "//user@host/path", "//@host", "http://host?x@y", "http://host#x@y",
                "http://user@host:notaport", "http://user@[::1]/", "http://[::1]/", "mailto:user@host",
                "https://host/path@thing", "ftp://@host", "https://us er@host", "not a url", "http://",
                "https://%41@host", "https://ü@host"));
        inputs.add("x".repeat(16_000));
        inputs.add("x".repeat(16_001));
        inputs.add("x".repeat(15_999) + "🛡"); // 16,001 UTF-16 units, 16,000 code points
        return inputs;
    }

    @Test
    void whatEachSettingAccepts() throws Exception {
        ArrayNode cases = JSON.createArrayNode();
        for (Setting setting : Setting.values()) {
            for (String input : inputs()) {
                String answer = setting.validate(input).orElse(null);
                if (answer == null && input != null && input.length() > 200) {
                    // Long inputs only once each: whether the ceiling holds, not the same "fits" 54 times.
                    if (setting.type() != SettingType.TEXT) {
                        continue;
                    }
                }
                ObjectNode node = cases.addObject();
                node.put("setting", setting.name());
                if (input != null && input.length() > 200) {
                    node.put("repeat", input.charAt(0) + "");
                    node.put("units", input.length());
                    node.put("tail", input.length() > 16_000 && input.endsWith("🛡") ? "🛡" : null);
                } else {
                    node.put("input", input);
                }
                node.put("refusal", answer);
            }
        }
        ReferenceSet.expect("settings/validation.json", JSON.writeValueAsString(cases) + "\n");
    }

    /**
     * The code points {@code Integer.parseInt} reads as the digit zero: an integer setting accepts any decimal
     * digit {@code Character.digit} knows, not only ASCII's, and each block of ten starts at one of these.
     */
    @Test
    void theDecimalDigitZeros() {
        StringBuilder text = new StringBuilder();
        for (int codePoint = 0; codePoint <= Character.MAX_CODE_POINT; codePoint++) {
            if (Character.digit(codePoint, 10) == 0) {
                text.append(String.format("%X", codePoint)).append('\n');
            }
        }
        ReferenceSet.expect("settings/digit-zeros.txt", text.toString());
    }

    /** The thresholds a severity setting offers, in order. */
    @Test
    void theThresholds() {
        StringBuilder text = new StringBuilder();
        SettingType.THRESHOLDS.forEach(severity -> text.append(severity.wireName()).append('\n'));
        ReferenceSet.expect("settings/thresholds.txt", text.toString());
    }
}
