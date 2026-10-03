package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportSchema;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.Error;
import com.networknt.schema.InputFormat;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Holds a project export to its published schema (decision 0035 §1), in two passes.
 *
 * <p><b>The schema, by a validator.</b> Every required field present, every type as declared, read by a
 * draft 2020-12 implementation rather than by this test's idea of one.
 *
 * <p><b>Nothing the schema does not declare.</b> The published schema stays open — a reader of 1.0 must
 * read a 1.3 export, so it cannot refuse a property it does not know — which means a validator alone
 * would let the generator write a field nobody added to the schema. This pass walks the export beside the
 * schema and fails on any property a declared object does not list; it stops where the schema stops
 * declaring (the checklist statement's insides, whose contract is {@code checklist.json}'s own).
 */
final class ProjectExportContract {

    private static final ObjectMapper JSON = new ObjectMapper();

    private ProjectExportContract() {}

    static String schemaText() {
        return new String(ProjectExportSchema.of(ProjectExportSchema.MAJOR).orElseThrow(), StandardCharsets.UTF_8);
    }

    /** Fails unless the export is valid against the schema and carries nothing it does not declare. */
    static void conforms(byte[] export) throws Exception {
        String text = new String(export, StandardCharsets.UTF_8);
        Schema schema = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)
                .getSchema(schemaText(), InputFormat.JSON);
        List<Error> errors = schema.validate(text, InputFormat.JSON);
        assertThat(errors).as("the export against v%d.schema.json", ProjectExportSchema.MAJOR)
                .extracting(error -> error.getInstanceLocation() + ": " + error.getMessage())
                .isEmpty();

        JsonNode root = JSON.readTree(schemaText());
        List<String> undeclared = new ArrayList<>();
        walk(root, root, JSON.readTree(export), "$", undeclared);
        assertThat(undeclared).as("properties the export writes and the schema does not declare").isEmpty();
    }

    private static void walk(JsonNode root, JsonNode schema, JsonNode value, String path, List<String> undeclared) {
        schema = resolve(root, schema);
        if (value == null || value.isNull()) {
            return;
        }
        if (schema.has("oneOf")) {
            for (JsonNode option : schema.get("oneOf")) {
                JsonNode resolved = resolve(root, option);
                if (resolved.has("properties") || resolved.has("items")) {
                    walk(root, resolved, value, path, undeclared);
                }
            }
            return;
        }
        if (value.isObject() && schema.has("properties")) {
            JsonNode properties = schema.get("properties");
            for (Map.Entry<String, JsonNode> field : value.properties()) {
                if (!properties.has(field.getKey())) {
                    undeclared.add(path + "." + field.getKey());
                } else {
                    walk(root, properties.get(field.getKey()), field.getValue(), path + "." + field.getKey(), undeclared);
                }
            }
        } else if (value.isArray() && schema.has("items")) {
            int index = 0;
            for (JsonNode element : value) {
                walk(root, schema.get("items"), element, path + "[" + index++ + "]", undeclared);
            }
        }
    }

    private static JsonNode resolve(JsonNode root, JsonNode schema) {
        while (schema.has("$ref")) {
            String reference = schema.get("$ref").asText();
            if (!reference.startsWith("#/")) {
                throw new IllegalStateException("Only local references are expected: " + reference);
            }
            schema = root.at(reference.substring(1));
        }
        return schema;
    }
}
