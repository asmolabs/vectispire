package com.asmolabs.vectispire.reportdemo;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A project export, read as this plugin understands {@code vectispire-project-export} 1.x — and refused
 * otherwise.
 *
 * <p><b>Read as a tree, never bound to records.</b> A plugin written for 1.0 must read every 1.x and
 * ignore what it does not know (the schema's own words); a tree reads a field it was not told about by
 * not looking at it, where a record binding would have to be told to forgive it field by field.
 *
 * <p><b>A part this plugin renders must be there.</b> The export states every part, an empty array meaning
 * "produced, nothing in it" (decision 0007): a document missing its {@code issues} is not a project
 * without issues, and rendering it as one would put "no issue" under the platform's signature.
 */
final class ExportDocument {

    static final String SCHEMA = "vectispire-project-export";
    static final int MAJOR = 1;

    private static final Pattern VERSION = Pattern.compile("^(\\d{1,4})\\.(\\d{1,4})$");

    /** The parts the workbook is drawn from, each required in the type the schema gives it. */
    private static final String[] OBJECTS = {"export", "project"};

    private static final String[] ARRAYS = {"gate", "issues", "issue_counts", "checklists"};

    private static final ObjectMapper JSON = JsonMapper.builder()
            // Two values for one key: two readers of the same file could each take a different one.
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            // Anything after the document is not part of it, and not ignored either.
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    private final JsonNode root;

    private ExportDocument(JsonNode root) {
        this.root = root;
    }

    static ExportDocument read(byte[] bytes) throws RefusedExport {
        JsonNode root;
        try {
            root = JSON.readTree(bytes);
        } catch (JsonProcessingException malformed) {
            throw new RefusedExport(RefusedExport.Kind.UNREADABLE, "The export is not a JSON document: "
                    + malformed.getOriginalMessage());
        } catch (IOException unreadable) {
            throw new RefusedExport(RefusedExport.Kind.UNREADABLE, "The export could not be read: "
                    + unreadable.getMessage());
        }
        if (root == null || !root.isObject()) {
            throw new RefusedExport(RefusedExport.Kind.UNREADABLE, "The export is not a JSON object.");
        }
        JsonNode schema = root.get("schema");
        if (schema == null || !SCHEMA.equals(schema.asText(null))) {
            throw new RefusedExport(RefusedExport.Kind.UNSUPPORTED, "This plugin reads " + SCHEMA + " documents; this "
                    + "one states schema " + quoted(schema) + ".");
        }
        JsonNode version = root.get("schema_version");
        Matcher matcher = version == null || !version.isTextual() ? null : VERSION.matcher(version.asText());
        if (matcher == null || !matcher.matches()) {
            throw new RefusedExport(RefusedExport.Kind.UNSUPPORTED, "The export states no MAJOR.MINOR schema_version ("
                    + quoted(version) + "); this plugin reads major " + MAJOR + ".");
        }
        if (Integer.parseInt(matcher.group(1)) != MAJOR) {
            throw new RefusedExport(RefusedExport.Kind.UNSUPPORTED, "The export is " + SCHEMA + " "
                    + version.asText() + "; this plugin reads major " + MAJOR + " only, and a document of another "
                    + "major may mean something else by the same field.");
        }
        for (String part : OBJECTS) {
            if (!root.path(part).isObject()) {
                throw missing(part, "an object");
            }
        }
        for (String part : ARRAYS) {
            if (!root.path(part).isArray()) {
                throw missing(part, "an array");
            }
        }
        return new ExportDocument(root);
    }

    private static RefusedExport missing(String part, String what) {
        return new RefusedExport(RefusedExport.Kind.UNREADABLE, "The export's \"" + part + "\" is not " + what
                + ". Every part of an export is present, an empty one included; a document without it is not "
                + "rendered as if it were empty.");
    }

    private static String quoted(JsonNode value) {
        if (value == null || value.isMissingNode()) {
            return "none";
        }
        String text = value.toString();
        return text.length() <= 80 ? text : text.substring(0, 80) + "…";
    }

    JsonNode root() {
        return root;
    }

    JsonNode part(String name) {
        return root.path(name);
    }
}
