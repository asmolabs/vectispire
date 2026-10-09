package com.asmolabs.vectispire.core.compliance.internal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Optional;

/**
 * The column {@code evidence_identifiers} (V84): the identifiers an OWASP review's model was shown,
 * written as a JSON array when the review is requested and read back for the report's links.
 *
 * <p><b>JSON rather than a separator.</b> An identifier is whatever a scanner, a plugin or an import
 * wrote; no character is guaranteed absent from it, and a list split on one would hand the links an
 * identifier nobody reported.
 */
public final class EvidenceIdentifiers {

    private static final ObjectMapper JSON = new ObjectMapper();

    private EvidenceIdentifiers() {}

    public static String write(List<String> identifiers) {
        try {
            return JSON.writeValueAsString(List.copyOf(identifiers));
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("A list of strings could not be written as JSON.", impossible);
        }
    }

    /**
     * The column read back, or empty when it holds nothing readable — a review written before V84, or a
     * value nobody here wrote.
     *
     * <p><b>Empty, and not an empty list.</b> An empty list says the model was shown no identified
     * finding, so there is nothing to link; an unreadable column says nothing was recorded, and a
     * screen told "nothing to link" would be told something nobody knows.
     */
    public static Optional<List<String>> read(String column) {
        if (column == null || column.isBlank()) {
            return Optional.empty();
        }
        try {
            List<String> identifiers = JSON.readValue(column, new TypeReference<List<String>>() {});
            return identifiers == null || identifiers.contains(null)
                    ? Optional.empty()
                    : Optional.of(List.copyOf(identifiers));
        } catch (JsonProcessingException unreadable) {
            return Optional.empty();
        }
    }
}
