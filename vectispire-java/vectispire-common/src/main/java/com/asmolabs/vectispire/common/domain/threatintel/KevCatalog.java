package com.asmolabs.vectispire.common.domain.threatintel;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * CISA's catalogue of Known Exploited Vulnerabilities, as one document read whole.
 *
 * <p><b>Read whole, or not at all.</b> The catalogue is a replacement, not a delta: a CVE the
 * document does not list is taken as not listed, and an issue flagged exploited is un-flagged when
 * its CVE leaves it. That makes a partial document dangerous in a way an unreachable one is not — a
 * mirror serving a truncated file, or an answer that is JSON but not the catalogue, would un-flag
 * every exploited vulnerability it lost, and the gate would go green on them. So a document without
 * its {@code vulnerabilities} array, one that lists nothing, or one that carries fewer entries than
 * the {@code count} it declares is {@link Unreadable}, and the catalogue already stored stays.
 *
 * @param version CISA's {@code catalogVersion}, as published; null when the document carries none
 * @param released CISA's {@code dateReleased}: how old the data is, which the date of the sync does
 *     not say — a mirror refreshed weekly is synced every six hours with the same week-old catalogue
 * @param added every listed CVE, upper-case, with the day CISA added it (null when unreadable)
 */
public record KevCatalog(String version, Instant released, Map<String, Instant> added) {

    /** The shape of a CVE identifier; anything else in the list is not a catalogue entry. */
    private static final Pattern CVE = Pattern.compile("CVE-\\d{4}-\\d{4,}");

    /** The column the version is stored in. */
    static final int VERSION_MAX = 32;

    public KevCatalog {
        // Not Map.copyOf, which refuses a null value: a day CISA did not state is unknown, and the
        // entry is still an entry.
        added = Collections.unmodifiableMap(new LinkedHashMap<>(added));
    }

    /** A document that is not the catalogue, or not all of it. Never read as an empty catalogue. */
    public static final class Unreadable extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public Unreadable(String reason) {
            super(reason);
        }
    }

    /**
     * The catalogue this document is.
     *
     * @throws Unreadable when it is not the whole catalogue — see the class comment for why a
     *     partial one is refused rather than applied
     */
    public static KevCatalog parse(JsonNode payload) {
        JsonNode vulnerabilities = payload == null ? null : payload.path("vulnerabilities");
        if (vulnerabilities == null || !vulnerabilities.isArray()) {
            throw new Unreadable("the document has no \"vulnerabilities\" list: it is not the KEV catalogue");
        }

        Map<String, Instant> added = new LinkedHashMap<>();
        for (JsonNode entry : vulnerabilities) {
            JsonNode id = entry.path("cveID");
            if (!id.isTextual()) {
                continue;
            }
            String cve = id.asText().trim().toUpperCase(Locale.ROOT);
            if (CVE.matcher(cve).matches()) {
                added.putIfAbsent(cve, day(entry.path("dateAdded")));
            }
        }

        if (added.isEmpty()) {
            // CISA's catalogue has held well over a thousand entries since its first year. An empty
            // one applied as such would un-flag every exploited vulnerability in the backlog.
            throw new Unreadable("the document lists no vulnerability");
        }
        JsonNode count = payload.path("count");
        if (count.isIntegralNumber() && count.asLong() > added.size()) {
            throw new Unreadable("the document declares " + count.asLong() + " entries and carries "
                    + added.size() + ": it is incomplete");
        }

        return new KevCatalog(version(payload.path("catalogVersion")), instant(payload.path("dateReleased")), added);
    }

    private static String version(JsonNode node) {
        if (!node.isTextual() || node.asText().isBlank()) {
            return null;
        }
        String version = node.asText().trim();
        return version.length() <= VERSION_MAX ? version : version.substring(0, VERSION_MAX);
    }

    private static Instant instant(JsonNode node) {
        if (!node.isTextual()) {
            return null;
        }
        try {
            return Instant.parse(node.asText().trim());
        } catch (DateTimeParseException unreadable) {
            // Unknown rather than invented: a release date that cannot be read says nothing about
            // how old the data is, and "now" would say it is fresh.
            return null;
        }
    }

    private static Instant day(JsonNode node) {
        if (!node.isTextual()) {
            return null;
        }
        try {
            return LocalDate.parse(node.asText().trim()).atStartOfDay(ZoneOffset.UTC).toInstant();
        } catch (DateTimeParseException unreadable) {
            return null;
        }
    }
}
