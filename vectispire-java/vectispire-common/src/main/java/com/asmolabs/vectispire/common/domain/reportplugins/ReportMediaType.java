package com.asmolabs.vectispire.common.domain.reportplugins;

import com.asmolabs.vectispire.common.domain.plugins.InvalidPluginException;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * What a report plugin may produce — the closed list of decision 0035 §3, each with the extension its
 * output file carries.
 *
 * <p><b>Closed, and checked on the bytes later.</b> The manifest declares one of these; the executor (lot R4)
 * checks the file against it before the platform signs anything. HTML is not here — a document served from
 * the product's origin would run in it — nor the legacy binary Office formats, nor a macro-enabled package,
 * whatever its extension. A type added here is a type the platform will sign; it comes with its check.
 *
 * <p><b>The extension is the manifest's too.</b> The output's file name is what a recipient double-clicks:
 * a workbook declared {@code .xlsx} and named {@code .xlsm} would open as a macro-enabled one on the
 * recipient's desktop, whatever the bytes check found. So the output must end with the type's extension.
 */
public enum ReportMediaType {
    XLSX("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx"),
    DOCX("application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx"),
    PPTX("application/vnd.openxmlformats-officedocument.presentationml.presentation", ".pptx"),
    ODS("application/vnd.oasis.opendocument.spreadsheet", ".ods"),
    ODT("application/vnd.oasis.opendocument.text", ".odt"),
    PDF("application/pdf", ".pdf"),
    CSV("text/csv", ".csv"),
    TEXT("text/plain", ".txt");

    private final String wireName;
    private final String extension;

    ReportMediaType(String wireName, String extension) {
        this.wireName = wireName;
        this.extension = extension;
    }

    /** The media type itself, as the manifest, the API and the database carry it. */
    @JsonValue
    public String wireName() {
        return wireName;
    }

    /** What the output's file name ends with, the dot included. */
    public String extension() {
        return extension;
    }

    /** @throws InvalidPluginException for a type off the list, naming the list */
    @JsonCreator
    public static ReportMediaType fromJson(String value) {
        return fromWireName(value).orElseThrow(() -> new InvalidPluginException(
                "A report plugin produces one of " + wireNames() + "; \"" + value + "\" is not offered: the platform "
                        + "signs what it produces, and checks each of these types before it does."));
    }

    public static Optional<ReportMediaType> fromWireName(String value) {
        if (value == null) {
            return Optional.empty();
        }
        String normalized = value.strip().toLowerCase(Locale.ROOT);
        return Arrays.stream(values()).filter(type -> type.wireName.equals(normalized)).findFirst();
    }

    public static List<String> wireNames() {
        return Arrays.stream(values()).map(ReportMediaType::wireName).toList();
    }
}
