package com.asmolabs.vectispire.common.domain.reports;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.Locale;

/**
 * A test report as the pipeline declares it: one JUnit XML document, or a zip of them — most build
 * tools write one file per test class, and a pipeline should not have to merge them.
 *
 * <p>Declared by the request's media type and never sniffed, like a coverage format: a zip is read as
 * a zip because the pipeline said so, and a body that is not one is refused.
 */
public enum TestReportFormat {
    JUNIT_XML("junit"),
    JUNIT_ZIP("junit-zip");

    private final String wireName;

    TestReportFormat(String wireName) {
        this.wireName = wireName;
    }

    public String wireName() {
        return wireName;
    }

    /**
     * {@code application/xml} or {@code text/xml} for one document, {@code application/zip} for an
     * archive; parameters such as {@code charset} are ignored — the XML declaration names its own.
     */
    public static TestReportFormat ofMediaType(String mediaType) {
        String type = mediaType == null ? "" : mediaType.split(";", 2)[0].strip().toLowerCase(Locale.ROOT);
        return switch (type) {
            case "application/xml", "text/xml" -> JUNIT_XML;
            case "application/zip" -> JUNIT_ZIP;
            default -> throw new InvalidInputException("Send a JUnit XML document as application/xml, or a zip of them "
                    + "as application/zip" + (type.isEmpty() ? "" : "; \"" + BoundedText.clip(type, 60) + "\" is neither")
                    + ".");
        };
    }
}
