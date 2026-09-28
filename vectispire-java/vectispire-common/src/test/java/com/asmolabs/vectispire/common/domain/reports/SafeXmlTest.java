package com.asmolabs.vectispire.common.domain.reports;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the XML reader under the report readers")
class SafeXmlTest {

    private static void read(String document, SafeXml.Budget budget, SafeXml.Handler handler) {
        SafeXml.read(new ByteArrayInputStream(document.getBytes(StandardCharsets.UTF_8)), "The report", budget, handler);
    }

    @Test
    @DisplayName("one budget of elements spans every document of an upload")
    void sharedBudget() {
        SafeXml.Budget budget = new SafeXml.Budget(5);
        read("<a><b/><c/></a>", budget, element -> {});

        assertThatThrownBy(() -> read("<a><b/><c/></a>", budget, element -> {}))
                .isInstanceOf(InvalidReportException.class)
                .hasMessage("The report holds more than 5 XML elements.");
    }

    @Test
    @DisplayName("an element with too many attributes is refused")
    void attributes() {
        StringBuilder element = new StringBuilder("<a");
        for (int i = 0; i <= SafeXml.MAX_ATTRIBUTES; i++) {
            element.append(" a").append(i).append("=\"x\"");
        }
        element.append("/>");

        assertThatThrownBy(() -> read(element.toString(), new SafeXml.Budget(10), e -> {}))
                .hasMessageContaining("more than " + SafeXml.MAX_ATTRIBUTES + " attributes");
    }

    @Test
    @DisplayName("hands each element its depth, and the predefined entities read as characters")
    void depths() {
        List<String> seen = new ArrayList<>();
        read("<a n=\"&lt;x&gt;\"><b><c/></b></a>", new SafeXml.Budget(10),
                element -> seen.add(element.name() + element.depth() + (element.attribute("n") == null ? "" : element.attribute("n"))));

        assertThat(seen).containsExactly("a1<x>", "b2", "c3");
    }

    @Test
    @DisplayName("says where the document broke, never the parser's localised words")
    void malformed() {
        assertThatThrownBy(() -> read("<a>\n<b></a>", new SafeXml.Budget(10), e -> {}))
                .hasMessageStartingWith("The report is not well-formed XML (line 2");
    }
}
