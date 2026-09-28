package com.asmolabs.vectispire.common.domain.xml;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the XML reader under the uploaded-document readers")
class SafeXmlTest {

    /** A refusal of its own, to see that the caller's type is the one thrown. */
    static final class Refused extends InvalidInputException {
        Refused(String message) {
            super(message);
        }
    }

    private static final SafeXml TOLERANT = SafeXml.of(SafeXml.Doctype.NAMED_ONLY, Refused::new);
    private static final SafeXml STRICT = SafeXml.of(SafeXml.Doctype.REFUSED, Refused::new);

    private static void read(SafeXml xml, String document, SafeXml.Budget budget, SafeXml.Handler handler) {
        xml.read(new ByteArrayInputStream(document.getBytes(StandardCharsets.UTF_8)), "The report", budget, handler);
    }

    private static void read(String document, SafeXml.Budget budget, SafeXml.Handler handler) {
        read(TOLERANT, document, budget, handler);
    }

    @Test
    @DisplayName("one budget of elements spans every document of an upload")
    void sharedBudget() {
        SafeXml.Budget budget = new SafeXml.Budget(5, "The report");
        read("<a><b/><c/></a>", budget, element -> {});

        assertThatThrownBy(() -> read("<a><b/><c/></a>", budget, element -> {}))
                .isInstanceOf(Refused.class)
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

        assertThatThrownBy(() -> read(element.toString(), new SafeXml.Budget(10, "The report"), e -> {}))
                .isInstanceOf(Refused.class)
                .hasMessageContaining("more than " + SafeXml.MAX_ATTRIBUTES + " attributes");
    }

    @Test
    @DisplayName("hands each element its depth, and the predefined entities read as characters")
    void depths() {
        List<String> seen = new ArrayList<>();
        read("<a n=\"&lt;x&gt;\"><b><c/></b></a>", new SafeXml.Budget(10, "The report"),
                element -> seen.add(element.name() + element.depth() + (element.attribute("n") == null ? "" : element.attribute("n"))));

        assertThat(seen).containsExactly("a1<x>", "b2", "c3");
    }

    @Test
    @DisplayName("hands text over at the depth of the element holding it, predefined entities and CDATA included")
    void text() {
        StringBuilder[] seen = {new StringBuilder(), new StringBuilder(), new StringBuilder()};
        read("<a>R&amp;D<b><![CDATA[<raw>]]></b></a>", new SafeXml.Budget(10, "The report"), new SafeXml.Handler() {
            @Override
            public void start(SafeXml.Element element) {}

            @Override
            public void text(String characters, int depth) {
                seen[depth].append(characters);
            }
        });

        assertThat(seen[1].toString()).isEqualTo("R&D");
        assertThat(seen[2].toString()).isEqualTo("<raw>");
    }

    @Test
    @DisplayName("says where the document broke, never the parser's localised words")
    void malformed() {
        assertThatThrownBy(() -> read("<a>\n<b></a>", new SafeXml.Budget(10, "The report"), e -> {}))
                .isInstanceOf(Refused.class)
                .hasMessageStartingWith("The report is not well-formed XML (line 2");
    }

    @Test
    @DisplayName("a DOCTYPE that only names its DTD passes where the format allows one, and never where it does not")
    void doctypePolicy() {
        String named = "<?xml version=\"1.0\"?><!DOCTYPE report PUBLIC \"-//JACOCO//DTD Report 1.1//EN\" \"report.dtd\"><report/>";
        read(named, new SafeXml.Budget(10, "The report"), e -> {});

        assertThatThrownBy(() -> read(STRICT, named, new SafeXml.Budget(10, "The report"), e -> {}))
                .isInstanceOf(Refused.class)
                .hasMessageContaining("carries a DOCTYPE declaration");
    }

    @Test
    @DisplayName("an internal subset is refused under either policy")
    void internalSubset() {
        String subset = "<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>";

        assertThatThrownBy(() -> read(subset, new SafeXml.Budget(10, "The report"), e -> {}))
                .isInstanceOf(Refused.class)
                .hasMessageContaining("internal DTD subset");
        assertThatThrownBy(() -> read(STRICT, subset, new SafeXml.Budget(10, "The report"), e -> {}))
                .isInstanceOf(Refused.class);
    }
}
