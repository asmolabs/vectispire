package com.asmolabs.vectispire.common.domain.reports;

import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.stream.Location;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * An XML report read as a stream of elements, resolving nothing.
 *
 * <h2>Why a DOCTYPE is tolerated, and an internal subset is not</h2>
 *
 * <p>JaCoCo opens every report with {@code <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN"
 * "report.dtd">}, and Cobertura's writers name {@code coverage-04.dtd} the same way, so refusing any
 * DOCTYPE — {@code ProjectManifest}'s rule for a {@code pom.xml} — would refuse the formats this
 * exists to read. The declaration is therefore <b>read as text and never acted on</b>: DTD support is
 * off, so the named DTD is never fetched (a {@code SYSTEM "http://…"} would otherwise be a request
 * made from this host on the uploader's behalf) and nothing it could declare applies.
 *
 * <p><b>No entity is ever defined</b>, which is the guard itself: with DTD support off, the JDK's
 * parser skips an internal subset's declarations — the {@code [ … ]} inside the DOCTYPE, the one
 * place a document declares entities of its own, external ({@code <!ENTITY x SYSTEM
 * "file:///etc/passwd">}) or expanding ({@code <!ENTITY a "&b;&b;…">}) — so a reference to one is an
 * undeclared entity: an error, or, in an attribute of a document naming an external DTD, an empty
 * value (a count then reads as no count and is refused). Two nets over that, so that the refusal
 * says what it is: an internal subset is refused when the parser reports the DOCTYPE, and an entity
 * reference in text that is not one of XML's five is refused when it is met. The first is not the
 * guard — without an XML declaration the JDK hands back the DOCTYPE's text damaged, and the document
 * is then refused as not well-formed at the reference instead. No report format this reads needs an
 * internal subset.
 *
 * <h2>The implementation is the JDK's</h2>
 *
 * <p>{@link XMLInputFactory#newDefaultFactory()}, never {@code newFactory()}: the latter resolves an
 * implementation from the classpath and the system properties, so which parser ran — and which of
 * these switches it honours — would become a property of the host. The same reason the
 * cryptography is BouncyCastle's lightweight API rather than the JCA.
 *
 * <h2>Bounds</h2>
 *
 * <p>Nesting at {@value #MAX_DEPTH}, attributes at {@value #MAX_ATTRIBUTES} per element, and the
 * element count against a {@link Budget} the caller shares across every document of one upload — a
 * zip of five thousand files is one budget, not five thousand. The size of the input is the
 * caller's ceiling, checked before the first byte is parsed.
 */
final class SafeXml {

    static final int MAX_DEPTH = 64;
    static final int MAX_ATTRIBUTES = 64;

    private SafeXml() {}

    /** An element as it starts: valid only for the duration of the callback. */
    record Element(String name, int depth, XMLStreamReader reader) {

        /** The attribute's value, or {@code null} when the element does not carry it. */
        String attribute(String attribute) {
            return reader.getAttributeValue(null, attribute);
        }
    }

    interface Handler {
        void start(Element element);

        default void end(String name, int depth) {}
    }

    /** How many elements an upload may still hold, whatever the number of documents in it. */
    static final class Budget {
        private final long max;
        private long left;

        Budget(long max) {
            this.max = max;
            this.left = max;
        }

        void spend() {
            if (--left < 0) {
                throw new InvalidReportException("The report holds more than " + max + " XML elements.");
            }
        }
    }

    /**
     * Reads one document to its end, calling the handler on every element.
     *
     * @param what the document as the producer knows it — "The JaCoCo report", "Entry TEST-a.xml"
     * @throws InvalidReportException not well-formed, an internal subset, an entity, past a bound
     */
    static void read(InputStream input, String what, Budget budget, Handler handler) {
        XMLStreamReader reader;
        try {
            reader = factory().createXMLStreamReader(input);
        } catch (XMLStreamException unreadable) {
            throw malformed(what, unreadable);
        }
        int depth = 0;
        try {
            while (reader.hasNext()) {
                switch (reader.next()) {
                    case XMLStreamConstants.DTD -> refuseInternalSubset(what, reader.getText());
                    case XMLStreamConstants.ENTITY_REFERENCE -> throw new InvalidReportException(what
                            + " refers to the entity &" + reader.getLocalName() + "; — entities are not expanded.");
                    case XMLStreamConstants.START_ELEMENT -> {
                        depth++;
                        if (depth > MAX_DEPTH) {
                            throw new InvalidReportException(what + " nests elements deeper than " + MAX_DEPTH + ".");
                        }
                        if (reader.getAttributeCount() > MAX_ATTRIBUTES) {
                            throw new InvalidReportException(what + " has an element with more than " + MAX_ATTRIBUTES
                                    + " attributes.");
                        }
                        budget.spend();
                        handler.start(new Element(reader.getLocalName(), depth, reader));
                    }
                    case XMLStreamConstants.END_ELEMENT -> {
                        handler.end(reader.getLocalName(), depth);
                        depth--;
                    }
                    default -> {
                        // Text, comments, processing instructions: nothing a count is read from.
                    }
                }
            }
        } catch (XMLStreamException unreadable) {
            throw malformed(what, unreadable);
        } finally {
            try {
                reader.close();
            } catch (XMLStreamException ignored) {
                // Closing a reader over a byte stream releases nothing that could fail.
            }
        }
    }

    /**
     * A DOCTYPE with nothing but a name and identifiers passes; one carrying declarations does not.
     * A public identifier cannot contain {@code [}, so its presence is the subset's opening bracket.
     */
    private static void refuseInternalSubset(String what, String doctype) {
        if (doctype != null && (doctype.indexOf('[') >= 0 || doctype.indexOf("<!", 1) >= 0)) {
            throw new InvalidReportException(what + " declares an internal DTD subset, where entities are declared; it is "
                    + "not read. A DOCTYPE that only names its DTD is accepted, and the DTD is never loaded.");
        }
    }

    /**
     * Where the parser stopped, and not its message: the JDK's messages are localised to the
     * server's locale, which is not the reader's, and they quote the document back.
     */
    private static InvalidReportException malformed(String what, XMLStreamException unreadable) {
        Location at = unreadable.getLocation();
        String where = at == null ? "" : " (line " + at.getLineNumber() + ", column " + at.getColumnNumber() + ")";
        return new InvalidReportException(what + " is not well-formed XML" + where + ".");
    }

    private static XMLInputFactory factory() {
        XMLInputFactory factory = XMLInputFactory.newDefaultFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false);
        factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        return factory;
    }
}
