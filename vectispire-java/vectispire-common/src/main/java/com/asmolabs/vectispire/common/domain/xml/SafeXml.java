package com.asmolabs.vectispire.common.domain.xml;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.io.InputStream;
import java.util.Objects;
import java.util.function.Function;
import javax.xml.XMLConstants;
import javax.xml.stream.Location;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * An uploaded XML document read as a stream of elements, resolving nothing.
 *
 * <p>Shared by every reader of a document somebody else wrote — the coverage and test reports, the
 * parts of a checklist workbook — so that the switches below are set once. Each caller states two
 * things: what a DOCTYPE means in its format ({@link Doctype}), and the refusal its route answers
 * with, so a report is refused as a report and a workbook as a workbook, in their own words.
 *
 * <h2>Why a DOCTYPE may be tolerated, and an internal subset never is</h2>
 *
 * <p>JaCoCo opens every report with {@code <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN"
 * "report.dtd">}, and Cobertura's writers name {@code coverage-04.dtd} the same way, so refusing any
 * DOCTYPE — {@code ProjectManifest}'s rule for a {@code pom.xml} — would refuse the formats the
 * report readers exist to read. For them ({@link Doctype#NAMED_ONLY}) the declaration is <b>read as
 * text and never acted on</b>: DTD support is off, so the named DTD is never fetched (a {@code SYSTEM
 * "http://…"} would otherwise be a request made from this host on the uploader's behalf) and nothing
 * it could declare applies. A workbook's parts are written by Office and never carry one, so there
 * ({@link Doctype#REFUSED}) any DOCTYPE is refused: a part that has one was edited by hand to have it.
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
 * is then refused as not well-formed at the reference instead. No format read here needs an
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
 * caller's ceiling, checked before the first byte is parsed; text is handed over in the chunks the
 * parser produces, and a caller keeping it bounds what it keeps.
 */
public final class SafeXml {

    public static final int MAX_DEPTH = 64;
    public static final int MAX_ATTRIBUTES = 64;

    /** What a DOCTYPE declaration means in the caller's format. */
    public enum Doctype {
        /** Tolerated when it only names its DTD, which is never loaded; an internal subset is refused. */
        NAMED_ONLY,
        /** Refused whatever it holds: the format never carries one. */
        REFUSED
    }

    private final Doctype doctype;
    private final Function<String, ? extends InvalidInputException> refusal;

    private SafeXml(Doctype doctype, Function<String, ? extends InvalidInputException> refusal) {
        this.doctype = Objects.requireNonNull(doctype);
        this.refusal = Objects.requireNonNull(refusal);
    }

    /**
     * @param refusal builds the exception every refusal is thrown as, from its sentence — a 400 in
     *     the caller's words, since the document is the caller's to correct
     */
    public static SafeXml of(Doctype doctype, Function<String, ? extends InvalidInputException> refusal) {
        return new SafeXml(doctype, refusal);
    }

    /** An element as it starts: valid only for the duration of the callback. */
    public record Element(String name, int depth, XMLStreamReader reader) {

        /**
         * The attribute's value, or {@code null} when the element does not carry it. Matched by its
         * local name in any namespace: OOXML's {@code r:id} is read as {@code id}.
         */
        public String attribute(String attribute) {
            return reader.getAttributeValue(null, attribute);
        }
    }

    public interface Handler {
        void start(Element element);

        default void end(String name, int depth) {}

        /**
         * Character data inside the element at {@code depth}, possibly in several chunks: the parser
         * does not coalesce, and a caller that needs the whole text joins them until {@link #end}.
         */
        default void text(String characters, int depth) {}
    }

    /** How many elements an upload may still hold, whatever the number of documents in it. */
    public static final class Budget {
        private final long max;
        private final String whole;
        private long left;

        /** @param whole the upload as its sender knows it — "The report", "The workbook" */
        public Budget(long max, String whole) {
            this.max = max;
            this.whole = whole;
            this.left = max;
        }

        private boolean spend() {
            return --left >= 0;
        }
    }

    /**
     * Reads one document to its end, calling the handler on every element.
     *
     * @param what the document as the producer knows it — "The JaCoCo report", "Entry TEST-a.xml"
     * @throws InvalidInputException as built by the refusal: not well-formed, a DOCTYPE this format
     *     does not allow, an entity, past a bound
     */
    public void read(InputStream input, String what, Budget budget, Handler handler) {
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
                    case XMLStreamConstants.DTD -> refuseDoctype(what, reader.getText());
                    case XMLStreamConstants.ENTITY_REFERENCE -> throw refusal.apply(what
                            + " refers to the entity &" + reader.getLocalName() + "; — entities are not expanded.");
                    case XMLStreamConstants.START_ELEMENT -> {
                        depth++;
                        if (depth > MAX_DEPTH) {
                            throw refusal.apply(what + " nests elements deeper than " + MAX_DEPTH + ".");
                        }
                        if (reader.getAttributeCount() > MAX_ATTRIBUTES) {
                            throw refusal.apply(what + " has an element with more than " + MAX_ATTRIBUTES
                                    + " attributes.");
                        }
                        if (!budget.spend()) {
                            throw refusal.apply(budget.whole + " holds more than " + budget.max + " XML elements.");
                        }
                        handler.start(new Element(reader.getLocalName(), depth, reader));
                    }
                    case XMLStreamConstants.END_ELEMENT -> {
                        handler.end(reader.getLocalName(), depth);
                        depth--;
                    }
                    case XMLStreamConstants.CHARACTERS, XMLStreamConstants.CDATA, XMLStreamConstants.SPACE -> {
                        if (depth > 0) {
                            handler.text(reader.getText(), depth);
                        }
                    }
                    default -> {
                        // Comments, processing instructions: nothing any reader here takes a value from.
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
     * A DOCTYPE with nothing but a name and identifiers passes where the format allows one; one
     * carrying declarations never does. A public identifier cannot contain {@code [}, so its presence
     * is the subset's opening bracket.
     */
    private void refuseDoctype(String what, String declaration) {
        if (doctype == Doctype.REFUSED) {
            throw refusal.apply(what + " carries a DOCTYPE declaration, which this format never needs; it is not "
                    + "read.");
        }
        if (declaration != null && (declaration.indexOf('[') >= 0 || declaration.indexOf("<!", 1) >= 0)) {
            throw refusal.apply(what + " declares an internal DTD subset, where entities are declared; it is "
                    + "not read. A DOCTYPE that only names its DTD is accepted, and the DTD is never loaded.");
        }
    }

    /**
     * Where the parser stopped, and not its message: the JDK's messages are localised to the
     * server's locale, which is not the reader's, and they quote the document back.
     */
    private InvalidInputException malformed(String what, XMLStreamException unreadable) {
        Location at = unreadable.getLocation();
        String where = at == null ? "" : " (line " + at.getLineNumber() + ", column " + at.getColumnNumber() + ")";
        return refusal.apply(what + " is not well-formed XML" + where + ".");
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
