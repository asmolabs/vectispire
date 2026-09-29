package com.asmolabs.vectispire.common.domain.checklists;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.SequencedMap;
import java.util.Set;

/**
 * The tags of an XML part, one after the other, each with where it starts and ends in the text — what
 * the renderer needs to replace a few cells and leave every other byte of the part where it was.
 *
 * <p><b>Why not a StAX writer.</b> Reading a part into events and writing them back re-serialises all
 * of it: quotes, namespace declarations, empty elements, character references come out as the writer
 * spells them, and a sheet whose one cell changed becomes a sheet of which every line changed. The
 * renderer's promise is narrower — the template's own bytes around the cells it writes — and holding it
 * takes offsets, which the JDK's pull parser does not give exactly.
 *
 * <p><b>Only on parts already read by {@link WorkbookReader}.</b> The reader has refused a DOCTYPE and
 * a malformed part, through the hardened parser; this cursor splits what is known to be well-formed
 * and resolves nothing — no entity but the five predefined ones and character references, which are
 * all an attribute value may carry without a DTD. Text between tags is never tokenised: a {@code >}
 * is legal in it, and a {@code <} is not.
 */
final class XmlCursor {

    enum Kind {
        START,
        END,
        /** A self-closing tag: {@code <c r="A1"/>}. */
        EMPTY
    }

    /** An attribute as written: its qualified name, its value undecoded, and the quote around it. */
    record Attribute(String name, String raw, char quote) {

        String value() {
            return decode(raw);
        }

        String local() {
            int colon = name.indexOf(':');
            return colon < 0 ? name : name.substring(colon + 1);
        }

        boolean prefixed() {
            return name.indexOf(':') > 0;
        }
    }

    /**
     * A tag of the part.
     *
     * @param start the offset of its {@code <}
     * @param end the offset just after its {@code >}
     */
    record Tag(Kind kind, String name, int start, int end, List<Attribute> attributes) {

        String local() {
            int colon = name.indexOf(':');
            return colon < 0 ? name : name.substring(colon + 1);
        }

        /** The prefix with its colon — {@code "x:"} — or nothing: what a sibling written beside it uses. */
        String prefix() {
            int colon = name.indexOf(':');
            return colon < 0 ? "" : name.substring(0, colon + 1);
        }

        Optional<String> attribute(String qualifiedName) {
            return attributes.stream().filter(attribute -> attribute.name().equals(qualifiedName)).findFirst()
                    .map(Attribute::value);
        }

        boolean opens() {
            return kind != Kind.END;
        }
    }

    private final String xml;
    private int position;

    XmlCursor(String xml) {
        this.xml = xml;
    }

    /** The next tag, comments, processing instructions and CDATA sections skipped; null at the end. */
    Tag next() {
        while (true) {
            int open = xml.indexOf('<', position);
            if (open < 0) {
                position = xml.length();
                return null;
            }
            if (xml.startsWith("<!--", open)) {
                position = after(open, "-->");
            } else if (xml.startsWith("<![CDATA[", open)) {
                position = after(open, "]]>");
            } else if (xml.startsWith("<?", open)) {
                position = after(open, "?>");
            } else if (xml.startsWith("<!", open)) {
                throw new InvalidTemplateException("A part of the workbook carries a declaration the renderer does not "
                        + "read.");
            } else if (xml.startsWith("</", open)) {
                int close = xml.indexOf('>', open);
                if (close < 0) {
                    throw truncated();
                }
                position = close + 1;
                return new Tag(Kind.END, xml.substring(open + 2, close).strip(), open, close + 1, List.of());
            } else {
                return startTag(open);
            }
        }
    }

    private Tag startTag(int open) {
        int i = open + 1;
        int nameStart = i;
        while (i < xml.length() && !Character.isWhitespace(xml.charAt(i)) && xml.charAt(i) != '/' && xml.charAt(i) != '>') {
            i++;
        }
        String name = xml.substring(nameStart, i);
        List<Attribute> attributes = new ArrayList<>();
        while (true) {
            while (i < xml.length() && Character.isWhitespace(xml.charAt(i))) {
                i++;
            }
            if (i >= xml.length()) {
                throw truncated();
            }
            char c = xml.charAt(i);
            if (c == '>') {
                position = i + 1;
                return new Tag(Kind.START, name, open, i + 1, List.copyOf(attributes));
            }
            if (c == '/' && i + 1 < xml.length() && xml.charAt(i + 1) == '>') {
                position = i + 2;
                return new Tag(Kind.EMPTY, name, open, i + 2, List.copyOf(attributes));
            }
            int attributeStart = i;
            while (i < xml.length() && xml.charAt(i) != '=' && !Character.isWhitespace(xml.charAt(i))) {
                i++;
            }
            String attribute = xml.substring(attributeStart, i);
            while (i < xml.length() && Character.isWhitespace(xml.charAt(i))) {
                i++;
            }
            if (i >= xml.length() || xml.charAt(i) != '=') {
                throw truncated();
            }
            i++;
            while (i < xml.length() && Character.isWhitespace(xml.charAt(i))) {
                i++;
            }
            if (i >= xml.length() || (xml.charAt(i) != '"' && xml.charAt(i) != '\'')) {
                throw truncated();
            }
            char quote = xml.charAt(i);
            int valueEnd = xml.indexOf(quote, i + 1);
            if (valueEnd < 0) {
                throw truncated();
            }
            attributes.add(new Attribute(attribute, xml.substring(i + 1, valueEnd), quote));
            i = valueEnd + 1;
        }
    }

    private int after(int from, String terminator) {
        int found = xml.indexOf(terminator, from);
        if (found < 0) {
            throw truncated();
        }
        return found + terminator.length();
    }

    private static InvalidTemplateException truncated() {
        return new InvalidTemplateException("A part of the workbook ends inside a tag.");
    }

    /**
     * A tag written again with some attributes set or removed and the others exactly as they were —
     * their order, their quotes, their escapes.
     *
     * @param set qualified names and their new values, unescaped; appended when the tag lacked them
     * @param open whether to write it as a start tag even when it was self-closing
     */
    static String rewrite(Tag tag, SequencedMap<String, String> set, Set<String> remove, boolean open) {
        StringBuilder written = new StringBuilder("<").append(tag.name());
        Set<String> done = new HashSet<>();
        for (Attribute attribute : tag.attributes()) {
            if (remove.contains(attribute.name())) {
                continue;
            }
            if (set.containsKey(attribute.name())) {
                written.append(' ').append(attribute.name()).append("=\"").append(escapeAttribute(set.get(attribute.name())))
                        .append('"');
                done.add(attribute.name());
            } else {
                written.append(' ').append(attribute.name()).append('=').append(attribute.quote()).append(attribute.raw())
                        .append(attribute.quote());
            }
        }
        set.forEach((name, value) -> {
            if (!done.contains(name)) {
                written.append(' ').append(name).append("=\"").append(escapeAttribute(value)).append('"');
            }
        });
        return written.append(tag.kind() == Kind.EMPTY && !open ? "/>" : ">").toString();
    }

    /** The five predefined entities and character references; anything else is left as written. */
    static String decode(String raw) {
        if (raw.indexOf('&') < 0) {
            return raw;
        }
        StringBuilder decoded = new StringBuilder(raw.length());
        int i = 0;
        while (i < raw.length()) {
            char c = raw.charAt(i);
            int semicolon = c == '&' ? raw.indexOf(';', i) : -1;
            if (semicolon < 0) {
                decoded.append(c);
                i++;
                continue;
            }
            String entity = raw.substring(i + 1, semicolon);
            String replacement = switch (entity) {
                case "lt" -> "<";
                case "gt" -> ">";
                case "amp" -> "&";
                case "quot" -> "\"";
                case "apos" -> "'";
                default -> characterReference(entity);
            };
            if (replacement == null) {
                decoded.append(c);
                i++;
            } else {
                decoded.append(replacement);
                i = semicolon + 1;
            }
        }
        return decoded.toString();
    }

    private static String characterReference(String entity) {
        try {
            if (entity.startsWith("#x") || entity.startsWith("#X")) {
                return Character.toString(Integer.parseInt(entity.substring(2), 16));
            }
            if (entity.startsWith("#")) {
                return Character.toString(Integer.parseInt(entity.substring(1)));
            }
        } catch (IllegalArgumentException notAReference) {
            return null;
        }
        return null;
    }

    /**
     * Text as an element's content: escaped, and without the characters XML 1.0 cannot carry at all —
     * a control character typed into a comment would otherwise make the whole part unreadable.
     */
    static String escapeText(String text) {
        StringBuilder escaped = new StringBuilder(text.length());
        text.codePoints().forEach(codePoint -> {
            switch (codePoint) {
                case '&' -> escaped.append("&amp;");
                case '<' -> escaped.append("&lt;");
                case '>' -> escaped.append("&gt;");
                default -> {
                    if (allowed(codePoint)) {
                        escaped.appendCodePoint(codePoint);
                    }
                }
            }
        });
        return escaped.toString();
    }

    static String escapeAttribute(String value) {
        return escapeText(value).replace("\"", "&quot;");
    }

    private static boolean allowed(int codePoint) {
        return codePoint == 0x9 || codePoint == 0xA || codePoint == 0xD
                || (codePoint >= 0x20 && codePoint <= 0xD7FF)
                || (codePoint >= 0xE000 && codePoint <= 0xFFFD)
                || (codePoint >= 0x10000 && codePoint <= 0x10FFFF);
    }
}
