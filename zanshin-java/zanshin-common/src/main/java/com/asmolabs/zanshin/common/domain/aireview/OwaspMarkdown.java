package com.asmolabs.zanshin.common.domain.aireview;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The model's Markdown, read once into blocks that both renderers consume.
 *
 * <h2>Why the server parses it</h2>
 *
 * <p>The report is rendered twice — as a PDF and on a screen — and the first version parsed it
 * twice, in two languages. That is two answers to "what is a heading", and they drift on the
 * first construct one of them learns to handle.
 *
 * <p><b>And the screen must not be handed Markdown to render itself.</b> Doing that in a browser
 * means either a Markdown library writing into {@code innerHTML}, or hand-written HTML — and the
 * text is model prose derived from findings whose descriptions come from the audited repository
 * and from upstream rule authors. That is an injection path with three authors and no owner.
 * Blocks carry no markup: the client places text into elements it chose, and there is nothing to
 * sanitise because nothing is interpreted.
 *
 * <p>What is recognised is what {@link OwaspReview#PROMPT} asks for. <b>Anything else becomes a
 * paragraph rather than disappearing</b> — a construct that vanishes is a report quietly missing
 * a sentence.
 */
public final class OwaspMarkdown {

    private OwaspMarkdown() {}

    private static final Pattern HEADING = Pattern.compile("^(#{1,4})\\s+(.*)$");
    private static final Pattern BULLET = Pattern.compile("^\\s*[-*+]\\s+(.*)$");
    private static final Pattern NUMBERED = Pattern.compile("^\\s*(\\d+)[.)]\\s+(.*)$");

    /** What a block is. Deliberately few: this is a report, not a document format. */
    public enum Kind {
        HEADING,
        /** A heading naming one of the Top 10 — what a reader scans the document for. */
        CATEGORY,
        PARAGRAPH,
        BULLET,
        NUMBERED
    }

    /**
     * @param level 1 to 4 for a heading, 0 otherwise
     * @param marker the number of a numbered item, absent elsewhere
     */
    public record Block(Kind kind, int level, String marker, String text) {}

    public static List<Block> parse(String markdown) {
        if (markdown == null || markdown.isBlank()) {
            return List.of();
        }

        List<Block> blocks = new ArrayList<>();
        StringBuilder paragraph = new StringBuilder();

        for (String raw : markdown.split("\n", -1)) {
            String line = raw.stripTrailing();

            if (line.isBlank()) {
                flush(blocks, paragraph);
                continue;
            }

            Matcher heading = HEADING.matcher(line.strip());
            if (heading.matches()) {
                flush(blocks, paragraph);
                String text = strip(heading.group(2));
                blocks.add(new Block(
                        isCategory(text) ? Kind.CATEGORY : Kind.HEADING,
                        heading.group(1).length(),
                        null,
                        text));
                continue;
            }

            Matcher bullet = BULLET.matcher(line);
            if (bullet.matches()) {
                flush(blocks, paragraph);
                blocks.add(new Block(Kind.BULLET, 0, null, strip(bullet.group(1))));
                continue;
            }

            Matcher numbered = NUMBERED.matcher(line);
            if (numbered.matches()) {
                flush(blocks, paragraph);
                blocks.add(new Block(Kind.NUMBERED, 0, numbered.group(1), strip(numbered.group(2))));
                continue;
            }

            // **Consecutive lines are one paragraph, which is Markdown's own rule.** A model
            // hard-wraps its prose at seventy or ninety columns; treating each source line as a
            // paragraph reproduces those breaks in a wider column and leaves a third of the page
            // unused — visible immediately on the PDF, and just as wrong on screen.
            paragraph.append(paragraph.isEmpty() ? "" : " ").append(line.strip());
        }
        flush(blocks, paragraph);
        return List.copyOf(blocks);
    }

    private static void flush(List<Block> blocks, StringBuilder paragraph) {
        if (paragraph.isEmpty()) {
            return;
        }
        blocks.add(new Block(Kind.PARAGRAPH, 0, null, strip(paragraph.toString())));
        paragraph.setLength(0);
    }

    private static boolean isCategory(String heading) {
        String upper = heading.toUpperCase(Locale.ROOT);
        return OwaspReview.TOP_TEN.keySet().stream().anyMatch(upper::startsWith);
    }

    /**
     * Emphasis removed rather than carried.
     *
     * <p>Bold inside a wrapped paragraph means measuring and drawing runs of mixed fonts on one
     * side and nested elements on the other — a typesetter, for a few emphasised words. Leaving
     * the asterisks in is worse: they read as noise, and the reader learns to ignore the emphasis
     * they were meant to carry.
     */
    static String strip(String value) {
        return value.replaceAll("\\*\\*(.+?)\\*\\*", "$1")
                .replaceAll("(?<!\\*)\\*(?!\\*)(.+?)(?<!\\*)\\*(?!\\*)", "$1")
                .replaceAll("`([^`]+)`", "$1")
                .strip();
    }
}
