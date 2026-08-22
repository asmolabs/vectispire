package com.asmolabs.zanshin.common.domain.aireview;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.aireview.OwaspMarkdown.Block;
import com.asmolabs.zanshin.common.domain.aireview.OwaspMarkdown.Kind;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The report's Markdown, read once for both renderers.
 *
 * <p>Parsed on the server so the PDF and the screen cannot disagree about what a heading is, and
 * so the browser is handed text rather than markup to interpret.
 */
@DisplayName("reading the model's Markdown")
class OwaspMarkdownTest {

    @Test
    @DisplayName("a Top 10 heading is a category, an ordinary one is not")
    void categoriesAreRecognised() {
        // The unit a reader scans for. Both renderers give it a band, and neither decides that
        // for itself.
        List<Block> blocks = OwaspMarkdown.parse("## A03 — Injection\n\n## Executive summary");

        assertThat(blocks).extracting(Block::kind).containsExactly(Kind.CATEGORY, Kind.HEADING);
    }

    @Test
    @DisplayName("hard-wrapped prose becomes one paragraph, not one per line")
    void linesJoinIntoParagraphs() {
        // A model wraps at seventy or ninety columns. Treated as one paragraph per line, the PDF
        // reproduced those breaks in a wider column and used two thirds of the page — visible on
        // the rendered document, and just as wrong on screen.
        List<Block> blocks = OwaspMarkdown.parse("The dependency backlog\ndominates this report.\n\nA second one.");

        assertThat(blocks).hasSize(2);
        assertThat(blocks.getFirst().text()).isEqualTo("The dependency backlog dominates this report.");
    }

    @Test
    @DisplayName("bullets and numbered items keep their marker apart from their text")
    void listsAreStructured() {
        List<Block> blocks = OwaspMarkdown.parse("- Bump openssl\n1. Triage the backlog");

        assertThat(blocks.get(0)).isEqualTo(new Block(Kind.BULLET, 0, null, "Bump openssl"));
        assertThat(blocks.get(1)).isEqualTo(new Block(Kind.NUMBERED, 0, "1", "Triage the backlog"));
    }

    @Test
    @DisplayName("emphasis is removed, and the words it emphasised are kept")
    void emphasisIsStripped() {
        assertThat(OwaspMarkdown.parse("The **openssl** and `jackson` and *old* libraries.").getFirst().text())
                .isEqualTo("The openssl and jackson and old libraries.");
    }

    @Test
    @DisplayName("blockquotes and markdown tables are structured into dedicated blocks")
    void quotesAndTablesAreStructured() {
        List<Block> blocks = OwaspMarkdown.parse(
                "> Important caveat: Silence is not safety.\n\n| Category | Why |\n|---|---|\n| A01 | No scanner |");

        assertThat(blocks).hasSize(2);
        assertThat(blocks.get(0).kind()).isEqualTo(Kind.BLOCKQUOTE);
        assertThat(blocks.get(0).text()).isEqualTo("Important caveat: Silence is not safety.");

        assertThat(blocks.get(1).kind()).isEqualTo(Kind.TABLE);
        assertThat(blocks.get(1).headers()).containsExactly("Category", "Why");
        assertThat(blocks.get(1).rows()).containsExactly(List.of("A01", "No scanner"));
    }

    @Test
    @DisplayName("no block carries markup, because the browser places text and interprets nothing")
    void blocksCarryTextOnly() {
        // The reason the server parses this at all. The prose is model output derived from
        // findings written by the audited repository; handed to a browser as HTML it would be an
        // injection path with three authors and no owner.
        List<Block> blocks = OwaspMarkdown.parse("## A03\n\nSee <script>alert(1)</script> in the report.");

        assertThat(blocks.get(1).text())
                .describedAs("kept verbatim as text — it is displayed, never interpreted")
                .isEqualTo("See <script>alert(1)</script> in the report.");
    }

    @Test
    @DisplayName("nothing in, nothing out")
    void emptyIsEmpty() {
        assertThat(OwaspMarkdown.parse(null)).isEmpty();
        assertThat(OwaspMarkdown.parse("   ")).isEmpty();
    }
}
