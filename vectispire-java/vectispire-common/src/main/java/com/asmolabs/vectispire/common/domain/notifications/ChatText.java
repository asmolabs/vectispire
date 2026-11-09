package com.asmolabs.vectispire.common.domain.notifications;

/**
 * A value made inert for the markup of the chat it is posted to.
 *
 * <p><b>Most of what a notification says was written by somebody else.</b> A package name comes from
 * the scanned repository's manifest, a file path from its tree, a rule identifier and a fix version
 * from a scanner's output. Interpolated as they are into Slack's {@code mrkdwn}, Discord's markdown
 * or an Adaptive Card, such a value is markup: {@code <!channel>} pings a whole Slack channel,
 * {@code <https://…|Open in Vectispire>} or {@code [Open in Vectispire](https://…)} is a link that
 * reads as the product's own, in the channel where a team waits for its alerts. Each chat has its own
 * rule, and each is applied to every value the message did not write itself.
 */
public final class ChatText {

    private ChatText() {}

    private static final char ZERO_WIDTH_SPACE = '\u200B';

    /**
     * Slack's own rule: {@code &}, {@code <} and {@code >} as entities, and nothing else.
     *
     * <p>Every control sequence of {@code mrkdwn} — a mention, a channel, a link, a date — opens with
     * {@code <}; the emphasis characters have no escape in Slack and only change how text looks.
     */
    public static String slack(String value) {
        if (value == null) {
            return null;
        }
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /**
     * Discord markdown escaped with backslashes, and the two mass mentions broken.
     *
     * <p>A masked link needs {@code [} and {@code (}, a mention {@code <@…>}; emphasis, spoilers,
     * headings, quotes and code are escaped too, so a value renders as the text it is. An embed does
     * not ping, and the payload also says so ({@code allowed_mentions}); {@code @everyone} and
     * {@code @here} are broken all the same, since a message quoted or forwarded elsewhere would.
     */
    public static String discord(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder escaped = new StringBuilder(value.length() + 8);
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if ("\\*_~`|>[]()#<".indexOf(c) >= 0) {
                escaped.append('\\');
            }
            escaped.append(c);
            if (c == '@') {
                escaped.append(ZERO_WIDTH_SPACE);
            }
        }
        return escaped.toString();
    }

    /**
     * An Adaptive Card text block's markdown, with its link and its templating broken.
     *
     * <p>Teams renders a subset of markdown and honours no backslash escape in it, so the sequences
     * that do harm are split with a zero-width space instead: {@code ](} — the middle of
     * {@code [text](url)} — and {@code {{}, which opens the card's date and time functions. What is
     * shown is the same text.
     */
    public static String teams(String value) {
        if (value == null) {
            return null;
        }
        return value.replace("](", "]" + ZERO_WIDTH_SPACE + "(").replace("{{", "{" + ZERO_WIDTH_SPACE + "{");
    }
}
