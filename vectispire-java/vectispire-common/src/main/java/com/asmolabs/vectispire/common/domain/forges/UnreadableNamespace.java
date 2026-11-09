package com.asmolabs.vectispire.common.domain.forges;

import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * A namespace a discovery could not read with the connection's token (decision 0037 §3): one organisation the
 * token is refused is not a reason to show nothing of the others, and not a reason to pretend it was empty either.
 * The run goes on, records it here, and marks none of its repositories gone.
 *
 * @param path the namespace as the forge names it — GitHub's organisation or user; {@code null} when the forge
 *     withheld namespaces without naming them (GitHub's single sign-on filtering a list, or refusing to list a
 *     token's organisations at all), in which case the run marks nothing gone outside what it read
 * @param reason why, in words an administrator can act on
 */
public record UnreadableNamespace(String path, String reason) {

    /** How many a run records; past it the rest are counted in the last one's place rather than stored. */
    public static final int MAX_RECORDED = 100;

    /** The longest reason kept: a sentence, not a document. */
    public static final int REASON_LENGTH = 500;

    public UnreadableNamespace {
        path = path == null || path.isBlank() ? null : flat(path);
        reason = BoundedText.clip(flat(reason == null ? "" : reason), REASON_LENGTH);
    }

    /**
     * The list as the discovery's column holds it: one per line, the path and the reason separated by a tab, an
     * unnamed namespace with an empty path. Neither a forge's namespace path nor a sentence written here holds a
     * tab or a line break once {@link #flat} has run, so the reading is unambiguous; no document format is needed
     * for two strings.
     */
    public static String encode(Collection<UnreadableNamespace> namespaces) {
        if (namespaces.isEmpty()) {
            return null;
        }
        List<UnreadableNamespace> kept = new ArrayList<>(namespaces);
        if (kept.size() > MAX_RECORDED) {
            int dropped = kept.size() - MAX_RECORDED + 1;
            kept = new ArrayList<>(kept.subList(0, MAX_RECORDED - 1));
            kept.add(new UnreadableNamespace(null, dropped + " more namespaces could not be read; their repositories "
                    + "are not marked gone either."));
        }
        StringBuilder text = new StringBuilder();
        for (UnreadableNamespace namespace : kept) {
            text.append(text.isEmpty() ? "" : "\n").append(namespace.path() == null ? "" : namespace.path()).append('\t')
                    .append(namespace.reason());
        }
        return text.toString();
    }

    /** The column read back; empty for a run that recorded none. */
    public static List<UnreadableNamespace> decode(String stored) {
        if (stored == null || stored.isBlank()) {
            return List.of();
        }
        List<UnreadableNamespace> namespaces = new ArrayList<>();
        for (String line : stored.split("\n")) {
            int tab = line.indexOf('\t');
            namespaces.add(tab < 0 ? new UnreadableNamespace(null, line)
                    : new UnreadableNamespace(line.substring(0, tab), line.substring(tab + 1)));
        }
        return List.copyOf(namespaces);
    }

    private static String flat(String value) {
        return value.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ').trim();
    }
}
