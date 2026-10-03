package com.asmolabs.vectispire.common.domain.reportplugins;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Optional;

/**
 * How large a project export may be — and the rule that one larger is <b>refused, never truncated</b>
 * (decision 0035 §1). A truncated export would be signed, and rendered into a document that looks
 * complete: the lie decision 0007 exists to refuse.
 *
 * @param maxJsonBytes the largest export, as the JSON written
 * @param maxIssues the most issues one may list
 * @param maxComponents the most components its inventory may list
 */
public record ProjectExportBounds(long maxJsonBytes, int maxIssues, int maxComponents) {

    /** 64 MiB of JSON, 100,000 issues, 100,000 components. */
    public static final ProjectExportBounds STANDARD = new ProjectExportBounds(64L * 1024 * 1024, 100_000, 100_000);

    public ProjectExportBounds {
        if (maxJsonBytes < 1 || maxIssues < 0 || maxComponents < 0) {
            throw new IllegalArgumentException("A bound is positive.");
        }
    }

    /**
     * Which bound an export exceeds.
     *
     * @param part what exceeded it: {@code issues} or {@code inventory.components}, as the schema names
     *     the parts, or {@link #JSON_BYTES} for the document's size
     * @param found how many there were — for the size, how far the write had got when it crossed the
     *     bound, since it stops there
     */
    public record Exceeded(String part, long found, long limit) {

        public static final String JSON_BYTES = "json_bytes";

        /** The sentence a refusal states: the figure that exceeded, and the bound. */
        public String sentence() {
            String what = JSON_BYTES.equals(part)
                    ? "its JSON passed " + limit + " bytes, the most"
                    : "its " + part + " would hold " + found + ", above the " + limit;
            return "The project's export is not built: " + what + " an export may hold. An export is refused "
                    + "rather than cut short, since a document rendered from part of it would read as complete.";
        }
    }

    /** The issues' bound, asked before a single issue is read. */
    public Optional<Exceeded> issues(long count) {
        return count > maxIssues ? Optional.of(new Exceeded("issues", count, maxIssues)) : Optional.empty();
    }

    public Optional<Exceeded> components(long count) {
        return count > maxComponents
                ? Optional.of(new Exceeded("inventory.components", count, maxComponents))
                : Optional.empty();
    }

    /**
     * A buffer the JSON is written into, which stops the write past {@link #maxJsonBytes} by throwing
     * {@link TooLarge} — rather than holding an export of any size in memory to measure it afterwards.
     */
    public BoundedBuffer buffer() {
        return new BoundedBuffer(maxJsonBytes);
    }

    /** Thrown by a {@link BoundedBuffer} whose bound a write would cross. */
    public static final class TooLarge extends RuntimeException {

        private static final long serialVersionUID = 1L;

        private final transient Exceeded exceeded;

        TooLarge(Exceeded exceeded) {
            super(exceeded.sentence());
            this.exceeded = exceeded;
        }

        public Exceeded exceeded() {
            return exceeded;
        }
    }

    /** An in-memory output that refuses to grow past its bound. */
    public static final class BoundedBuffer extends OutputStream {

        private final long limit;
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        BoundedBuffer(long limit) {
            this.limit = limit;
        }

        @Override
        public void write(int b) {
            reserve(1);
            bytes.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) {
            reserve(len);
            bytes.write(b, off, len);
        }

        private void reserve(int more) {
            long size = (long) bytes.size() + more;
            if (size > limit) {
                throw new TooLarge(new Exceeded(Exceeded.JSON_BYTES, size, limit));
            }
        }

        public byte[] toByteArray() {
            return bytes.toByteArray();
        }
    }
}
