package com.asmolabs.vectispire.common.scanning;

/**
 * A ceiling on the work regular expressions may spend on one file of the repository under analysis.
 *
 * <p><b>The file is the author's, and so is the time a pattern spends on it.</b> The patterns that
 * read source files in this process have been rewritten twice after one of them turned out to
 * backtrack super-linearly — a class header search that took 36 minutes on a megabyte of spaces,
 * then a NestJS prefix search whose three overlapping quantifiers took two seconds on 2,000
 * whitespace characters and grew with the cube. Each was found by reading; the next one may not be,
 * and a worker thread spinning on one file holds a scan slot, a CPU and, in the built-in worker, the
 * control plane's own process.
 *
 * <p>So every character a pattern reads is counted, through the {@link CharSequence} the matcher is
 * handed, against a budget proportional to the file's length. A linear pattern reads each character
 * a handful of times; {@value #READS_PER_CHARACTER} reads per character over every pattern applied
 * to the file is an order of magnitude above what the discovery's patterns use on real controllers
 * (fewer than six per character in every source file of this repository's own control plane), and
 * orders of magnitude below what a backtracking one needs to be noticed. Characters rather than
 * time, deliberately: a character count gives the same answer on a loaded CI runner as on a laptop,
 * where a time limit would make the outcome of a scan a property of the host's load.
 *
 * <p>Exhausting the budget throws {@link Exhausted}; the caller skips the file, as it skips any file
 * it cannot read. Not thread-safe: one budget belongs to one file on one thread.
 */
public final class AnalysisBudget {

    /** Reads allowed per character of the file, across every pattern applied to it. */
    public static final long READS_PER_CHARACTER = 64;

    /** So that a small file is not refused over the fixed cost of a few patterns. */
    static final long FLOOR = 1_000_000;

    private final long limit;
    private long spent;

    private AnalysisBudget(long limit) {
        this.limit = limit;
    }

    /** A budget for the patterns applied to a file of this content. */
    public static AnalysisBudget forContent(CharSequence content) {
        return new AnalysisBudget(FLOOR + READS_PER_CHARACTER * content.length());
    }

    /** A budget of exactly this many reads, for the tests that exhaust one. */
    static AnalysisBudget ofReads(long reads) {
        return new AnalysisBudget(reads);
    }

    /** The text to hand the matcher: the same characters, each read counted against this budget. */
    public CharSequence guard(CharSequence text) {
        return new Guarded(text, 0, text.length());
    }

    long spent() {
        return spent;
    }

    private void spend() {
        if (++spent > limit) {
            throw new Exhausted(limit);
        }
    }

    /** The patterns read more of the file than any linear pattern would. */
    public static final class Exhausted extends RuntimeException {

        Exhausted(long limit) {
            super("the patterns read more than " + limit + " characters of one file and were stopped");
        }
    }

    private final class Guarded implements CharSequence {

        private final CharSequence text;
        private final int start;
        private final int end;

        Guarded(CharSequence text, int start, int end) {
            this.text = text;
            this.start = start;
            this.end = end;
        }

        @Override
        public int length() {
            return end - start;
        }

        @Override
        public char charAt(int index) {
            spend();
            return text.charAt(start + index);
        }

        @Override
        public CharSequence subSequence(int from, int to) {
            if (from < 0 || to > length() || from > to) {
                throw new IndexOutOfBoundsException("subSequence(" + from + ", " + to + ") of " + length());
            }
            return new Guarded(text, start + from, start + to);
        }

        /** What a matcher's {@code group()} returns: the characters themselves, uncounted. */
        @Override
        public String toString() {
            return text.subSequence(start, end).toString();
        }
    }
}
