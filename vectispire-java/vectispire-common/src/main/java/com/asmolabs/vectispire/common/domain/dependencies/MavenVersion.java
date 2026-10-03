package com.asmolabs.vectispire.common.domain.dependencies;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * A Maven version, ordered as Maven orders it — the order of {@code ComparableVersion} in {@code
 * maven-artifact} 3.9, written here rather than depended on: {@code common.domain} depends on the JDK,
 * BouncyCastle and Jackson alone, and pulling Maven's artifact model onto the classpath of every module
 * for one comparator would be the larger change.
 *
 * <p><b>Why not {@link Versions}.</b> That order is a remediation advisor's, which errs high on purpose
 * — {@code 1.0.0-alpha} after {@code 1.0.0}, so a suggestion is never one notch too low. A checklist
 * range judges a line: {@code [1.0,2.0)} admitting {@code 1.0-SNAPSHOT} or {@code 2.0-RC1} wrongly would
 * pass a line on a build nobody released. Maven's order is the one the people binding a Maven range
 * read it with, so it is the one applied, qualifiers included:
 *
 * <ul>
 *   <li>the version is lower-cased, then split on {@code .} and {@code -}, and where digits and letters
 *       meet ({@code 1.0alpha1} is {@code 1, 0, alpha, 1}); a {@code -}, a digit-letter transition and a
 *       qualifier after a {@code .} each open a sub-list, so {@code 1-1} is after every {@code 1.x} with a
 *       qualifier and before {@code 1.1};
 *   <li>the known qualifiers order {@code alpha < beta < milestone < rc = cr < snapshot < "" = ga = final
 *       = release < sp}; {@code a}, {@code b} and {@code m} directly followed by a digit are {@code alpha},
 *       {@code beta}, {@code milestone}; an unknown qualifier sorts after them all, alphabetically;
 *   <li>a number is after any qualifier at the same place ({@code 1.1 > 1.sp}), and a sub-list after a
 *       qualifier, before a number;
 *   <li>trailing zeros and release qualifiers are dropped: {@code 1}, {@code 1.0}, {@code 1.0.0}, {@code
 *       1-0}, {@code 1.ga}, {@code 1.0.RELEASE} and {@code 1-final} are one version.
 * </ul>
 */
public final class MavenVersion implements Comparable<MavenVersion> {

    private final String written;
    private final ListItem items;

    private MavenVersion(String written, ListItem items) {
        this.written = written;
        this.items = items;
    }

    public static MavenVersion of(String version) {
        Objects.requireNonNull(version, "version");
        return new MavenVersion(version, parse(version.strip()));
    }

    @Override
    public int compareTo(MavenVersion other) {
        return items.compareTo(other.items);
    }

    @Override
    public String toString() {
        return written;
    }

    /** The parsed form, for a test to read which items a version became. */
    String canonical() {
        return items.toString();
    }

    // ------------------------------------------------------------------ parsing

    private static ListItem parse(String version) {
        String lower = version.toLowerCase(Locale.ROOT);
        ListItem root = new ListItem();
        ListItem list = root;
        Deque<ListItem> stack = new ArrayDeque<>();
        stack.push(list);
        boolean digit = false;
        int start = 0;
        for (int index = 0; index < lower.length(); index++) {
            char c = lower.charAt(index);
            if (c == '.') {
                list.add(index == start ? IntItem.ZERO : item(digit, lower.substring(start, index)));
                start = index + 1;
            } else if (c == '-') {
                list.add(index == start ? IntItem.ZERO : item(digit, lower.substring(start, index)));
                start = index + 1;
                ListItem sub = new ListItem();
                list.add(sub);
                list = sub;
                stack.push(list);
            } else if (Character.isDigit(c)) {
                if (!digit && index > start) {
                    // The same for a qualifier a digit follows: 1.0.0.M1 is 1-milestone-1, not 1.0.0.milestone-1.
                    if (!list.isEmpty()) {
                        ListItem sub = new ListItem();
                        list.add(sub);
                        list = sub;
                        stack.push(list);
                    }
                    list.add(new StringItem(lower.substring(start, index), true));
                    start = index;
                    ListItem sub = new ListItem();
                    list.add(sub);
                    list = sub;
                    stack.push(list);
                }
                digit = true;
            } else {
                if (digit && index > start) {
                    list.add(item(true, lower.substring(start, index)));
                    start = index;
                    ListItem sub = new ListItem();
                    list.add(sub);
                    list = sub;
                    stack.push(list);
                }
                digit = false;
            }
        }
        if (lower.length() > start) {
            // A qualifier after a dot reads as after a dash: 1.0.0.X1 < 1.0.0-X2.
            if (!digit && !list.isEmpty()) {
                ListItem sub = new ListItem();
                list.add(sub);
                list = sub;
                stack.push(list);
            }
            list.add(item(digit, lower.substring(start)));
        }
        while (!stack.isEmpty()) {
            stack.pop().normalize();
        }
        return root;
    }

    private static Item item(boolean digit, String text) {
        return digit ? new IntItem(new BigInteger(text)) : new StringItem(text, false);
    }

    // ------------------------------------------------------------------ the items

    private sealed interface Item permits IntItem, StringItem, ListItem {

        /** Compared with an absent item: what a shorter version has where this one goes on. */
        int compareTo(Item other);

        boolean isNull();
    }

    private record IntItem(BigInteger value) implements Item {

        static final IntItem ZERO = new IntItem(BigInteger.ZERO);

        @Override
        public boolean isNull() {
            return value.signum() == 0;
        }

        @Override
        public int compareTo(Item other) {
            return switch (other) {
                case null -> isNull() ? 0 : 1;
                case IntItem number -> value.compareTo(number.value);
                case StringItem ignored -> 1;
                case ListItem ignored -> 1;
            };
        }

        @Override
        public String toString() {
            return value.toString();
        }
    }

    private record StringItem(String value) implements Item {

        private static final List<String> QUALIFIERS = List.of("alpha", "beta", "milestone", "rc", "snapshot", "", "sp");
        private static final String RELEASE = String.valueOf(QUALIFIERS.indexOf(""));

        StringItem(String value, boolean followedByDigit) {
            this(alias(followedByDigit && value.length() == 1 ? shorthand(value) : value));
        }

        private static String shorthand(String value) {
            return switch (value.charAt(0)) {
                case 'a' -> "alpha";
                case 'b' -> "beta";
                case 'm' -> "milestone";
                default -> value;
            };
        }

        private static String alias(String value) {
            return switch (value) {
                case "ga", "final", "release" -> "";
                case "cr" -> "rc";
                default -> value;
            };
        }

        /**
         * The qualifier's rank as a string: the known ones are their index, one digit; an unknown one is
         * {@code "7-"} and its name, after every known one and ordered alphabetically among its kind.
         */
        private static String comparable(String qualifier) {
            int index = QUALIFIERS.indexOf(qualifier);
            return index == -1 ? QUALIFIERS.size() + "-" + qualifier : String.valueOf(index);
        }

        @Override
        public boolean isNull() {
            return comparable(value).equals(RELEASE);
        }

        @Override
        public int compareTo(Item other) {
            return switch (other) {
                case null -> comparable(value).compareTo(RELEASE);
                case IntItem ignored -> -1;
                case StringItem text -> comparable(value).compareTo(comparable(text.value));
                case ListItem ignored -> -1;
            };
        }

        @Override
        public String toString() {
            return value;
        }
    }

    private static final class ListItem implements Item {

        private final List<Item> items = new ArrayList<>();

        void add(Item item) {
            items.add(item);
        }

        boolean isEmpty() {
            return items.isEmpty();
        }

        /** Trailing zeros and release qualifiers dropped, up to the first item that is neither nor a list. */
        void normalize() {
            for (int index = items.size() - 1; index >= 0; index--) {
                Item last = items.get(index);
                if (last.isNull()) {
                    items.remove(index);
                } else if (!(last instanceof ListItem)) {
                    break;
                }
            }
        }

        @Override
        public boolean isNull() {
            return items.isEmpty();
        }

        @Override
        public int compareTo(Item other) {
            return switch (other) {
                case null -> {
                    // Every item against absence, not the first alone (MNG-6964): 1-0.1 is after 1.
                    for (Item item : items) {
                        int result = item.compareTo(null);
                        if (result != 0) {
                            yield result;
                        }
                    }
                    yield 0;
                }
                case IntItem ignored -> -1;
                case StringItem ignored -> 1;
                case ListItem list -> {
                    Iterator<Item> left = items.iterator();
                    Iterator<Item> right = list.items.iterator();
                    while (left.hasNext() || right.hasNext()) {
                        Item l = left.hasNext() ? left.next() : null;
                        Item r = right.hasNext() ? right.next() : null;
                        int result = l == null ? (r == null ? 0 : -r.compareTo(null)) : l.compareTo(r);
                        if (result != 0) {
                            yield result;
                        }
                    }
                    yield 0;
                }
            };
        }

        @Override
        public String toString() {
            StringBuilder written = new StringBuilder();
            for (Item item : items) {
                if (!written.isEmpty()) {
                    written.append(item instanceof ListItem ? '-' : '.');
                }
                written.append(item);
            }
            return written.toString();
        }
    }
}
