package com.asmolabs.vectispire.common.domain.eol;

import java.util.ArrayList;
import java.util.List;

/**
 * A version's numeric components, for comparing a version to a release cycle.
 *
 * <p>{@code "9.7 (Plow)"} becomes {@code [9, 7]} and {@code "3.12.1-rc1"} becomes
 * {@code [3, 12, 1]}: neither a distribution's decorated version nor a package's build suffix
 * must stop the cycle from being recognized.
 */
record Version(List<Integer> parts) {

    static Version parse(String version) {
        String cleaned = version == null ? "" : version.trim().split(" ")[0];
        List<Integer> parts = new ArrayList<>();

        for (String chunk : cleaned.split("\\.")) {
            int digits = 0;
            while (digits < chunk.length() && Character.isDigit(chunk.charAt(digits))) {
                digits++;
            }
            if (digits == 0) {
                // Stop rather than skip: after a non-numeric chunk the remaining numbers no
                // longer line up positionally with the cycle's, and comparing them would match
                // the wrong one.
                break;
            }
            parts.add(Integer.parseInt(chunk.substring(0, digits)));
        }
        return new Version(List.copyOf(parts));
    }

    /**
     * Whether this version names a cycle {@code other} belongs to.
     *
     * <p><b>Component by component, never by string prefix.</b> "3.14" starts with "3.1", so a
     * prefix test files Python 3.14 under the 3.1 cycle and announces a support window that
     * closed years ago.
     */
    boolean isCycleOf(Version other) {
        if (parts.isEmpty() || parts.size() > other.parts().size()) {
            return false;
        }
        for (int i = 0; i < parts.size(); i++) {
            if (!parts.get(i).equals(other.parts().get(i))) {
                return false;
            }
        }
        return true;
    }

    int length() {
        return parts.size();
    }
}
