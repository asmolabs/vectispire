package com.asmolabs.zanshin.common.domain.issues;

import java.util.Arrays;
import java.util.Optional;

/**
 * The finding types, and the partition between what blocks a build and what does not.
 *
 * <p><b>{@code QUALITY} never fails a build, and never enters a security counter.</b> That is
 * not a setting: a flag would make this sentence a lie the moment somebody unticked it. On the
 * day SAST goes live an ordinary repository goes from a few dozen vulnerabilities to a few
 * thousand quality findings, and a counter that mixes them turns that number into noise nobody
 * looks at again.
 *
 * <p>An enum rather than the original's seven string constants plus a hand-maintained
 * {@code SECURITY_TYPES} list. The two could disagree — a new constant added to one and not
 * the other would appear in a counter it was meant to be excluded from, and nothing would
 * fail. Here the property travels with the value.
 */
public enum FindingType {
    VULNERABILITY("vulnerability", true),
    SECRET("secret", true),
    IAC("iac", true),
    LICENSE("license", true),
    EOL("eol", true),
    SAST("sast", true),
    QUALITY("quality", false);

    private final String wireName;
    private final boolean security;

    FindingType(String wireName, boolean security) {
        this.wireName = wireName;
        this.security = security;
    }

    /**
     * The form stored in the database and sent over the API.
     *
     * <p>Held separately from {@link #name()} so that renaming a constant is a refactor and not
     * a data migration.
     */
    public String wireName() {
        return wireName;
    }

    /** Whether the type counts towards a security posture, and may therefore fail a gate. */
    public boolean isSecurity() {
        return security;
    }

    public static Optional<FindingType> fromWireName(String value) {
        return Arrays.stream(values()).filter(type -> type.wireName.equals(value)).findFirst();
    }
}
