package com.asmolabs.vectispire.common.domain.forges;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * The forges a connection may name (decision 0037 §1). Bitbucket is lot D8's, and a value it would
 * add is refused until then rather than stored for an adapter that does not exist.
 */
public enum ForgeKind {
    GITHUB("github"),
    GITLAB("gitlab");

    private final String wireName;

    ForgeKind(String wireName) {
        this.wireName = wireName;
    }

    public String wireName() {
        return wireName;
    }

    /**
     * Read from a request or a row, refused in words — {@code valueOf}'s "No enum constant" is a 500.
     *
     * @throws InvalidInputException naming the kinds accepted
     */
    public static ForgeKind parse(String value) {
        String wanted = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values())
                .filter(kind -> kind.wireName.equals(wanted))
                .findFirst()
                .orElseThrow(() -> new InvalidInputException("The forge must be one of "
                        + Arrays.stream(values()).map(ForgeKind::wireName).collect(Collectors.joining(", "))
                        + "."));
    }
}
