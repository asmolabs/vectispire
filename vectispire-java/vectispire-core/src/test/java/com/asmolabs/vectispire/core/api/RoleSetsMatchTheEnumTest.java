package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.users.Role;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The screen and the server name the same roles, or the screen offers what the server refuses.
 *
 * <p><b>The defect this test closes.</b> {@link Role} carries the flags and the front end keeps a
 * copy of them, by hand, in {@code session.store.ts}. The copy drifted: {@code SUPERUSER} appeared
 * there among the roles that can act and among those whose triage settles, although the enum has
 * refused it both since governing was separated from acting. The bootstrap account therefore saw
 * the "Triage" button, opened the dialog, filled it in, and collected a 403 on save — exactly the
 * broken screen the role guards existed to remove.
 *
 * <p><b>The defect went unseen for four days</b>, because nothing compared the two lists: the
 * front-end specs checked the front end's consistency with itself, and the Java tests the server's
 * with itself. Each was right, separately.
 *
 * <p><b>Why here and not in a front-end spec.</b> The enum is authoritative, and it is here. A test
 * on the front-end side would have to copy the flags in order to compare them — a third copy to
 * maintain, and the same defect one step further along.
 */
@DisplayName("the screen's role sets")
class RoleSetsMatchTheEnumTest {

    /**
     * The front end's session store.
     *
     * <p>Declared as an input of the `test` task in `build.gradle.kts`: without that Gradle
     * considers the task up to date when only this file changes, and replays a stale success — the
     * lesson of `ShippedRealmTest`, learnt by breaking the file and watching the green hold.
     */
    private static final Path STORE =
            Path.of("../../vectispire-angular/src/app/core/session.store.ts");

    @Test
    @DisplayName("name exactly the roles the enum designates")
    void theyMatch() throws IOException {
        assertThat(STORE).as("the session store must be readable from here").isReadable();
        String source = Files.readString(STORE);

        assertSet(source, "ADMIN_ROLES", Role::isAdministrative);
        assertSet(source, "SECURITY_LEAD_ROLES", Role::canWriteGovernance);
        assertSet(source, "TRIAGE_APPROVER_ROLES", Role::canApproveTriage);
        assertSet(source, "EFFECT_CAUSING_ROLES", Role::canCauseEffects);
        assertSet(source, "PLATFORM_GOVERNOR_ROLES", Role::governsPlatform);
    }

    private static void assertSet(String source, String constant, Predicate<Role> flag) {
        List<String> expected = Arrays.stream(Role.values())
                .filter(flag)
                .map(Enum::name)
                .sorted()
                .toList();

        assertThat(declared(source, constant))
                .as("%s must name the same roles as the matching flag on Role", constant)
                .containsExactlyElementsOf(expected);
    }

    /** A constant's literal role names, in alphabetical order so they can be compared. */
    private static List<String> declared(String source, String constant) {
        Matcher declaration = Pattern
                .compile("export const " + constant + "\\s*:[^=]+=\\s*\\[([^\\]]*)\\]")
                .matcher(source);
        assertThat(declaration.find())
                .as("%s must be declared in the session store", constant)
                .isTrue();

        Matcher names = Pattern.compile("'([A-Z_]+)'").matcher(declaration.group(1));
        return names.results().map(result -> result.group(1)).sorted().collect(Collectors.toList());
    }
}
