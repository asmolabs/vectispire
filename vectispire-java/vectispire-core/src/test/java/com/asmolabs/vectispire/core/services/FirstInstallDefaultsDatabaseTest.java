package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.access.VisibilityMode;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.core.ZanshinContextTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The safe defaults of a fresh installation, through the real bean graph and a real database.
 *
 * <p><b>Why this exists beside the two unit suites.</b> {@code FirstInstallDefaultsTest} proves
 * the decision and {@code BootstrapServiceTest} proves the call, both against mocks. Neither can
 * see the two things that only a wired application has: that the value reaches {@code t_setting}
 * as a row rather than being written to a service nobody persisted, and that the read path —
 * {@link VisibilityService}, which is what actually decides what an account sees — answers with
 * the mode that was seeded. Those are one assignment apart from a system that logs the right
 * sentence and partitions nothing.
 */
@DisplayName("a fresh installation, wired")
class FirstInstallDefaultsDatabaseTest extends ZanshinContextTest {

    @Autowired
    private BootstrapService bootstrap;

    @Autowired
    private SettingsService settings;

    @Autowired
    private VisibilityService visibility;

    @Test
    @DisplayName("an empty database ends up partitioned, and the read path agrees")
    void seedsAndIsRead() {
        // The base class empties every table before each test, which is exactly the state
        // `createFirstUser` recognises as a new install.
        bootstrap.createFirstUser();

        assertThat(settings.isStored(Setting.TARGET_VISIBILITY)).isTrue();
        assertThat(settings.get(Setting.TARGET_VISIBILITY)).isEqualTo(VisibilityMode.ASSIGNED.wireName());
        // The assertion that matters: not that a row exists, but that the class deciding
        // visibility reads it. A row spelled in a way `VisibilityMode` did not recognise would
        // still answer ASSIGNED — safely, and while hiding the typo from every other reader.
        assertThat(visibility.mode()).isEqualTo(VisibilityMode.ASSIGNED);
    }

    @Test
    @DisplayName("a deployment that chose 'everyone' keeps it across a restart")
    void doesNotUndoAnOperatorsChoice() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());

        // Same conditions as above — no account exists — so this is the restart of an install
        // whose bootstrap credentials were never set. Re-seeding here would silently revert a
        // decision somebody made on the settings screen.
        bootstrap.createFirstUser();

        assertThat(visibility.mode()).isEqualTo(VisibilityMode.EVERYONE);
    }
}
