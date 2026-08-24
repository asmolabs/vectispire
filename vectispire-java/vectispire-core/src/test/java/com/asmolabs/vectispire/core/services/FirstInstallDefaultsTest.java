package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("what a fresh installation starts with")
class FirstInstallDefaultsTest {

    @Test
    @DisplayName("a new database is partitioned, where the catalog's compatible default is not")
    void seedsRestrictedVisibility() {
        SettingsService settings = mock(SettingsService.class);
        when(settings.isStored(any())).thenReturn(false);

        new FirstInstallDefaults(settings).apply();

        verify(settings).set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
    }

    @Test
    @DisplayName("the value written is one the read path understands, not a spelling of its own")
    void writesAValueVisibilityModeParses() {
        SettingsService settings = mock(SettingsService.class);
        when(settings.isStored(any())).thenReturn(false);

        new FirstInstallDefaults(settings).apply();

        // The stricter reading in `VisibilityMode.of` would turn a typo here into ASSIGNED too,
        // which is safe and would hide the typo — so the value is checked against the parser
        // rather than against itself.
        verify(settings).set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        assertThat(VisibilityMode.byWireName(VisibilityMode.ASSIGNED.wireName()))
                .contains(VisibilityMode.ASSIGNED);
    }

    @Test
    @DisplayName("an existing row is a decision, and is left alone")
    void neverOverwritesAStoredValue() {
        SettingsService settings = mock(SettingsService.class);
        when(settings.isStored(any())).thenReturn(true);

        new FirstInstallDefaults(settings).apply();

        // An operator who chose `everyone` before creating their first account keeps it, and a
        // restart does not undo the choice.
        verify(settings, never()).set(any(), anyString());
    }
}
