package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.SettingEntity;
import com.asmolabs.vectispire.core.repositories.Settings;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("reading a setting, present or not")
class SettingsServiceTest {

    private Settings rows;
    private SettingsService service;

    @BeforeEach
    void wire() {
        rows = mock(Settings.class);
        service = new SettingsService(rows);
        when(rows.findById(anyString())).thenReturn(Optional.empty());
    }

    @Test
    @DisplayName("an absent row reads as the catalog's default, not as empty")
    void absentRowFallsBackToTheCatalog() {
        // The whole point of holding the default in the catalog: a reader cannot supply the
        // wrong one, because it does not supply one at all.
        assertThat(service.get(Setting.SAST_ENABLED)).isEqualTo(Setting.SAST_ENABLED.defaultValue());
        assertThat(service.isEnabled(Setting.SAST_ENABLED)).isFalse();
    }

    @Test
    @DisplayName("a deliberately cleared value stays cleared")
    void anEmptyStoredValueIsNotReplacedByTheDefault() {
        stored(Setting.WEBHOOK_URL, "");

        assertThat(service.get(Setting.WEBHOOK_URL)).isEmpty();
    }

    @Test
    @DisplayName("only the exact string \"true\" enables")
    void anythingElseIsFalse() {
        stored(Setting.SAST_ENABLED, "true");
        assertThat(service.isEnabled(Setting.SAST_ENABLED)).isTrue();

        stored(Setting.SAST_ENABLED, "TRUE");
        assertThat(service.isEnabled(Setting.SAST_ENABLED)).isFalse();

        stored(Setting.SAST_ENABLED, "1");
        assertThat(service.isEnabled(Setting.SAST_ENABLED)).isFalse();
    }

    @Test
    @DisplayName("an unparseable number reads as the default rather than taking the screen down")
    void asIntSurvivesAMalformedRow() {
        stored(Setting.RETENTION_KEEP_PER_TARGET, "not a number");

        assertThat(service.asInt(Setting.RETENTION_KEEP_PER_TARGET))
                .isEqualTo(Integer.parseInt(Setting.RETENTION_KEEP_PER_TARGET.defaultValue()));
    }

    @Test
    @DisplayName("effective values are the defaults overlaid with what is stored")
    void effectiveCoversTheWholeCatalog() {
        when(rows.findAll()).thenReturn(List.of(row(Setting.SAST_ENABLED, "true")));

        assertThat(service.effective())
                .containsEntry(Setting.SAST_ENABLED.key(), "true")
                .containsKeys(Setting.RETENTION_KEEP_PER_TARGET.key())
                .hasSameSizeAs(Setting.defaults());
        // `stored` says what is on disk; the two answers must not be conflated by a caller
        // deciding whether an operator has ever touched a setting.
        assertThat(service.stored()).containsOnlyKeys(Setting.SAST_ENABLED.key());
    }

    @Test
    @DisplayName("writing updates in place when the row exists")
    void setUpdatesRatherThanInserting() {
        when(rows.updateValue(eq(Setting.SAST_ENABLED.key()), anyString())).thenReturn(1);

        service.set(Setting.SAST_ENABLED, "true");

        verify(rows, never()).save(any());
    }

    @Test
    @DisplayName("writing inserts when nothing was updated")
    void setInsertsWhenTheKeyIsNew() {
        when(rows.updateValue(anyString(), anyString())).thenReturn(0);

        service.set(Setting.SAST_ENABLED, "true");

        verify(rows).save(any(SettingEntity.class));
    }

    private void stored(Setting setting, String value) {
        when(rows.findById(setting.key())).thenReturn(Optional.of(row(setting, value)));
    }

    private static SettingEntity row(Setting setting, String value) {
        SettingEntity row = new SettingEntity();
        row.setKey(setting.key());
        row.setValue(value);
        return row;
    }
}
