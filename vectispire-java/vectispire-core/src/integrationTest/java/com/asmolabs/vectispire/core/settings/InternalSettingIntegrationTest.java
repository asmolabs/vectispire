package com.asmolabs.vectispire.core.settings;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * An internal row stored if absent, on a real engine.
 *
 * <p>The insert names the {@code key} column, a reserved word on MySQL that each engine quotes its
 * own way, and the refusal of a second insert is the engine's primary key — so both the statement
 * and the arbitration are the engine's to prove. The document signing key depends on it: of two
 * instances starting together, the second must be refused rather than overwrite the first.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("an internal setting stored if absent, on a real engine")
class InternalSettingIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    @BeforeAll
    static void start() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::start);
    }

    @AfterAll
    static void stop() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::stop);
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("the first store wins, and the second neither overwrites nor throws")
    void theFirstStoreWins() {
        String key = "probe_internal_" + UUID.randomUUID();

        assertThat(settings.storeInternalIfAbsent(key, "first")).isTrue();
        assertThat(settings.storeInternalIfAbsent(key, "second")).isFalse();

        assertThat(settings.internalValue(key)).contains("first");
    }
}
