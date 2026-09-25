package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import java.util.Optional;
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
 * A setting as long as the service allows, written to a real engine.
 *
 * <p><b>Only a real engine can say this.</b> {@code t_setting.value} was {@code varchar(255)} and
 * every credential stored in it is encrypted, so an Atlassian token of 192 characters became a
 * ciphertext of about 300 and MySQL and PostgreSQL refused the row: a 500 on the settings screen.
 * SQLite, which the HTTP suite runs on, does not enforce a varchar length, and saw nothing. V38 made
 * the column {@code text}; this writes both kinds of value at their ceilings and reads them back.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("a long setting on a real engine")
class LongSettingIntegrationTest {

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
        // A credential is only ever stored encrypted, so the campaign needs a key to store one.
        registry.add("vectispire.encryption.key", () -> "vectispire-campaign-encryption-passphrase");
    }

    @Autowired
    private TicketService tickets;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("a 200-character tracker token is stored encrypted and decrypts to itself")
    void aRealTrackerToken() {
        String token = "T".repeat(200);

        tickets.setToken(token);

        assertThat(tickets.token()).isEqualTo(token);
    }

    @Test
    @DisplayName("a credential at the service's ceiling fits once encrypted")
    void theLongestSecretFits() {
        String secret = "S".repeat(SettingsAdministrationService.MAX_SECRET_LENGTH);

        tickets.setWebhookSecret(secret);

        assertThat(tickets.webhookSecret())
                .isEqualTo(new TicketService.WebhookSecret.Present(secret));
    }

    @Test
    @DisplayName("free text at the ceiling fits, three-byte characters included")
    void theLongestTextFits() {
        // U+20AC is three bytes in UTF-8: the worst case a MySQL `text` has to hold per unit.
        String text = "€".repeat(BoundedText.TEXT_MAX);

        settings.set(Setting.ISMS_SCOPE_STATEMENT, text);

        assertThat(settings.get(Setting.ISMS_SCOPE_STATEMENT)).isEqualTo(text);
    }
}
