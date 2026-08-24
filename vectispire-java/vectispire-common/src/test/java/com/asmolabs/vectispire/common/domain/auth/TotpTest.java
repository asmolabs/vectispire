package com.asmolabs.vectispire.common.domain.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Totp RFC 6238 generation and verification")
class TotpTest {

    @Test
    @DisplayName("generates valid base32 secret and standard QR URI")
    void secretAndUri() {
        String secret = Totp.generateSecret();
        assertThat(secret).matches("^[A-Z2-7]{32}$");

        String uri = Totp.qrCodeUri("alice", secret, "Vectispire");
        assertThat(uri).startsWith("otpauth://totp/Vectispire:alice?secret=" + secret);
    }

    @Test
    @DisplayName("verifies valid TOTP code within current and adjacent windows")
    void verifiesTotpCode() {
        String secret = Totp.generateSecret();
        Instant now = Instant.parse("2026-08-22T10:00:00Z");

        String codeNow = Totp.generateCode(secret, now);
        assertThat(codeNow).hasSize(6).matches("^\\d{6}$");

        // Valid on exact instant
        assertThat(Totp.verify(secret, codeNow, now)).isTrue();

        // Valid within -25s (same step) and +25s (same step)
        assertThat(Totp.verify(secret, codeNow, now.minusSeconds(25))).isTrue();
        assertThat(Totp.verify(secret, codeNow, now.plusSeconds(25))).isTrue();

        // Valid within 1 adjacent window step (-30s and +30s)
        assertThat(Totp.verify(secret, codeNow, now.plusSeconds(30))).isTrue();

        // Invalid on wrong code or distant time
        assertThat(Totp.verify(secret, "000000", now)).isFalse();
        assertThat(Totp.verify(secret, codeNow, now.plusSeconds(90))).isFalse();
    }

    @Test
    @DisplayName("generates distinct backup recovery codes")
    void backupCodes() {
        List<String> codes = Totp.generateBackupCodes(8);
        assertThat(codes).hasSize(8);
        assertThat(codes).allMatch(c -> c.matches("^[a-z0-9]{4}-[a-z0-9]{4}$"));
        assertThat(codes.stream().distinct().count()).isEqualTo(8);
    }
}
