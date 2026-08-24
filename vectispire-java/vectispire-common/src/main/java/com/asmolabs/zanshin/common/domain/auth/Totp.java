package com.asmolabs.zanshin.common.domain.auth;

import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pure implementation of RFC 6238 Time-based One-Time Password (TOTP) and RFC 4648 Base32.
 */
public final class Totp {

    private static final String HMAC_ALGO = "HmacSHA1";
    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;
    private static final int DIGIT_MODULO = 1_000_000;
    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Totp() {}

    /**
     * Generates a 160-bit (20-byte) cryptographically secure Base32 TOTP secret.
     */
    public static String generateSecret() {
        byte[] bytes = new byte[20];
        RANDOM.nextBytes(bytes);
        return encodeBase32(bytes);
    }

    /**
     * Generates a standard `otpauth://totp/...` URI for authenticator app enrollment.
     */
    public static String qrCodeUri(String username, String secret, String issuer) {
        String encodedIssuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8);
        String encodedUser = URLEncoder.encode(username, StandardCharsets.UTF_8);
        return "otpauth://totp/" + encodedIssuer + ":" + encodedUser
                + "?secret=" + secret
                + "&issuer=" + encodedIssuer
                + "&algorithm=SHA1&digits=6&period=30";
    }

    /**
     * Generates a list of emergency one-time recovery backup codes.
     */
    public static List<String> generateBackupCodes(int count) {
        List<String> codes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            StringBuilder sb = new StringBuilder(9);
            for (int j = 0; j < 8; j++) {
                if (j == 4) sb.append('-');
                int idx = RANDOM.nextInt(36);
                sb.append(idx < 10 ? (char) ('0' + idx) : (char) ('a' + idx - 10));
            }
            codes.add(sb.toString());
        }
        return List.copyOf(codes);
    }

    /**
     * Calculates the TOTP code for a specific instant.
     */
    public static String generateCode(String secret, Instant instant) {
        long timeStep = instant.getEpochSecond() / TIME_STEP_SECONDS;
        return generateCodeForStep(secret, timeStep);
    }

    /**
     * Validates a TOTP code against the secret with a tolerance window of ±1 step (±30s).
     */
    public static boolean verify(String secret, String submittedCode, Instant instant) {
        if (secret == null || submittedCode == null || submittedCode.trim().length() != CODE_DIGITS) {
            return false;
        }

        String cleaned = submittedCode.trim();
        long currentStep = instant.getEpochSecond() / TIME_STEP_SECONDS;

        // Window: current step, previous step (-30s), next step (+30s)
        for (long step = currentStep - 1; step <= currentStep + 1; step++) {
            if (cleaned.equals(generateCodeForStep(secret, step))) {
                return true;
            }
        }
        return false;
    }

    private static String generateCodeForStep(String secret, long step) {
        byte[] key = decodeBase32(secret);
        byte[] data = ByteBuffer.allocate(8).putLong(step).array();

        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(key, HMAC_ALGO));
            byte[] hash = mac.doFinal(data);

            // Dynamic truncation (RFC 4226 section 5.4)
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int otp = binary % DIGIT_MODULO;
            return String.format("%06d", otp);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to calculate HMAC-SHA1", e);
        }
    }

    public static String encodeBase32(byte[] data) {
        StringBuilder result = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;

        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                result.append(BASE32_CHARS.charAt((buffer >> bitsLeft) & 0x1F));
            }
        }

        if (bitsLeft > 0) {
            buffer <<= (5 - bitsLeft);
            result.append(BASE32_CHARS.charAt(buffer & 0x1F));
        }

        return result.toString();
    }

    public static byte[] decodeBase32(String base32) {
        String clean = base32.toUpperCase().replaceAll("[^A-Z2-7]", "");
        ByteBuffer buffer = ByteBuffer.allocate((clean.length() * 5) / 8);

        int cur = 0;
        int bitsLeft = 0;

        for (char c : clean.toCharArray()) {
            int val = BASE32_CHARS.indexOf(c);
            if (val < 0) continue;
            cur = (cur << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                buffer.put((byte) ((cur >> bitsLeft) & 0xFF));
            }
        }

        return buffer.array();
    }
}
