package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.common.domain.users.AccountRules;
import com.asmolabs.vectispire.core.VectispireContextTest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The name a failure is counted under agrees with the collation that decides which spellings open an
 * account (the audit of 10 October 2026).
 *
 * <p><b>Asked of the server, not recalled.</b> {@code jeßica} opened {@code jessica} on MySQL while counting
 * against a counter of its own, which turned the lockout into an account-existence oracle. Two strings the
 * collation weighs the same open the same account, so they must share {@link LoginThrottle#userKey}: every
 * letter of Latin-1 and Latin Extended-A — the alphabets people's names are typed in here — is weighed
 * against the ASCII letters and the digraphs the collation expands to.
 */
@DisplayName("the name a login failure counts under, against the database's collation")
class CollationFoldDatabaseTest extends VectispireContextTest {

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("two spellings the collation equates share one counter")
    void equalUnderTheCollationIsOneKey() {
        List<String> spellings = new ArrayList<>();
        for (char c = 'a'; c <= 'z'; c++) {
            spellings.add(String.valueOf(c));
        }
        spellings.addAll(List.of("ss", "ae", "oe", "th", "ij", "dz", "lj", "nj", "l·"));
        for (int c = 0x00C0; c <= 0x017F; c++) {
            if (Character.isLetter(c)) {
                spellings.add(Character.toString(c));
            }
        }

        Map<String, List<String>> byWeight = new HashMap<>();
        for (String spelling : spellings) {
            String weight = jdbc.queryForObject(
                    "select hex(weight_string(convert(? using utf8mb4) collate utf8mb4_0900_ai_ci))", String.class,
                    spelling);
            byWeight.computeIfAbsent(weight, ignored -> new ArrayList<>()).add(spelling);
        }

        List<String> disagreements = new ArrayList<>();
        for (List<String> same : byWeight.values()) {
            String key = LoginThrottle.userKey(same.getFirst());
            for (String other : same) {
                if (!LoginThrottle.userKey(other).equals(key)) {
                    disagreements.add(same.getFirst() + " = " + other);
                }
            }
        }
        assertThat(disagreements).as("spellings the collation equates and the counter keeps apart").isEmpty();
        assertThat(LoginThrottle.userKey("jeßica")).isEqualTo(LoginThrottle.userKey("Jessica"));
    }

    @Test
    @DisplayName("a spelling the collation equates only by characters it reads past is no name an account can hold")
    void ignoredCharactersOpenNoAccount() {
        // The fold above takes letters apart; it leaves alone what the collation ignores outright — a soft
        // hyphen, zero-width spaces and joiners, the word joiner, a byte-order mark, controls inside the
        // name. "ali\u00ADce" opened "alice" while counting on a key of its own (the audit of 12 October
        // 2026). Such a spelling must either share the account's counter or be no name an account can
        // hold, which sign-in then answers as an unknown one.
        List<Integer> candidates = new ArrayList<>();
        for (int c = 0x01; c <= 0x1F; c++) {
            candidates.add(c);
        }
        candidates.addAll(List.of(0x7F, 0xAD, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF));

        String plain = "alice";
        String plainWeight = weight(plain);
        List<String> ignored = new ArrayList<>();
        List<String> disagreements = new ArrayList<>();
        for (int c : candidates) {
            String spelling = "ali" + Character.toString(c) + "ce";
            if (!weight(spelling).equals(plainWeight)) {
                continue;
            }
            String named = String.format("U+%04X", c);
            ignored.add(named);
            if (AccountRules.isWellFormedUsername(spelling)
                    && !LoginThrottle.userKey(spelling).equals(LoginThrottle.userKey(plain))) {
                disagreements.add(named);
            }
        }

        assertThat(ignored).as("characters the server's collation reads past — the premise").contains("U+00AD");
        assertThat(disagreements).as("spellings that open the account under a counter of their own").isEmpty();
    }

    private String weight(String spelling) {
        return jdbc.queryForObject(
                "select hex(weight_string(convert(? using utf8mb4) collate utf8mb4_0900_ai_ci))", String.class, spelling);
    }
}

