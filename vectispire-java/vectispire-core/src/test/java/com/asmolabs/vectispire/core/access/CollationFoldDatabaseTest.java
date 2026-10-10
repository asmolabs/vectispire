package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
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
}
