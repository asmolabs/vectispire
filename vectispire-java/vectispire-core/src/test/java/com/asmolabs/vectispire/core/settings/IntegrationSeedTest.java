package com.asmolabs.vectispire.core.settings;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.integrations.Integration;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Which integrations an installation starts with enabled (decision 0040 §5): every one V83 seeded, and no
 * other. The migration is applied and its checksum checked on every start, so it can never learn a later
 * adapter — which is the point: a key it does not seed has no row and reads disabled.
 */
@DisplayName("the integrations an installation starts with")
class IntegrationSeedTest {

    /**
     * Integrations added after V83, each arriving disabled. A new value in an adapter's enum fails this test
     * until it is written here — the moment to decide, on purpose, that an upgrade does not switch it on.
     * Bitbucket (0037, D8) will be the first.
     */
    private static final Set<String> ARRIVED_DISABLED = Set.of();

    @Test
    @DisplayName("V83 seeds, enabled, exactly the integrations that existed when the registry was introduced")
    void theSeedIsEveryIntegrationOfItsDay() throws IOException {
        String migration;
        try (InputStream in = getClass().getResourceAsStream("/db/migration/common/V83__integration_registry.sql")) {
            assertThat(in).as("V83 on the classpath").isNotNull();
            migration = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        Set<String> seeded = new LinkedHashSet<>();
        Matcher row = Pattern.compile("\\('([a-z0-9_.]+)', \\$\\{(true|false)}\\)").matcher(migration);
        while (row.find()) {
            assertThat(row.group(2)).as(row.group(1) + " is seeded enabled").isEqualTo("true");
            seeded.add(row.group(1));
        }

        Set<String> known = Integration.all().stream().map(Integration::key).collect(Collectors.toCollection(TreeSet::new));
        assertThat(seeded).as("every seeded key is an integration this version knows").isSubsetOf(known);
        Set<String> unseeded = new TreeSet<>(known);
        unseeded.removeAll(seeded);
        assertThat(unseeded)
                .as("integrations V83 does not seed — they read disabled; list each in ARRIVED_DISABLED on purpose")
                .isEqualTo(new TreeSet<>(ARRIVED_DISABLED));
    }
}
