package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.scheduling.CronSchedule;
import com.asmolabs.vectispire.core.RustReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.scheduling.support.CronExpression;

/**
 * What Spring's {@link CronExpression} and {@link CronExpressions} answer for {@code cron/inputs.json} — the
 * answers the Rust port of the parser ({@code vectispire_domain::cron}) is held to.
 *
 * <p><b>Why a port needs this.</b> A target's schedule is stored as the text an operator typed and read back
 * by Spring's parser: a seconds field, day of week 0 to 7, the Quartz {@code L}, {@code W} and {@code #}
 * forms, the macros, names in either case. No Rust crate reads those the same way, and a parser that
 * disagrees by one occurrence scans a fleet at the wrong hour, or never — silently, since an unusable
 * expression schedules nothing ({@link CronSchedule#NEVER}). So each expression's next fire times are
 * pinned, from starts chosen near the boundaries that break date arithmetic (a leap day, the end of a
 * year, a nanosecond before a second), and each refusal's sentence, which the operator reads.
 *
 * <p>Two readings per expression: Spring's own ({@code spring}), and the product's ({@code crontab}): the
 * five-field form with seconds prepended, blank as absent, unusable as never.
 */
class CronReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private static final Instant[] STARTS = {
        Instant.parse("2026-10-17T12:34:56.789Z"),
        Instant.parse("2024-02-28T23:59:59Z"),
        Instant.parse("2025-12-31T23:59:59.999999999Z"),
        Instant.parse("2027-01-31T00:00:00Z"),
    };

    private static final int OCCURRENCES = 6;

    @Test
    void theAnswersTheRustParserIsHeldTo() throws Exception {
        JsonNode inputs = JSON.readTree(Path.of(System.getProperty("vectispire.rust.reference"), "cron", "inputs.json").toFile());
        ArrayNode answers = JSON.createArrayNode();
        for (JsonNode input : inputs) {
            String expression = input.asText();
            ObjectNode answer = answers.addObject();
            answer.put("expression", expression);

            ObjectNode spring = answer.putObject("spring");
            try {
                CronExpression parsed = CronExpression.parse(expression);
                ArrayNode runs = spring.putArray("next");
                for (Instant start : STARTS) {
                    ArrayNode chain = runs.addArray();
                    ZonedDateTime from = start.atZone(ZoneOffset.UTC);
                    for (int i = 0; i < OCCURRENCES && from != null; i++) {
                        from = parsed.next(from);
                        chain.add(from == null ? null : instant(from.toInstant()));
                    }
                }
            } catch (IllegalArgumentException refused) {
                spring.put("refused", refused.getMessage());
            }

            ObjectNode crontab = answer.putObject("crontab");
            crontab.put("valid", CronExpressions.isValid(expression));
            Optional<CronSchedule> schedule = CronExpressions.parse(expression);
            crontab.put("schedule", schedule.isEmpty() ? "absent" : schedule.get() == CronSchedule.NEVER ? "never" : "parsed");
            ArrayNode next = crontab.putArray("next");
            for (Instant start : STARTS) {
                next.add(CronExpressions.nextOccurrence(expression, start).map(CronReferenceSetTest::instant).orElse(null));
            }
        }
        ObjectNode out = RustReference.object();
        out.set("answers", answers);
        RustReference.expect("cron/java-answers.json", out, CronReferenceSetTest.class);
    }

    private static ObjectNode instant(Instant value) {
        return JSON.createObjectNode().put("epoch_second", value.getEpochSecond()).put("nano", value.getNano());
    }
}
