package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AnalysisBudgetTest {

    @Test
    @DisplayName("a backtracking pattern is stopped by the budget, not by the patience of the thread")
    void aBacktrackingPatternIsStopped() {
        // The NestJS prefix pattern as it was: three quantifiers that all match a space, cubic in
        // the run — two seconds for 2,000 spaces, hours for this many.
        String content = "@Controller(" + " ".repeat(50_000);
        AnalysisBudget budget = AnalysisBudget.forContent(content);
        Pattern cubic = Pattern.compile("@Controller\\s*\\(\\s*['\"`]?([^'\"`]*)['\"`]?\\s*\\)");

        Assertions.assertTimeoutPreemptively(Duration.ofSeconds(10), () ->
                assertThatThrownBy(() -> cubic.matcher(budget.guard(content)).find())
                        .isInstanceOf(AnalysisBudget.Exhausted.class));
    }

    @Test
    @DisplayName("a linear pattern over a large file stays far inside the budget, and reads the same text")
    void aLinearPatternFits() {
        String content = ("@GetMapping(\"/items/{id}\")\n    Item one(@PathVariable long id) { return null; }\n")
                .repeat(20_000);
        AnalysisBudget budget = AnalysisBudget.forContent(content);

        Matcher matcher = Pattern.compile("@(GetMapping)\\b\\s*+\\(\"([^\"]++)\"\\)").matcher(budget.guard(content));
        int found = 0;
        while (matcher.find()) {
            assertThat(matcher.group(2)).isEqualTo("/items/{id}");
            found++;
        }

        assertThat(found).isEqualTo(20_000);
        assertThat(budget.spent()).isLessThan(4L * content.length());
    }

    @Test
    @DisplayName("every guarded view of a file draws on the one budget")
    void theBudgetIsShared() {
        AnalysisBudget budget = AnalysisBudget.ofReads(10);
        CharSequence first = budget.guard("abcdef");
        CharSequence second = budget.guard("ghijkl").subSequence(1, 6);

        for (int i = 0; i < 5; i++) {
            first.charAt(i);
            second.charAt(i);
        }

        assertThatThrownBy(() -> first.charAt(5)).isInstanceOf(AnalysisBudget.Exhausted.class);
        assertThat(second.toString()).isEqualTo("hijkl");
    }
}
