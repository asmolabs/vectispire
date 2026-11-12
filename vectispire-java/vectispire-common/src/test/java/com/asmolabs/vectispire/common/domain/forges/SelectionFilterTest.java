package com.asmolabs.vectispire.common.domain.forges;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.forges.SelectionFilter.Candidate;
import com.asmolabs.vectispire.common.domain.forges.SelectionFilter.Judged;
import com.asmolabs.vectispire.common.domain.forges.SelectionFilter.Verdict;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("the selection table's filters (decision 0037 §4)")
class SelectionFilterTest {

    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");

    private static Candidate repository(Boolean archived, Boolean fork, Instant activity, String language) {
        return new Candidate(archived, fork, activity, language, "private", "acme/backend", "acme/backend/api", false, false, null);
    }

    private static SelectionFilter filter(String archived, String forks, Integer inactiveDays, String language) {
        return SelectionFilter.parse(archived, forks, inactiveDays, language, null, null, null, null, null, null);
    }

    @Test
    @DisplayName("by default archived repositories and forks are hidden, and nothing else")
    void defaults() {
        assertThat(SelectionFilter.DEFAULT.judge(repository(false, false, NOW, "Java"), NOW).matches()).isTrue();
        assertThat(SelectionFilter.DEFAULT.judge(repository(true, false, NOW, "Java"), NOW).matches()).isFalse();
        assertThat(SelectionFilter.DEFAULT.judge(repository(false, true, NOW, "Java"), NOW).matches()).isFalse();
        assertThat(filter(null, null, null, null)).isEqualTo(SelectionFilter.DEFAULT);
    }

    @Test
    @DisplayName("a hiding filter keeps what it cannot judge, and counts it")
    void hidingKeepsTheUnknown() {
        Verdict verdict = SelectionFilter.DEFAULT.judge(repository(null, null, NOW, "Java"), NOW);
        assertThat(verdict.matches()).as("GitLab states no fork flag for most projects: not hidden").isTrue();
        assertThat(verdict.unjudged()).containsExactlyInAnyOrder(Judged.ARCHIVED, Judged.FORK);

        Verdict inactive = filter("show", "show", 90, null).judge(repository(false, false, null, null), NOW);
        assertThat(inactive.matches()).isTrue();
        assertThat(inactive.unjudged()).containsExactly(Judged.ACTIVITY);
    }

    @Test
    @DisplayName("a requiring filter leaves out what it cannot judge, and counts it")
    void requiringLeavesOutTheUnknown() {
        Verdict language = filter("show", "show", null, "java").judge(repository(false, false, NOW, null), NOW);
        assertThat(language.matches()).isFalse();
        assertThat(language.unjudged()).containsExactly(Judged.LANGUAGE);

        Verdict onlyArchived = filter("only", "show", null, null).judge(repository(null, false, NOW, null), NOW);
        assertThat(onlyArchived.matches()).isFalse();
        assertThat(onlyArchived.unjudged()).containsExactly(Judged.ARCHIVED);
        assertThat(filter("only", "show", null, null).judge(repository(true, false, NOW, null), NOW).matches()).isTrue();
        assertThat(filter("show", "only", null, null).judge(repository(false, true, NOW, null), NOW).matches()).isTrue();
        assertThat(filter("show", "only", null, null).judge(repository(false, false, NOW, null), NOW).matches()).isFalse();
    }

    @Test
    @DisplayName("an unknown is counted only where nothing else hides the repository")
    void countedOnlyWhereItDecides() {
        Verdict hiddenAnyway = SelectionFilter.DEFAULT.judge(repository(true, null, NOW, null), NOW);
        assertThat(hiddenAnyway.matches()).isFalse();
        assertThat(hiddenAnyway.unjudged()).as("archived hides it whatever its fork flag").isEmpty();
        Verdict elsewhere = SelectionFilter.parse(null, null, null, null, null, "other", null, null, null, null)
                .judge(repository(null, null, NOW, null), NOW);
        assertThat(elsewhere.unjudged()).isEmpty();
    }

    @Test
    @DisplayName("inactivity, language and visibility, case aside")
    void values() {
        SelectionFilter recent = filter(null, null, 30, null);
        assertThat(recent.judge(repository(false, false, NOW.minus(Duration.ofDays(29)), null), NOW).matches()).isTrue();
        assertThat(recent.judge(repository(false, false, NOW.minus(Duration.ofDays(31)), null), NOW).matches()).isFalse();
        assertThat(filter(null, null, null, "JAVA").judge(repository(false, false, NOW, "Java"), NOW).matches()).isTrue();
        assertThat(filter(null, null, null, "Go").judge(repository(false, false, NOW, "Java"), NOW).matches()).isFalse();
        SelectionFilter visibility = SelectionFilter.parse(null, null, null, null, "Internal", null, null, null, null, null);
        assertThat(visibility.judge(repository(false, false, NOW, null), NOW).matches()).isFalse();
    }

    @Test
    @DisplayName("a namespace covers itself and what lies below, by whole segments")
    void namespace() {
        SelectionFilter acme = SelectionFilter.parse(null, null, null, null, null, "/ACME/", null, null, null, null);
        assertThat(acme.judge(repository(false, false, NOW, null), NOW).matches()).isTrue();
        SelectionFilter partial = SelectionFilter.parse(null, null, null, null, null, "acme/back", null, null, null, null);
        assertThat(partial.judge(repository(false, false, NOW, null), NOW).matches()).isFalse();
    }

    @ParameterizedTest(name = "{0} on {1}: {2}")
    @CsvSource({
        "acme/payments/*, acme/payments/api, true",
        "acme/payments/*, acme/payments/team/api, true",
        "acme/payments/*, acme/billing/api, false",
        "*/api, acme/payments/api, true",
        "acme/?ayments/api, acme/Payments/api, true",
        "acme/*/api, acme/x/y/api, true",
        "acme/*/api, acme/x/y/apiz, false",
        "payments, acme/payments/api, true",
        "PAYMENTS, acme/payments/api, true",
        "billing, acme/payments/api, false",
        "*, anything, true",
        "a*b*c*d, axxbxxcxxd, true",
        "a*b*c*d, axxbxxcxxe, false",
    })
    void pathPatterns(String pattern, String path, boolean matches) {
        assertThat(SelectionFilter.pathMatches(pattern, path)).isEqualTo(matches);
    }

    @Test
    @DisplayName("a pattern of many stars on a long path that almost matches is answered at once")
    void noBacktrackingBlowUp() {
        String pattern = "*a".repeat(40) + "*b";
        String path = "a".repeat(1_000);
        long started = System.nanoTime();
        assertThat(SelectionFilter.pathMatches(pattern, path)).isFalse();
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(2));
    }

    @Test
    @DisplayName("personal and present: show, hide or only")
    void personalAndPresent() {
        Candidate personal = new Candidate(false, false, NOW, null, null, "ada", "ada/notes", true, false, null);
        Candidate present = new Candidate(false, false, NOW, null, null, "acme", "acme/api", false, true, null);
        SelectionFilter hidePersonal = SelectionFilter.parse(null, null, null, null, null, null, null, "hide", null, null);
        SelectionFilter onlyPresent = SelectionFilter.parse(null, null, null, null, null, null, null, null, "only", null);
        assertThat(SelectionFilter.DEFAULT.judge(personal, NOW).matches()).isTrue();
        assertThat(SelectionFilter.DEFAULT.judge(present, NOW).matches()).isTrue();
        assertThat(hidePersonal.judge(personal, NOW).matches()).isFalse();
        assertThat(onlyPresent.judge(present, NOW).matches()).isTrue();
        assertThat(onlyPresent.judge(personal, NOW).matches()).isFalse();
    }

    @Test
    @DisplayName("refused in words")
    void refusals() {
        assertThatThrownBy(() -> filter("maybe", null, null, null)).isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("hide, show or only");
        assertThatThrownBy(() -> filter(null, null, 0, null)).isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("between 1 and");
        assertThat(Set.of(Judged.values())).extracting(Judged::wireName)
                .containsExactlyInAnyOrder("archived", "fork", "activity", "language", "visibility", "branch");
    }

    private static Candidate withBranches(BranchPresence branches) {
        return new Candidate(false, false, NOW, null, null, "acme", "acme/api", false, false, branches);
    }

    private static SelectionFilter branches(String... names) {
        return SelectionFilter.parse(null, null, null, null, null, null, null, null, null, List.of(names));
    }

    @Test
    @DisplayName("the branch filter: any one of the names present keeps it; all absent leaves it out; unread is unjudged")
    void branches() {
        Set<String> tracked = Set.of("main", "master", "develop");
        SelectionFilter developOrMaster = branches("develop", " master ", "");

        assertThat(developOrMaster.branches()).as("trimmed, the blank dropped").containsExactlyInAnyOrder("develop", "master");
        assertThat(developOrMaster.judge(withBranches(new BranchPresence("main", tracked, Set.of("main", "develop"))), NOW)
                .matches()).as("develop present: any one is enough").isTrue();
        Verdict absent = developOrMaster.judge(withBranches(new BranchPresence("main", tracked, Set.of("main"))), NOW);
        assertThat(absent.matches()).isFalse();
        assertThat(absent.unjudged()).as("both read absent: judged").isEmpty();

        Verdict unread = developOrMaster.judge(withBranches(new BranchPresence("main", null, null)), NOW);
        assertThat(unread.matches()).as("never read: not a repository with develop").isFalse();
        assertThat(unread.unjudged()).containsExactly(Judged.BRANCH);
        Verdict unanswered = developOrMaster.judge(withBranches(new BranchPresence("main", tracked, null)), NOW);
        assertThat(unanswered.unjudged()).as("the forge did not answer for one of them").containsExactly(Judged.BRANCH);
        Verdict notAsked = developOrMaster.judge(withBranches(new BranchPresence("main", Set.of("main"), Set.of())), NOW);
        assertThat(notAsked.unjudged()).as("a name the reading did not ask is unknown, not absent")
                .containsExactly(Judged.BRANCH);

        assertThat(developOrMaster.judge(withBranches(new BranchPresence("master", null, null)), NOW).matches())
                .as("the default branch needs no reading").isTrue();
        assertThat(SelectionFilter.DEFAULT.judge(withBranches(new BranchPresence(null, null, null)), NOW).matches())
                .as("no branch filter, nothing judged").isTrue();

        assertThatThrownBy(() -> branches("feature x")).isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("whitespace");
        assertThatThrownBy(() -> branches("default")).isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("default branch");
    }
}
