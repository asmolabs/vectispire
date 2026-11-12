package com.asmolabs.vectispire.common.domain.forges;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.forges.BranchPresence.Answer;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a repository's tracked branches")
class BranchPresenceTest {

    @Test
    @DisplayName("the column: sorted and comma-separated, empty for none, null for unknown — and back")
    void theColumn() {
        assertThat(BranchPresence.encode(List.of("master", "develop", "master"))).isEqualTo("develop,master");
        assertThat(BranchPresence.encode(List.of())).as("none is an answer").isEmpty();
        assertThat(BranchPresence.encode(null)).as("unknown is not none").isNull();
        assertThat(BranchPresence.decode("develop,master")).containsExactlyInAnyOrder("develop", "master");
        assertThat(BranchPresence.decode("")).isEmpty();
        assertThat(BranchPresence.decode(null)).isNull();
    }

    @Test
    @DisplayName("present by the default branch or the reading, absent only when asked and not found, unknown otherwise")
    void answers() {
        BranchPresence read = BranchPresence.stored("main", "develop,main,master", "develop,main");
        assertThat(read.of("main")).isEqualTo(Answer.PRESENT);
        assertThat(read.of("develop")).isEqualTo(Answer.PRESENT);
        assertThat(read.of("master")).isEqualTo(Answer.ABSENT);
        assertThat(read.of("trunk")).as("not asked by that reading").isEqualTo(Answer.UNKNOWN);

        BranchPresence unanswered = BranchPresence.stored("master", "develop,main,master", null);
        assertThat(unanswered.of("master")).as("the default branch needs no answer").isEqualTo(Answer.PRESENT);
        assertThat(unanswered.of("main")).isEqualTo(Answer.UNKNOWN);
        assertThat(BranchPresence.stored("main", null, null).of("develop")).as("never read").isEqualTo(Answer.UNKNOWN);
        assertThat(new BranchPresence(null, Set.of("main"), Set.of()).of("main")).as("an empty repository")
                .isEqualTo(Answer.ABSENT);
    }

    @Test
    @DisplayName("a tracked name: not empty, no whitespace nor comma, within the column, never the word for the default")
    void names() {
        assertThat(BranchPresence.refusal("release/2.x")).isNull();
        assertThat(BranchPresence.refusal("")).isNotNull();
        assertThat(BranchPresence.refusal("a b")).contains("whitespace");
        assertThat(BranchPresence.refusal("a,b")).contains("comma");
        assertThat(BranchPresence.refusal("x".repeat(256))).contains("255");
        assertThat(BranchPresence.refusal("default")).contains("default branch");
    }
}
