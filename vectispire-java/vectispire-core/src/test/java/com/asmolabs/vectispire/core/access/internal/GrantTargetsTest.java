package com.asmolabs.vectispire.core.access.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.GrantableTargets;
import java.util.List;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The granter's visibility, on the one path the HTTP suite cannot reach: the administrators who
 * reach the grant routes see the whole estate, so a target that exists and is hidden from the granter
 * only arises for a role or a credential that sees less.
 */
@DisplayName("what a grant may name, for a granter who sees less than everything")
class GrantTargetsTest {

    private final GrantableTargets targets = mock(GrantableTargets.class);
    private final GrantTargets rule = new GrantTargets(targets);

    private static final Visibility SEES_ONE = Visibility.only(List.of(new ScanTarget.Repository(1L)));

    @Test
    @DisplayName("a target that exists and that the granter does not see is refused in the words of an absent one")
    void aHiddenTargetIsRefusedAsAbsent() {
        when(targets.exists(new ScanTarget.Repository(2L))).thenReturn(true);
        when(targets.exists(new ScanTarget.Repository(3L))).thenReturn(false);

        String hidden = messageOf(() -> rule.validate("repository", 2L, SEES_ONE, (kind, id) -> false));
        String absent = messageOf(() -> rule.validate("repository", 3L, Visibility.everything(), (kind, id) -> false));

        assertThat(hidden).isEqualTo("No repository with id 2.");
        assertThat(absent).isEqualTo("No repository with id 3.");
    }

    @Test
    @DisplayName("a target the granter sees is granted, its kind normalized")
    void aVisibleTargetIsGranted() {
        when(targets.exists(new ScanTarget.Repository(1L))).thenReturn(true);

        assertThat(rule.validate("Repository", 1L, SEES_ONE, (kind, id) -> false)).isEqualTo("repository");
    }

    @Test
    @DisplayName("a grant already held is kept without asking whether its target is still there")
    void aHeldGrantIsKept() {
        assertThat(rule.validate("container", 9L, SEES_ONE, (kind, id) -> kind.equals("container") && id == 9L))
                .isEqualTo("container");
    }

    private static String messageOf(Runnable validation) {
        Throwable[] thrown = new Throwable[1];
        assertThatThrownBy(() -> {
                    try {
                        validation.run();
                    } catch (RuntimeException refusal) {
                        thrown[0] = refusal;
                        throw refusal;
                    }
                })
                .isInstanceOf(NoSuchElementException.class);
        return thrown[0].getMessage();
    }
}
