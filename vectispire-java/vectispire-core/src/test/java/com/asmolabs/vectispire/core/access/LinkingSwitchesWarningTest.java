package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

/**
 * The two linking switches, together, said at start.
 *
 * <p>Each is legitimate alone. Together they bind a privileged account to whoever first signs on under
 * its name, which is right only for a realm where nobody chooses a username — and an operator who set
 * one for the SCIM side and left the other at its default had no way to see it.
 */
@ExtendWith(OutputCaptureExtension.class)
@DisplayName("the identity linking switches")
class LinkingSwitchesWarningTest {

    private static final String WARNING = "link-privileged-accounts and vectispire.oidc.link-by-claim are both on";

    private static ExternalIdentityService start(boolean linkPrivileged, boolean linkByClaim) {
        return new ExternalIdentityService(
                Mockito.mock(UserRepository.class), Optional.empty(), Optional.empty(), linkPrivileged, linkByClaim);
    }

    @Test
    @DisplayName("privileged linking with linking by claim is warned about at start")
    void bothOnIsWarned(CapturedOutput output) {
        start(true, true);

        assertThat(output.getAll()).contains(WARNING);
    }

    @Test
    @DisplayName("either alone is not")
    void eitherAloneIsSilent(CapturedOutput output) {
        start(true, false);
        start(false, true);
        start(false, false);

        assertThat(output.getAll()).doesNotContain(WARNING);
    }
}
