package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.services.AiReviewService;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.NotificationService;
import com.asmolabs.vectispire.core.services.SettingsService;
import com.asmolabs.vectispire.core.services.TicketService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * A credential has one door, and the generic settings route is not it.
 *
 * <p><b>The defect these close.</b> {@code Sensitivity.SECRET} meant "do not show this to a
 * non-administrator" and was consulted in exactly one place — the catalog's read side. Nothing in
 * the write path looked at it. So the tracker token, the webhook signing secret and the model
 * provider key, each of which has a route that encrypts before storing, stayed writable through
 * {@code PUT /api/v1/settings}, which stores what it is handed: in the clear, 200 OK, no warning.
 * The catalog then returned them verbatim to every administrative role, and the audit description
 * — in a log deliberately never purged — names each change as {@code key = value}.
 *
 * <p>The cases are generated from the catalog rather than listed, so a credential added later is
 * covered the day it is marked, and one that is <em>not</em> marked fails
 * {@code SettingTest.credentialsAreMarkedEncrypted} instead of slipping through both.
 */
@DisplayName("writing a credential")
class SettingsCredentialWriteTest {

    private SettingsService settings;
    private SettingsController controller;
    private VectispirePrincipal principal;
    private com.asmolabs.vectispire.core.repositories.Users users;

    static Stream<Setting> credentials() {
        return Arrays.stream(Setting.values()).filter(Setting::isEncrypted);
    }

    @BeforeEach
    void wire() {
        settings = mock(SettingsService.class);
        AiReviewService aiReview = mock(AiReviewService.class);
        users = mock(com.asmolabs.vectispire.core.repositories.Users.class);
        // Par défaut il existe des approbateurs : le cas contraire est le sujet d'un cas dédié.
        when(users.countActiveAdministratorsExcluding(any(), any(Long.class))).thenReturn(3L);
        controller = new SettingsController(
                settings, mock(TicketService.class), mock(AuditLogService.class), aiReview,
                mock(NotificationService.class), users);

        when(settings.get(any(Setting.class))).thenReturn("");
        when(aiReview.ollamaUrl()).thenReturn("http://localhost:11434");
        when(aiReview.openAiUrl()).thenReturn("https://api.openai.com/v1");

        UserEntity user = new UserEntity();
        user.setUsername("laurent");
        user.setRole(Role.ADMIN.name());
        principal = VectispirePrincipal.ofUser(user, null);
    }

    private static HttpServletRequest request() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        return request;
    }

    private VectispirePrincipal as(Role role) {
        UserEntity user = new UserEntity();
        user.setUsername("probe");
        user.setRole(role.name());
        return VectispirePrincipal.ofUser(user, null);
    }

    @Test
    @DisplayName("only the governor may lift the four-eyes rule, and an administrator may not")
    void theRuleBelongsToTheGovernor() {
        // **Le contournement que ceci ferme.** Éteindre la double validation, régler seul,
        // rallumer : une entrée d'audit pour toute trace. Retirer le droit d'approuver n'aurait
        // rien changé — `IssueTriageService` règle la décision de tout le monde quand le réglage
        // est éteint. Ce qui le ferme est que le seul rôle qui puisse lever la règle soit celui
        // qui ne peut pas agir sous elle.
        assertThatThrownBy(() -> controller.update(
                Map.of(Setting.FOUR_EYES_APPROVAL_REQUIRED.key(), "false"), as(Role.ADMIN), request()))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        assertThatThrownBy(() -> controller.update(
                Map.of(Setting.TARGET_VISIBILITY.key(), "everyone"), as(Role.CISO), request()))
                .as("qui voit quelles cibles est une règle, pas un réglage")
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        verify(settings, never()).set(any(Setting.class), anyString());

        // Et le gouverneur, lui, passe : une garde qui refuse tout le monde est aussi cassée
        // qu'une garde qui ne refuse personne.
        controller.update(Map.of(Setting.FOUR_EYES_APPROVAL_REQUIRED.key(), "false"),
                as(Role.SUPERUSER), request());
        verify(settings).set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
    }

    @Test
    @DisplayName("a two-person control cannot be switched on where there is no second person")
    void enablingNeedsSomebodyToApprove() {
        when(users.countActiveAdministratorsExcluding(any(), any(Long.class))).thenReturn(0L);

        // Sans ce garde, chaque décision réglée part dans une file que personne ne peut vider :
        // un contrôle qui bloque au lieu de contrôler, et dont la panne ne se voit qu'au premier
        // triage.
        assertThatThrownBy(() -> controller.update(
                Map.of(Setting.FOUR_EYES_APPROVAL_REQUIRED.key(), "true"), as(Role.SUPERUSER), request()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Aucun compte actif ne peut approuver");

        // L'éteindre reste possible : c'est l'activation qui demande un second, pas l'inverse.
        controller.update(Map.of(Setting.FOUR_EYES_APPROVAL_REQUIRED.key(), "false"),
                as(Role.SUPERUSER), request());
        verify(settings).set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
    }

    @ParameterizedTest(name = "{0} cannot be set through the generic route")
    @MethodSource("credentials")
    void theGenericRouteRefusesIt(Setting credential) {
        assertThatThrownBy(() -> controller.update(
                Map.of(credential.key(), "PROBE-secret-value"), principal, request()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("written by its own route");

        // Nothing reached the table. A refusal after a partial write would be the same defect with
        // an error message on top.
        verify(settings, never()).set(any(Setting.class), anyString());
    }

    @ParameterizedTest(name = "{0} is never returned by the catalog")
    @MethodSource("credentials")
    void theCatalogNeverReturnsIt(Setting credential) {
        when(settings.stored()).thenReturn(Map.of(credential.key(), "v2:some-ciphertext"));

        SettingsController.SettingView view = controller.list(principal).settings().stream()
                .filter(entry -> entry.key().equals(credential.key()))
                .findFirst()
                .orElseThrow();

        // Withheld from an administrator too: what is stored is a ciphertext, of no use to a form
        // that cannot re-submit it, and returning it puts the blob in a browser tab and a proxy log.
        assertThat(view.value()).isNull();
        // The row is still described, or the screen could not say a credential exists at all.
        assertThat(view.label()).isNotBlank();
        assertThat(view.configured()).isTrue();
    }
}
