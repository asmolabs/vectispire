package com.asmolabs.vectispire.core.gate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.gate.GatePolicy;
import com.asmolabs.vectispire.common.domain.gate.PolicyFlag;
import com.asmolabs.vectispire.common.domain.gate.RequestedPolicy;
import com.asmolabs.vectispire.common.domain.gate.SeverityRequest;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.gate.GateService.PolicyScope;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The one reading of a policy a route sent. Both routes parsed their own bodies until the parsing
 * moved here; the HTTP suites still pin what each route answers, this pins the two readings and
 * where they differ.
 */
@DisplayName("a policy as a route sent it")
class GatePolicyFieldsTest {

    private static GatePolicyFields fields(String severity, Boolean kev) {
        return new GatePolicyFields(severity, kev, false, false, false, null, null);
    }

    @Nested
    @DisplayName("read as one verdict's request")
    class AsRequest {

        @Test
        @DisplayName("an absent field is not mentioned, so the stored policy applies unchanged")
        void absentIsNotMentioned() {
            RequestedPolicy requested = new GatePolicyFields(null, null, null, null, null, null, null).asRequest();

            assertThat(requested).isEqualTo(RequestedPolicy.none());
        }

        @Test
        @DisplayName("a sent flag is mentioned, false included")
        void aSentFlagIsMentioned() {
            RequestedPolicy requested = new GatePolicyFields(null, false, null, null, null, null, true).asRequest();

            assertThat(requested.flags())
                    .isEqualTo(Map.of(PolicyFlag.FAIL_ON_KEV, false, PolicyFlag.INCLUDE_PLUGINS, true));
            assertThat(requested.failOnSeverity()).isEqualTo(SeverityRequest.UNSET);
        }

        @Test
        @DisplayName("\"none\" disables the threshold, whatever its case and padding")
        void noneDisables() {
            assertThat(fields("None", null).asRequest().failOnSeverity()).isInstanceOf(SeverityRequest.Disabled.class);
            assertThat(fields(" none ", null).asRequest().failOnSeverity()).isInstanceOf(SeverityRequest.Disabled.class);
        }

        @Test
        @DisplayName("a severity is a threshold")
        void aSeverityIsAThreshold() {
            assertThat(fields("critical", null).asRequest().failOnSeverity())
                    .isEqualTo(new SeverityRequest.Threshold(Severity.CRITICAL));
        }

        @Test
        @DisplayName("an unreadable severity is refused, never read as UNKNOWN — which would fail nothing")
        void aTypoIsRefused() {
            assertThatThrownBy(() -> fields("hgh", null).asRequest())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Unknown severity: \"hgh\".");
            assertThatThrownBy(() -> fields("", null).asRequest()).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("read as a stored policy replacing the last")
    class AsReplacement {

        @Test
        @DisplayName("every field is carried")
        void everyFieldIsCarried() {
            GatePolicy policy = new GatePolicyFields("medium", false, true, true, true, true, true).asReplacement();

            assertThat(policy).isEqualTo(new GatePolicy(Severity.MEDIUM, false, true, true, true, true, true));
        }

        @Test
        @DisplayName("\"none\" is the severity rule off — null, not a threshold nobody set")
        void noneIsOff() {
            assertThat(fields(" NONE ", true).asReplacement().failOnSeverity()).isNull();
        }

        @Test
        @DisplayName("an absent or blank severity is refused rather than reinstating the built-in one")
        void absentSeverityIsRefused() {
            assertThatThrownBy(() -> fields(null, true).asReplacement())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("\"fail_on_severity\" is required");
            assertThatThrownBy(() -> fields("  ", true).asReplacement())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("\"fail_on_severity\" is required");
        }

        @Test
        @DisplayName("an unreadable severity is refused")
        void aTypoIsRefused() {
            assertThatThrownBy(() -> fields("catastrophic", true).asReplacement())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Unknown severity: \"catastrophic\".");
        }

        @Test
        @DisplayName("an absent flag is refused: \"leave it\" and \"false\" differ by a build that fails")
        void anAbsentFlagIsRefused() {
            assertThatThrownBy(() -> fields("high", null).asReplacement())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("\"fail_on_kev\" is required.");
        }

        @Test
        @DisplayName("the two newest flags may be absent, and absent is off")
        void theNewestFlagsDefaultOff() {
            GatePolicy policy = fields("high", true).asReplacement();

            assertThat(policy.failOnUncoveredLanguages()).isFalse();
            assertThat(policy.includePlugins()).isFalse();
        }
    }

    @Nested
    @DisplayName("the target a route names")
    class Targets {

        @Test
        @DisplayName("a verdict names exactly one target")
        void exactlyOne() {
            assertThat(GateService.verdictTarget(7L, null)).isEqualTo(new ScanTarget.Repository(7));
            assertThat(GateService.verdictTarget(null, 3L)).isEqualTo(new ScanTarget.Container(3));
            assertThatThrownBy(() -> GateService.verdictTarget(7L, 3L)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> GateService.verdictTarget(null, null)).isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("a policy path names a repository or a container, nothing else")
        void aPathKind() {
            assertThat(PolicyScope.of("repository", 7)).isEqualTo(new PolicyScope("repository", 7));
            assertThat(PolicyScope.of("container", 3)).isEqualTo(new PolicyScope("container", 3));
            assertThatThrownBy(() -> PolicyScope.of("global", 0))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Unknown target kind");
        }
    }
}
