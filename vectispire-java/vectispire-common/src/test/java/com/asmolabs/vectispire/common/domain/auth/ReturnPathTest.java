package com.asmolabs.vectispire.common.domain.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("a return path after signing in")
class ReturnPathTest {

    @ParameterizedTest
    @ValueSource(strings = {
        "/projects/1/checklist",
        "/dashboard",
        "/issues?severity=critical&page=2",
        "/issues?path=src%2Fmain%2FApp.java",
        "/scans/42#findings",
        "/a"
    })
    @DisplayName("is one of this application's pages, kept exactly as written")
    void keepsThePagesOfThisApplication(String path) {
        assertThat(ReturnPath.parse(path)).hasValueSatisfying(p -> assertThat(p.value()).isEqualTo(path));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
        "//evil.example",
        "//evil.example/projects",
        "/\\evil.example",
        "\\\\evil.example",
        "https://evil.example",
        "http:/evil.example",
        "javascript:alert(1)",
        "evil.example/projects",
        "projects/1",
        "%2F%2Fevil.example",
        "/%2Fevil.example",
        "/%2fevil.example",
        "/%5Cevil.example",
        "/%252F%252Fevil.example",
        "/%25252F%25252F%25252Fevil.example",
        "/%2525252Fok",
        "/%zz",
        "/%2",
        "/\t/evil.example",
        "/\n/evil.example",
        "/ /evil.example",
        "/projects\u0000",
        "/projects/é",
        "/projects\\1",
        "/a/..//evil.example",
        "/./x",
        "/%2e%2e/x",
        "/",
        "/?returnUrl=/x",
        "/login",
        "/login?sso=complete",
        "/login/mfa"
    })
    @DisplayName("refuses every form a browser could follow off this origin, or that loops")
    void refusesTheRest(String hostile) {
        assertThat(ReturnPath.parse(hostile)).isEmpty();
    }

    @Test
    @DisplayName("is bounded")
    void isBounded() {
        String atLimit = "/" + "a".repeat(ReturnPath.MAX_LENGTH - 1);
        assertThat(ReturnPath.parse(atLimit)).isPresent();
        assertThat(ReturnPath.parse(atLimit + "a")).isEmpty();
    }

    @Test
    @DisplayName("cannot be built around the rule")
    void cannotBeBuiltAroundTheRule() {
        assertThatThrownBy(() -> new ReturnPath("//evil.example")).isInstanceOf(InvalidInputException.class);
    }
}
