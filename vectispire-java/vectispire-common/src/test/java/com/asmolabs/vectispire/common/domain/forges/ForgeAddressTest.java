package com.asmolabs.vectispire.common.domain.forges;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("a forge's address: the web address typed, the API's derived")
class ForgeAddressTest {

    @ParameterizedTest(name = "{0} \"{1}\" → {2} {3} {4}")
    @CsvSource(delimiter = '|', value = {
        "GITHUB | ''                                  | GITHUB_COM               | https://github.com            | https://api.github.com",
        "GITHUB | https://github.com/                 | GITHUB_COM               | https://github.com            | https://api.github.com",
        "GITHUB | https://acme.ghe.com                | GITHUB_DATA_RESIDENCY    | https://acme.ghe.com          | https://api.acme.ghe.com",
        "GITHUB | https://api.acme.ghe.com/           | GITHUB_DATA_RESIDENCY    | https://acme.ghe.com          | https://api.acme.ghe.com",
        "GITHUB | https://Git.Example.org//           | GITHUB_ENTERPRISE_SERVER | https://git.example.org       | https://git.example.org/api/v3",
        "GITLAB | ''                                  | GITLAB_COM               | https://gitlab.com            | https://gitlab.com/api/v4",
        "GITLAB | https://gitlab.com                  | GITLAB_COM               | https://gitlab.com            | https://gitlab.com/api/v4",
        "GITLAB | https://example.org/gitlab/         | GITLAB_SELF_MANAGED      | https://example.org/gitlab    | https://example.org/gitlab/api/v4",
        "GITLAB | https://gitlab.internal:8443        | GITLAB_SELF_MANAGED      | https://gitlab.internal:8443  | https://gitlab.internal:8443/api/v4",
    })
    void derivesTheEditionAndTheApi(ForgeKind kind, String typed, ForgeEdition edition, String base, String api) {
        ForgeAddress address = ForgeAddress.of(kind, typed);

        assertThat(address.edition()).isEqualTo(edition);
        assertThat(address.baseUrl()).isEqualTo(base);
        assertThat(address.apiRoot()).isEqualTo(api);
        assertThat(ForgeAddress.of(kind, address.baseUrl())).as("the stored address derives the same").isEqualTo(address);
    }

    @ParameterizedTest(name = "\"{0}\" is refused")
    @ValueSource(strings = {
        "http://gitlab.example.org",
        "https://user:secret@gitlab.example.org",
        "https://oauth2@gitlab.example.org",
        "https://gitlab.example.org/api/v4",
        "https://gitlab.example.org/gitlab/api/v4/",
        "https://gitlab.example.org/?private_token=x",
        "https://gitlab.example.org/#top",
        "gitlab.example.org",
        "https://",
    })
    void refusesWhatIsNotAWebAddress(String typed) {
        assertThatThrownBy(() -> ForgeAddress.of(ForgeKind.GITLAB, typed)).isInstanceOf(InvalidInputException.class);
    }

    @Test
    @DisplayName("http is refused in words that say why")
    void httpIsRefusedInWords() {
        assertThatThrownBy(() -> ForgeAddress.of(ForgeKind.GITHUB, "http://git.example.org"))
                .hasMessageContaining("https://")
                .hasMessageContaining("in the clear");
    }

    @Test
    @DisplayName("a pasted API path is refused with what to type instead")
    void anApiPathIsRefusedInWords() {
        assertThatThrownBy(() -> ForgeAddress.of(ForgeKind.GITLAB, "https://gitlab.example.org/api/v4"))
                .hasMessageContaining("web address");
    }

    @Test
    @DisplayName("only the vendors' clouds are clouds")
    void cloudEditions() {
        assertThat(ForgeEdition.GITHUB_COM.cloud()).isTrue();
        assertThat(ForgeEdition.GITHUB_DATA_RESIDENCY.cloud()).isTrue();
        assertThat(ForgeEdition.GITLAB_COM.cloud()).isTrue();
        assertThat(ForgeEdition.GITHUB_ENTERPRISE_SERVER.cloud()).isFalse();
        assertThat(ForgeEdition.GITLAB_SELF_MANAGED.cloud()).isFalse();
    }

    @Test
    @DisplayName("a kind outside the two is refused in words, Bitbucket included until lot D8")
    void kinds() {
        assertThat(ForgeKind.parse(" GitLab ")).isEqualTo(ForgeKind.GITLAB);
        assertThatThrownBy(() -> ForgeKind.parse("bitbucket")).isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("github, gitlab");
        assertThatThrownBy(() -> ForgeKind.parse(null)).isInstanceOf(InvalidInputException.class);
    }
}
