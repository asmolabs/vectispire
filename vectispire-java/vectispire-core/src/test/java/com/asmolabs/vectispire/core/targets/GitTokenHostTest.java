package com.asmolabs.vectispire.core.targets;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.targets.persistence.GitTokenEntity;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A token's host is written once, when the token is added.
 *
 * <p><b>This is what lets the ciphertext be bound to the row's id alone</b>
 * ({@code SecretCipher.gitTokenContext}). The host decides where the token is ever presented
 * (decision 0022); if a route could move it, binding it into the encryption context would be the
 * only thing keeping a token from following its row to another server. No route can: rotating a
 * token, or moving it to another host, is adding a new one. A method that changes the host of an
 * existing row reopens that decision — bind the host into the context first, with a re-seal of
 * the rows already stored.
 */
@DisplayName("an HTTPS token's host")
class GitTokenHostTest {

    @Test
    @DisplayName("is set by adding the token, and by nothing else")
    void onlyTheAdditionWritesTheHost() {
        JavaClasses classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("com.asmolabs.vectispire.core");

        var writers = classes.get(GitTokenEntity.class).getMethod("setHost", String.class).getCallsOfSelf().stream()
                .map(call -> call.getOrigin().getFullName())
                .distinct()
                .toList();

        assertThat(writers).containsExactly(
                GitTokenAdministrationService.class.getName() + ".add(java.lang.String, java.lang.String, "
                        + "java.lang.String, java.lang.String, "
                        + "com.asmolabs.vectispire.core.audit.RequestActor)");
    }
}
