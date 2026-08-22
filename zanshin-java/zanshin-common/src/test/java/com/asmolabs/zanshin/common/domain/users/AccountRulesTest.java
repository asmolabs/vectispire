package com.asmolabs.zanshin.common.domain.users;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("account rules")
class AccountRulesTest {

    @ParameterizedTest(name = "accepts {0}")
    @ValueSource(strings = {"admin", "jean.dupont", "ci-bot_01"})
    void acceptsReasonableUsernames(String username) {
        assertThat(AccountRules.validateUsername(username)).isEmpty();
    }

    @ParameterizedTest(name = "refuses [{0}]")
    @ValueSource(strings = {"", "a", "jean dupont", "jean@example.be"})
    void refusesBadUsernames(String username) {
        assertThat(AccountRules.validateUsername(username)).isPresent();
    }

    @Test
    @DisplayName("refuses a username past 64 characters")
    void refusesLongUsernames() {
        assertThat(AccountRules.validateUsername("x".repeat(65))).isPresent();
    }

    @Nested
    @DisplayName("passwords")
    class Passwords {

        @Test
        @DisplayName("asks for length and nothing else")
        void lengthOnly() {
            // Character-class rules produce `Password1!` and encourage reuse. Length is the
            // only constraint whose effect on entropy is real.
            assertThat(AccountRules.validatePassword("correct-horse-battery-staple")).isEmpty();
            assertThat(AccountRules.validatePassword("short")).isPresent();
        }

        @Test
        @DisplayName("no longer refuses long passwords, because Argon2 does not truncate")
        void acceptsLongPassphrases() {
            // The old 72-byte ceiling was bcrypt's, not a property of passwords: bcrypt
            // silently ignores everything past it, so accepting a 90-character passphrase
            // would have let someone believe a third of it protected them. Argon2id has no
            // such limit, and refusing long passwords was never the goal.
            assertThat(AccountRules.validatePassword("a".repeat(200))).isEmpty();
            // Accented characters are two bytes each: under the old rule 37 of them were
            // refused. The accents are load-bearing in this test — with ASCII it proves
            // nothing.
            assertThat(AccountRules.validatePassword("é".repeat(37))).isEmpty();
        }
    }

    @Nested
    @DisplayName("roles")
    class Roles {

        @Test
        @DisplayName("parses the vocabulary and refuses anything else")
        void parsesRoles() {
            assertThat(Role.of("ADMIN")).contains(Role.ADMIN);
            assertThat(Role.of("CISO")).contains(Role.CISO);
            // Case-sensitive: the field has a fixed set of choices, and accepting `admin`
            // means accepting whatever else arrives in it.
            assertThat(Role.of("admin")).isEmpty();
            assertThat(Role.of("ROOT")).isEmpty();
        }

        @Test
        @DisplayName("carries whether the role administers, rather than a second list")
        void adminIsAProperty() {
            assertThat(Role.SUPERUSER.isAdministrative()).isTrue();
            assertThat(Role.ADMIN.isAdministrative()).isTrue();
            assertThat(Role.CISO.isAdministrative()).isFalse();
            assertThat(Role.USER.isAdministrative()).isFalse();

            assertThat(Role.CISO.hasGlobalSecurityScope()).isTrue();
            assertThat(Role.USER.hasGlobalSecurityScope()).isFalse();
        }
    }

    @Nested
    @DisplayName("locking yourself out")
    class SelfLockout {

        private static AccountRules.Change base() {
            return new AccountRules.Change(false, true, true, true, 1);
        }

        @Test
        @DisplayName("lets an ordinary change through")
        void allowsOrdinaryChange() {
            assertThat(AccountRules.refuseSelfLockout(base())).isEmpty();
        }

        @Test
        @DisplayName("refuses deactivating yourself")
        void refusesSelfDeactivation() {
            assertThat(AccountRules.refuseSelfLockout(new AccountRules.Change(true, true, true, false, 1)))
                    .isPresent();
        }

        @Test
        @DisplayName("refuses removing your own administrator role")
        void refusesSelfDemotion() {
            assertThat(AccountRules.refuseSelfLockout(new AccountRules.Change(true, true, false, true, 1)))
                    .isPresent();
        }

        @Test
        @DisplayName("refuses removing the last administrator, even on somebody else's account")
        void refusesEmptyingTheAdminList() {
            // There is no rescue screen: with no active administrator left, recovery means a
            // database session.
            assertThat(AccountRules.refuseSelfLockout(new AccountRules.Change(false, true, false, true, 0)))
                    .hasValueSatisfying(reason -> assertThat(reason).contains("last active administrator"));
            assertThat(AccountRules.refuseSelfLockout(new AccountRules.Change(false, true, true, false, 0)))
                    .hasValueSatisfying(reason -> assertThat(reason).contains("last active administrator"));
        }

        @Test
        @DisplayName("says nothing while another administrator remains")
        void allowsWhileAnotherRemains() {
            assertThat(AccountRules.refuseSelfLockout(new AccountRules.Change(false, true, false, true, 1)))
                    .isEmpty();
        }

        @Test
        @DisplayName("lets an ordinary account be promoted even with no other administrator")
        void allowsPromotion() {
            assertThat(AccountRules.refuseSelfLockout(new AccountRules.Change(false, false, true, true, 0)))
                    .isEmpty();
        }
    }

    @Nested
    @DisplayName("deletion")
    class Deletion {

        @Test
        @DisplayName("refuses your own account")
        void refusesSelf() {
            assertThat(AccountRules.refuseDeletion(true, true, 5)).isPresent();
        }

        @Test
        @DisplayName("refuses the last active administrator")
        void refusesLastAdmin() {
            assertThat(AccountRules.refuseDeletion(false, true, 0))
                    .hasValueSatisfying(reason -> assertThat(reason).contains("last active administrator"));
        }

        @Test
        @DisplayName("lets an ordinary account go")
        void allowsOrdinaryAccount() {
            assertThat(AccountRules.refuseDeletion(false, false, 0)).isEmpty();
        }
    }
}
