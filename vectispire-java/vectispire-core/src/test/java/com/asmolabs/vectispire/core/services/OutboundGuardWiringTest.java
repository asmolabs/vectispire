package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.UnsafeUrlException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The bean, not the class: a guard that knows how to refuse the database is no use if the bean
 * every outbound request goes through was built without telling it where the database is.
 */
@DisplayName("the outbound guard bean")
class OutboundGuardWiringTest {

    @Test
    @DisplayName("refuses the configured database as a destination, whatever the policy")
    void reservesTheDatabase() {
        var guard = new OutboundGuardConfiguration().outboundUrlGuard("jdbc:mysql://127.0.0.1:3306/vectispire");

        assertThatThrownBy(() -> guard.validate("http://127.0.0.1:3306/", OutboundPolicy.INTERNAL_ALLOWED, "Webhook"))
                .isInstanceOf(UnsafeUrlException.class)
                .hasMessageContaining("the database");
    }
}
