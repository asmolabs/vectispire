package com.asmolabs.vectispire.core.access.web.security.chain;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireContextTest;
import jakarta.servlet.Filter;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;

/**
 * The security chain's filters are beans, which Spring Boot would also register with the servlet
 * container; each runs in the chain alone — see {@code SecurityConfiguration}.
 */
@DisplayName("the chain's filters")
class ChainFiltersRegisteredOnceTest extends VectispireContextTest {

    @Autowired
    private ApplicationContext context;

    @Test
    @DisplayName("every filter bean of the chain is kept out of the servlet container's own chain")
    void noneIsRegisteredWithTheContainer() {
        Map<Class<?>, Boolean> registered = context.getBeansOfType(FilterRegistrationBean.class).values().stream()
                .map(registration -> (FilterRegistrationBean<?>) registration)
                .collect(Collectors.toMap(registration -> registration.getFilter().getClass(),
                        registration -> registration.isEnabled()));

        // Every one, not a list of six: a filter added to this package later without its registration
        // would run twice again, and nothing else would say so.
        Map<String, Filter> filters = context.getBeansOfType(Filter.class);
        assertThat(filters.values().stream()
                        .filter(filter -> filter.getClass().getPackageName().equals(getClass().getPackageName()))
                        .map(Filter::getClass))
                .hasSize(6)
                .allSatisfy(type -> assertThat(registered).as(type.getSimpleName()).containsEntry(type, false));
    }
}
