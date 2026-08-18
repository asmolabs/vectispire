package com.asmolabs.zanshin.agent;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

/**
 * The remote agent: long-polls the control plane for work, runs the scanners, posts results.
 *
 * <p>Started with {@link WebApplicationType#NONE} on purpose. The agent opens no port — it
 * dials out. An agent that listened would be a second attack surface inside whatever network
 * it was placed in, which is usually the network the control plane is deliberately kept out
 * of.
 */
@SpringBootApplication
@org.springframework.boot.context.properties.ConfigurationPropertiesScan
public class ZanshinAgentApplication {

    /**
     * The clock, injected rather than called.
     *
     * <p>Same reason as in the control plane: a scan's duration is computed from it, and a
     * duration nobody can fix in a test is a duration nobody has ever asserted.
     */
    @org.springframework.context.annotation.Bean
    java.time.Clock clock() {
        return java.time.Clock.systemUTC();
    }

    public static void main(String[] args) {
        new SpringApplicationBuilder(ZanshinAgentApplication.class)
                .web(WebApplicationType.NONE)
                .run(args);
    }
}
