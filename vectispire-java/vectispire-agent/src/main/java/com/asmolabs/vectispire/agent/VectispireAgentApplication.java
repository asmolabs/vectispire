package com.asmolabs.vectispire.agent;

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
public class VectispireAgentApplication {

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

    /**
     * The JSON mapper. See {@code CoreConfiguration} for why it is declared and not
     * auto-configured — and note that both sides must build it the same way, or the agent
     * protocol's two ends disagree about how an instant is written.
     */
    @org.springframework.context.annotation.Bean
    com.fasterxml.jackson.databind.ObjectMapper objectMapper() {
        return com.fasterxml.jackson.databind.json.JsonMapper.builder()
                .addModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                .disable(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .build();
    }

    public static void main(String[] args) {
        new SpringApplicationBuilder(VectispireAgentApplication.class)
                .web(WebApplicationType.NONE)
                .run(args);
    }
}
