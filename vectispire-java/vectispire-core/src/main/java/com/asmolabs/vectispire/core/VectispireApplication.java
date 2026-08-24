package com.asmolabs.vectispire.core;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * The control plane: administration API, issue lifecycle, scan queue, agent protocol.
 */
@SpringBootApplication
@org.springframework.boot.context.properties.ConfigurationPropertiesScan
@org.springframework.scheduling.annotation.EnableScheduling
public class VectispireApplication {

    public static void main(String[] args) {
        SpringApplication.run(VectispireApplication.class, args);
    }
}
