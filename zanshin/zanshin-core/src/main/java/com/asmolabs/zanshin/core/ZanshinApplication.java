package com.asmolabs.zanshin.core;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * The control plane: administration API, issue lifecycle, scan queue, agent protocol.
 */
@SpringBootApplication
public class ZanshinApplication {

    public static void main(String[] args) {
        SpringApplication.run(ZanshinApplication.class, args);
    }
}
