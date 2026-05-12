package com.asmolabs.zanshin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class ZanshinApplication {

    public static void main(String[] args) {
        SpringApplication.run(ZanshinApplication.class, args);
    }

}
