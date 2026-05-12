package com.asmolabs.zanshin.common.config;

import com.asmolabs.zanshin.auth.entities.User;
import com.asmolabs.zanshin.auth.enums.UserRole;
import com.asmolabs.zanshin.auth.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        if (userRepository.count() == 0) {
            log.info("No users found. Creating default admin user...");
            User admin = User.builder()
                    .username("admin")
                    .password(passwordEncoder.encode("admin123"))
                    .email("admin@example.com")
                    .displayName("Administrator")
                    .role(UserRole.SUPERUSER)
                    .isActive(true)
                    .build();
            userRepository.save(admin);
            log.info("Default admin user created: admin / admin123");
        }
    }
}
