package com.asmolabs.zanshin.auth.services;

import com.asmolabs.zanshin.auth.entities.User;
import com.asmolabs.zanshin.auth.enums.UserRole;
import com.asmolabs.zanshin.auth.repositories.UserRepository;
import com.asmolabs.zanshin.auth.security.JwtUtils;
import com.asmolabs.zanshin.repository.services.AuditLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final AuditLogService auditService;
    private final AuthenticationManager authenticationManager;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword() != null ? user.getPassword() : "",
                user.isActive(),
                true, true, true,
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
        );
    }

    @Transactional
    public User registerUser(Map<String, String> userData) {
        String username = userData.get("username");
        String password = userData.get("password");
        String email = userData.get("email");
        String displayName = userData.get("displayName");

        if (userRepository.findByUsername(username).isPresent() || userRepository.findByEmail(email).isPresent()) {
            throw new RuntimeException("Username or email already exists");
        }

        long userCount = userRepository.count();
        boolean isFirstUser = userCount == 0;

        User user = User.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .email(email)
                .displayName(displayName)
                .role(isFirstUser ? UserRole.SUPERUSER : UserRole.USER)
                .isActive(isFirstUser)
                .build();

        user = userRepository.save(user);

        if (isFirstUser) {
            auditService.logAction(null, user.getId().toString(), "CREATE", "Superuser created during initial registration.");
        }

        return user;
    }

    public Map<String, Object> login(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!user.isActive()) {
            throw new RuntimeException("Identifiants invalides ou compte non activé.");
        }

        UserDetails userDetails = loadUserByUsername(username);
        String token = jwtUtils.generateToken(userDetails, Map.of("role", user.getRole().name(), "sub", user.getId()));

        auditService.logAction(user.getId().toString(), user.getId().toString(), "LOGIN_SUCCESSFUL", "User logged in successfully.");

        return Map.of(
                "access_token", token,
                "user", user
        );
    }

    public boolean isFirstUser() {
        return userRepository.count() == 0;
    }

    public User validateUser(Map<String, Object> profile) {
        // TODO: Implement GitHub/Oauth2 validation logic similar to NestJS
        return null;
    }
}
