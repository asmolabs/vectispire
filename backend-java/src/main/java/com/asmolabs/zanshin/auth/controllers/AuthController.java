package com.asmolabs.zanshin.auth.controllers;

import com.asmolabs.zanshin.auth.entities.User;
import com.asmolabs.zanshin.auth.services.AuthService;
import com.asmolabs.zanshin.repository.services.AuditLogService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AuditLogService auditLogService;

    @Value("${zanshin.frontend.url:http://localhost:4200}")
    private String frontendUrl;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> loginData, HttpServletResponse response) {
        String username = loginData.get("username");
        String password = loginData.get("password");

        Map<String, Object> result = authService.login(username, password);
        String token = (String) result.get("access_token");

        Cookie cookie = new Cookie("zanshin_token", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(24 * 60 * 60); // 1 day
        // cookie.setSecure(true); // Should be true in production
        response.addCookie(cookie);

        return ResponseEntity.ok(Map.of("success", true, "user", result.get("user")));
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody Map<String, String> userData) {
        return ResponseEntity.ok(authService.registerUser(userData));
    }

    @GetMapping("/registration-status")
    public ResponseEntity<Map<String, Boolean>> getRegistrationStatus() {
        return ResponseEntity.ok(Map.of("allowed", authService.isFirstUser()));
    }

    @GetMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Clear cookie
        Cookie cookie = new Cookie("zanshin_token", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        // Audit log (simplified)
        auditLogService.logAction(null, "N/A", "LOGOUT_SUCCESSFUL", "User logged out successfully.");

        response.sendRedirect(frontendUrl + "/login");
    }

    @GetMapping("/me")
    public ResponseEntity<UserDetails> getProfile(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userDetails);
    }
}
