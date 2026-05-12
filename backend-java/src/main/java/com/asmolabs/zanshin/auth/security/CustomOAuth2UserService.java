package com.asmolabs.zanshin.auth.security;

import com.asmolabs.zanshin.auth.entities.User;
import com.asmolabs.zanshin.auth.enums.UserRole;
import com.asmolabs.zanshin.auth.repositories.UserRepository;
import com.asmolabs.zanshin.repository.services.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final AuditLogService auditService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        try {
            return processOAuth2User(registrationId, oauth2User);
        } catch (Exception ex) {
            log.error("Error processing OAuth2 user", ex);
            throw ex;
        }
    }

    private OAuth2User processOAuth2User(String registrationId, OAuth2User oauth2User) {
        Map<String, Object> attributes = oauth2User.getAttributes();
        String id;
        String username;
        String email;
        String avatarUrl;
        String displayName;

        if ("github".equals(registrationId)) {
            id = String.valueOf(attributes.get("id"));
            username = (String) attributes.get("login");
            email = (String) attributes.get("email");
            avatarUrl = (String) attributes.get("avatar_url");
            displayName = (String) attributes.get("name");
        } else {
            // Default OIDC / Keycloak
            id = (String) attributes.get("sub");
            username = (String) attributes.get("preferred_username");
            email = (String) attributes.get("email");
            avatarUrl = (String) attributes.get("picture");
            displayName = (String) attributes.get("name");
        }

        Optional<User> userOptional = "github".equals(registrationId) 
                ? userRepository.findByGithubId(id) 
                : userRepository.findByKeycloakId(id);

        User user;
        if (userOptional.isPresent()) {
            user = userOptional.get();
            updateExistingUser(user, username, email, avatarUrl, displayName);
        } else {
            user = registerNewUser(registrationId, id, username, email, avatarUrl, displayName);
        }

        return new CustomOAuth2User(user, attributes);
    }

    private User registerNewUser(String registrationId, String id, String username, String email, String avatarUrl, String displayName) {
        long userCount = userRepository.count();
        boolean isFirstUser = userCount == 0;

        User.UserBuilder builder = User.builder()
                .username(username != null ? username : (email != null ? email.split("@")[0] : "user_" + id))
                .email(email)
                .avatarUrl(avatarUrl)
                .displayName(displayName)
                .role(isFirstUser ? UserRole.SUPERUSER : UserRole.USER)
                .isActive(isFirstUser);

        if ("github".equals(registrationId)) {
            builder.githubId(id);
        } else {
            builder.keycloakId(id);
        }

        User user = userRepository.save(builder.build());

        if (isFirstUser) {
            auditService.logAction(null, user.getId().toString(), "CREATE", "Superuser created during OAuth2 registration.");
        }

        return user;
    }

    private void updateExistingUser(User user, String username, String email, String avatarUrl, String displayName) {
        if (username != null) user.setUsername(username);
        if (email != null) user.setEmail(email);
        if (avatarUrl != null) user.setAvatarUrl(avatarUrl);
        if (displayName != null) user.setDisplayName(displayName);
        userRepository.save(user);
    }
}
