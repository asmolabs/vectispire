package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.common.domain.users.Role;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.services.AuditLogService;
import com.asmolabs.zanshin.core.services.SettingsService;
import com.asmolabs.zanshin.core.services.TicketService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.api.security.RequiresAdministrator;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The settings, read by everybody and written by administrators.
 *
 * <p><b>The catalog decides everything.</b> A key that is not in it is refused on write, which
 * gives two properties at once: the screen does not have to know the list, and the settings
 * table cannot fill with keys no service reads — the exact state that makes an operator believe
 * they configured something.
 *
 * <p><b>Every write is audited</b>, like any administration action: moving the notification
 * threshold from high to critical changes what the organization sees, and that is the kind of
 * decision one wants to be able to date.
 */
@RestController
@RequestMapping("/api/v1/settings")
// The catalog is readable by any account — the screen needs the labels and the types — and the
// two writing routes narrow it to administrators. A method's own marker wins over the class's,
// which is what lets one controller carry two different rules without a second controller.
@RequiresAccount
public class SettingsController {

    private final SettingsService settings;
    private final TicketService tickets;
    private final AuditLogService audit;

    public SettingsController(SettingsService settings, TicketService tickets, AuditLogService audit) {
        this.settings = settings;
        this.tickets = tickets;
        this.audit = audit;
    }

    /**
     * @param value the effective value, default included — without it the screen would show an
     *     empty field where the service is applying something
     * @param configured told apart explicitly, because "never set" and "set to the same value as
     *     the default" do not read the same to an operator
     */
    public record SettingView(
            String key,
            String type,
            String section,
            String label,
            String help,
            String defaultValue,
            String value,
            boolean configured) {}

    public record Catalog(List<SettingView> settings) {}

    public record TokenRequest(String token) {}

    /**
     * The catalog and the current values.
     *
     * <p>Both together rather than the values alone: the screen needs the type to pick its
     * control, and the help text to say what the setting does not do.
     */
    @GetMapping
    public Catalog list(@AuthenticationPrincipal ZanshinPrincipal principal) {
        Map<String, String> stored = settings.stored();
        // **A sensitive setting's value only leaves for an administrator.** A webhook URL is a
        // bearer capability: whoever reads it can post in the channel where the team awaits
        // Zanshin's alerts. The catalog itself stays readable by everybody — the screen needs
        // the labels and the types.
        boolean isAdmin = principal.user()
                .flatMap(user -> Role.of(user.getRole()))
                .map(Role::isAdministrative)
                .orElse(false);

        List<SettingView> views = new ArrayList<>();
        for (Setting setting : Setting.values()) {
            views.add(new SettingView(
                    setting.key(),
                    setting.type().name().toLowerCase(java.util.Locale.ROOT),
                    setting.section().name().toLowerCase(java.util.Locale.ROOT),
                    setting.label(),
                    setting.help(),
                    setting.defaultValue(),
                    setting.isSecret() && !isAdmin ? null : stored.getOrDefault(setting.key(), setting.defaultValue()),
                    stored.containsKey(setting.key())));
        }
        return new Catalog(views);
    }

    @RequiresAdministrator
    @PutMapping
    public Map<String, Integer> update(
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        if (body == null || body.isEmpty()) {
            throw new IllegalArgumentException("No setting supplied.");
        }

        record Change(Setting setting, String value) {}
        List<Change> changes = new ArrayList<>();
        for (Map.Entry<String, String> entry : body.entrySet()) {
            Setting setting = Setting.byKey(entry.getKey())
                    .orElseThrow(() -> new IllegalArgumentException("Unknown setting: \"" + entry.getKey() + "\"."));
            String value = entry.getValue() == null ? "" : entry.getValue().trim();
            setting.validate(value).ifPresent(problem -> {
                throw new IllegalArgumentException(setting.label() + " — " + problem);
            });
            changes.add(new Change(setting, value));
        }

        // All validated before any is written: a partial write would leave the configuration
        // half-way between two intended states.
        changes.forEach(change -> settings.set(change.setting(), change.value()));

        audit.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                changes.stream().map(change -> change.setting().key()).reduce((a, b) -> a + "," + b).orElse(""),
                // The values are logged: no catalog setting is a secret, and knowing *what*
                // somebody changed is the whole point of the entry.
                changes.stream()
                        .map(change -> change.setting().key() + " = "
                                + (change.value().isEmpty() ? "(empty)" : change.value()))
                        .reduce((a, b) -> a + "; " + b)
                        .orElse(""),
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return Map.of("updated", changes.size());
    }

    /**
     * The tracker token, write-only.
     *
     * <p><b>Its own route, outside the catalog</b>, because a secret does not behave like a
     * setting: it is encrypted at rest, it cannot be read back into a form, and the screen can
     * therefore only show "configured" or "absent". Routing it through the generic path would
     * have needed an exception at every step — read, validate, audit — and one of them would
     * eventually have been forgotten.
     */
    @RequiresAdministrator
    @PutMapping("/ticket-token")
    public Map<String, Boolean> setTicketToken(
            @RequestBody TokenRequest body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        String token = body == null || body.token() == null ? "" : body.token();
        tickets.setToken(token);

        audit.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                Setting.TICKET_TOKEN.key(),
                // The value is **not** logged, unlike the other settings: the audit trail is
                // readable by every administrator.
                token.isBlank() ? "Tracker token cleared." : "Tracker token stored.",
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return Map.of("configured", !token.isBlank());
    }

    /** The token's state, without ever returning it. */
    @GetMapping("/ticket-token")
    public Map<String, Boolean> ticketTokenState() {
        return Map.of("configured", !tickets.token().isEmpty());
    }
}
