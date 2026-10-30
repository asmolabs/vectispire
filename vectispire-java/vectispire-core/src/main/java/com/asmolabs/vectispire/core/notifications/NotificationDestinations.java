package com.asmolabs.vectispire.core.notifications;

import com.asmolabs.vectispire.common.domain.notifications.NotificationChannelKind;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.access.TeamChannels;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Where each notification channel sends, read as the integrations' registry needs it (decision 0040 §3, lot
 * I6): whether a channel has a destination — and so may not be switched off — and which channels a settings
 * save starts sending to — and so must be on.
 *
 * <p><b>One reading for both questions.</b> The switch asks "is anything configured to send there?" and the
 * save asks "does this change configure it?"; answered by two lists of settings, the day a sixth setting
 * gave a channel somewhere to send, one list would learn it and the other would not, and a channel could be
 * switched off under a destination the refusal did not know about.
 *
 * <p>A team's own webhook is the {@link NotificationChannelKind#WEBHOOK} channel too: it is written on the
 * team ({@code TeamAdministrationService}, which holds the integration itself — {@code access} may not use
 * this module), and read here as a use.
 *
 * <p><b>It reads no registry</b>, and must not: the registry asks it, through {@code NotificationChannelInUse}, while
 * the registry itself is being built, and a dependency back on it is a cycle the context refuses. The caller holds
 * each channel this answers ({@code Integrations.holdEnabled}).
 */
@Service
public class NotificationDestinations {

    /**
     * The settings each channel's destination is read from. The checklist reminders are mail's: they need no
     * recipient — each goes to an account's own address — but switching mail off under them would stop them
     * in silence, which is the loss the in-use refusal exists for.
     */
    private static final Map<NotificationChannelKind, List<Setting>> SETTINGS = settings();

    private final SettingsService settings;
    private final TeamChannels teams;

    public NotificationDestinations(SettingsService settings, TeamChannels teams) {
        this.settings = settings;
        this.teams = teams;
    }

    private static Map<NotificationChannelKind, List<Setting>> settings() {
        Map<NotificationChannelKind, List<Setting>> of = new EnumMap<>(NotificationChannelKind.class);
        of.put(NotificationChannelKind.WEBHOOK, List.of(Setting.WEBHOOK_URL));
        of.put(NotificationChannelKind.TEAMS, List.of(Setting.TEAMS_ENABLED, Setting.TEAMS_WEBHOOK_URL));
        of.put(NotificationChannelKind.SLACK, List.of(Setting.SLACK_WEBHOOK_URL));
        of.put(NotificationChannelKind.DISCORD, List.of(Setting.DISCORD_WEBHOOK_URL));
        of.put(NotificationChannelKind.MAIL, List.of(Setting.MAIL_RECIPIENTS, Setting.CHECKLIST_REMINDERS_ENABLED));
        return of;
    }

    /**
     * What gives the channel somewhere to send today, as phrases the refusal lists; empty when nothing does.
     *
     * <p>Read without the registry: a channel switched off by hand under a destination is still in use, and is
     * the case a governor most needs told. Teams needs its own switch and its URL, as it does to send.
     */
    @Transactional(readOnly = true)
    public List<String> uses(NotificationChannelKind kind) {
        List<String> uses = new ArrayList<>(uses(kind, settings::get));
        if (kind == NotificationChannelKind.WEBHOOK) {
            long withOne = teams.countWithChannel();
            if (withOne > 0) {
                uses.add(withOne == 1 ? "a team has a webhook of its own" : withOne + " teams have a webhook of their own");
            }
        }
        return List.copyOf(uses);
    }

    private static List<String> uses(NotificationChannelKind kind, Function<Setting, String> value) {
        List<String> uses = new ArrayList<>();
        switch (kind) {
            case WEBHOOK -> {
                if (set(value.apply(Setting.WEBHOOK_URL))) {
                    uses.add("the global webhook URL is set");
                }
            }
            case TEAMS -> {
                if ("true".equals(value.apply(Setting.TEAMS_ENABLED)) && set(value.apply(Setting.TEAMS_WEBHOOK_URL))) {
                    uses.add("the Microsoft Teams URL is set");
                }
            }
            case SLACK -> {
                if (set(value.apply(Setting.SLACK_WEBHOOK_URL))) {
                    uses.add("the Slack URL is set");
                }
            }
            case DISCORD -> {
                if (set(value.apply(Setting.DISCORD_WEBHOOK_URL))) {
                    uses.add("the Discord URL is set");
                }
            }
            case MAIL -> {
                if (set(value.apply(Setting.MAIL_RECIPIENTS))) {
                    uses.add("e-mail recipients are set");
                }
                if ("true".equals(value.apply(Setting.CHECKLIST_REMINDERS_ENABLED))) {
                    uses.add("the weekly checklist reminders are on");
                }
            }
        }
        return uses;
    }

    /**
     * The channels a settings save configures: one of their settings changed to a value that sends — a URL or a
     * recipient written, a switch turned on. Clearing one, or sending back the stored value, configures nothing:
     * a disabled channel is always emptied, and a screen saving its whole section is not refused for a channel
     * this save does not move.
     *
     * @param changes the values the save writes, trimmed
     */
    public Set<NotificationChannelKind> configuredBy(Map<Setting, String> changes) {
        Set<NotificationChannelKind> configured = EnumSet.noneOf(NotificationChannelKind.class);
        SETTINGS.forEach((kind, read) -> {
            for (Setting setting : read) {
                String value = changes.get(setting);
                if (value != null && set(value) && !"false".equals(value) && !value.equals(settings.get(setting).trim())) {
                    configured.add(kind);
                }
            }
        });
        return configured;
    }

    private static boolean set(String value) {
        return value != null && !value.isBlank();
    }
}
