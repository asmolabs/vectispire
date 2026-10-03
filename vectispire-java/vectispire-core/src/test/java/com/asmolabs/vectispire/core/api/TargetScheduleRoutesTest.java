package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * A target's schedule through the routes: the default, a custom interval, a cron expression, and
 * manual only — what the add and edit forms send, and what the lists read back (0.11.0).
 *
 * <p>The schedule in force is the server's answer ({@code schedule}), so that no screen holds a copy
 * of the precedence rule — the lists used to, and said "manual only" for a target that the default
 * now scans weekly.
 */
@DisplayName("a target's schedule, through the routes")
class TargetScheduleRoutesTest extends ApiTestBase {

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("a repository added with no schedule runs on the default, a week, and says so")
    void addedWithNothingIsTheDefault() throws Exception {
        mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("url", "https://github.com/example/weekly.git", "branch", "main"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scanManualOnly").value(false))
                .andExpect(jsonPath("$.schedule.mode").value("default"))
                .andExpect(jsonPath("$.schedule.intervalMinutes").value(7 * 24 * 60));
    }

    @Test
    @DisplayName("the default the lists show follows the setting, and a default of zero shows none")
    void theDefaultFollowsTheSetting() throws Exception {
        repository(Map.of());

        settings.set(Setting.SCAN_DEFAULT_INTERVAL_DAYS, "1");
        mvc.perform(authenticated(get("/api/v1/repositories"), asReader()))
                .andExpect(jsonPath("$[0].schedule.intervalMinutes").value(1440));

        settings.set(Setting.SCAN_DEFAULT_INTERVAL_DAYS, "0");
        mvc.perform(authenticated(get("/api/v1/repositories"), asReader()))
                .andExpect(jsonPath("$[0].schedule.mode").value("default"))
                .andExpect(jsonPath("$[0].schedule.intervalMinutes").doesNotExist());
    }

    @Test
    @DisplayName("a custom interval and a cron expression are in force as they always were")
    void customAndCron() throws Exception {
        long id = repository(Map.of("scanIntervalMinutes", 360));
        mvc.perform(authenticated(get("/api/v1/repositories"), asReader()))
                .andExpect(jsonPath("$[0].schedule.mode").value("interval"))
                .andExpect(jsonPath("$[0].schedule.intervalMinutes").value(360));

        patchRepository(id, Map.of("scanCron", "0 2 * * *"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.schedule.mode").value("cron"))
                .andExpect(jsonPath("$.schedule.intervalMinutes").doesNotExist());
    }

    @Test
    @DisplayName("manual only clears the interval and the expression, and is never the default")
    void manualOnly() throws Exception {
        long id = repository(Map.of("scanIntervalMinutes", 360, "scanCron", "0 2 * * *"));

        patchRepository(id, Map.of("scanManualOnly", true, "scanIntervalMinutes", 0, "scanCron", ""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scanManualOnly").value(true))
                .andExpect(jsonPath("$.scanIntervalMinutes").doesNotExist())
                .andExpect(jsonPath("$.scanCron").doesNotExist())
                .andExpect(jsonPath("$.schedule.mode").value("manual"))
                .andExpect(jsonPath("$.schedule.intervalMinutes").doesNotExist());

        // Sent alone, as an API caller would: the row still never holds both.
        long other = repository(Map.of("scanIntervalMinutes", 60));
        patchRepository(other, Map.of("scanManualOnly", true))
                .andExpect(jsonPath("$.scanIntervalMinutes").doesNotExist())
                .andExpect(jsonPath("$.schedule.mode").value("manual"));
    }

    @Test
    @DisplayName("an edit that names a schedule takes the target out of manual only; one that names nothing leaves it")
    void aScheduleLeavesManualOnly() throws Exception {
        long id = repository(Map.of("scanManualOnly", true));

        patchRepository(id, Map.of("name", "renamed"))
                .andExpect(jsonPath("$.schedule.mode").value("manual"));
        patchRepository(id, Map.of("scanIntervalMinutes", 120))
                .andExpect(jsonPath("$.scanManualOnly").value(false))
                .andExpect(jsonPath("$.schedule.mode").value("interval"));
        patchRepository(id, Map.of("scanManualOnly", true))
                .andExpect(jsonPath("$.schedule.mode").value("manual"));
        patchRepository(id, Map.of("scanManualOnly", false))
                .andExpect(jsonPath("$.schedule.mode").value("default"));
    }

    @Test
    @DisplayName("manual only beside an interval or an expression is refused in words, and changes nothing")
    void bothAreRefused() throws Exception {
        long id = repository(Map.of("scanIntervalMinutes", 60));

        MvcResult refused = patchRepository(id, Map.of("scanManualOnly", true, "scanIntervalMinutes", 30))
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(detailOf(refused)).contains("manual only");
        patchRepository(id, Map.of("scanManualOnly", true, "scanCron", "0 2 * * *"))
                .andExpect(status().isBadRequest());

        mvc.perform(authenticated(get("/api/v1/repositories"), asReader()))
                .andExpect(jsonPath("$[0].scanIntervalMinutes").value(60))
                .andExpect(jsonPath("$[0].scanManualOnly").value(false));
    }

    @Test
    @DisplayName("a negative interval is refused in words rather than stored")
    void aNegativeIntervalIsRefused() throws Exception {
        mvc.perform(authenticated(post("/api/v1/containers"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("image_name", "team/service", "scanIntervalMinutes", -5))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("an image has the same four choices")
    void images() throws Exception {
        MvcResult created = mvc.perform(authenticated(post("/api/v1/containers"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("image_name", "team/service", "tag", "1.0.0"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.schedule.mode").value("default"))
                .andExpect(jsonPath("$.schedule.intervalMinutes").value(7 * 24 * 60))
                .andReturn();
        long id = json.readTree(created.getResponse().getContentAsString()).get("id").asLong();

        Map<String, Object> manual = new HashMap<>();
        manual.put("scanManualOnly", true);
        mvc.perform(authenticated(patch("/api/v1/containers/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(manual)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scanManualOnly").value(true))
                .andExpect(jsonPath("$.schedule.mode").value("manual"));
    }

    private long repository(Map<String, Object> schedule) throws Exception {
        Map<String, Object> body = new HashMap<>(schedule);
        body.put("url", "https://github.com/example/service-" + System.nanoTime() + ".git");
        body.put("branch", "main");
        MvcResult created = mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andExpect(status().isOk())
                .andReturn();
        return json.readTree(created.getResponse().getContentAsString()).get("id").asLong();
    }

    private org.springframework.test.web.servlet.ResultActions patchRepository(long id, Map<String, Object> body)
            throws Exception {
        return mvc.perform(authenticated(patch("/api/v1/repositories/" + id), asAdmin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(body)));
    }
}
