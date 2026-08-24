package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Changing a monitored image.
 *
 * <p>There was no way to: create, scan and delete were the whole surface, so correcting a cron
 * expression on an image meant deleting the row — and its scan history and its triaged backlog
 * with it. The schedule became editable on the repository screen first, which made the gap worse
 * than a missing feature: the field was offered on both screens and fixable on one.
 */
@DisplayName("updating a container image")
class ContainerUpdateTest extends ApiTestBase {

    @Autowired
    private Containers containers;

    @Test
    @DisplayName("a schedule change round-trips, the row and its history staying put")
    void theScheduleRoundTrips() throws Exception {
        long id = seed();

        mvc.perform(authenticated(patch("/api/v1/containers/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("scanIntervalMinutes", 1440, "scanCron", "0 0 3 * * *"))))
                .andExpect(status().isOk())
                // The point of having an update at all: the same identifier, so the scans and the
                // triaged issues attached to it survive the correction.
                .andExpect(jsonPath("$.id").value((int) id))
                .andExpect(jsonPath("$.scanIntervalMinutes").value(1440))
                .andExpect(jsonPath("$.scanCron").value("0 0 3 * * *"));
    }

    @Test
    @DisplayName("leaves out what the request left out, instead of clearing it")
    void absentMeansUnchanged() throws Exception {
        long id = seed();

        // The trap this pins: a screen that edits one field sends one field. With the opposite
        // convention it would silently erase the schedule and the agent label — and nothing would
        // say so until a scan waited for an agent nobody requires any more.
        mvc.perform(authenticated(patch("/api/v1/containers/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("tag", "1.2.3"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tag").value("1.2.3"))
                .andExpect(jsonPath("$.scanIntervalMinutes").value(60))
                .andExpect(jsonPath("$.requiredAgentLabel").value("linux-x64"));
    }

    @Test
    @DisplayName("clears the cron on an empty string, and the interval on zero")
    void clearingTheSchedule() throws Exception {
        long id = seed("0 0 3 * * *");

        // The asymmetry the route's javadoc spells out: the empty string is distinguishable from
        // absent and clears the expression, but `null` on the interval already means "leave
        // alone", so switching a rescan off is spelled zero. An operator whose form sent nothing
        // would see an empty field and keep being scanned every hour.
        Map<String, Object> body = new HashMap<>();
        body.put("scanCron", "");
        body.put("scanIntervalMinutes", 0);
        mvc.perform(authenticated(patch("/api/v1/containers/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scanCron").doesNotExist())
                .andExpect(jsonPath("$.scanIntervalMinutes").value(0));
    }

    @Test
    @DisplayName("refuses an unusable cron expression, and changes nothing")
    void anInvalidCronIsRefused() throws Exception {
        long id = seed("0 0 3 * * *");

        mvc.perform(authenticated(patch("/api/v1/containers/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("scanCron", "nightly"))))
                .andExpect(status().isBadRequest());

        // Rejected at the entry point rather than at scheduling time: discovering that an
        // expression was refused by watching scans *not* happen is the expensive way.
        mvc.perform(authenticated(get("/api/v1/containers"), asAdmin()))
                .andExpect(jsonPath("$[0].scanCron").value("0 0 3 * * *"));
    }

    @Test
    @DisplayName("validates the reference on update exactly as on create")
    void theReferenceIsValidatedAgain() throws Exception {
        long id = seed();

        // A reference reaching a `docker pull` unchecked is whatever the daemon will fetch. A row
        // edited later is no safer than a row added.
        mvc.perform(authenticated(patch("/api/v1/containers/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("image_name", "Team/Service"))))
                .andExpect(status().isBadRequest());

        mvc.perform(authenticated(get("/api/v1/containers"), asAdmin()))
                .andExpect(jsonPath("$[0].imageName").value("team/service"));
    }

    @Test
    @DisplayName("is closed to an ordinary account, as the repository's is")
    void readersMayNotEdit() throws Exception {
        long id = seed();

        // Listing is any account's; changing what gets pulled and how often is an
        // administrator's. A route added later must not be the hole in that rule.
        mvc.perform(authenticated(patch("/api/v1/containers/" + id), asReader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("scanIntervalMinutes", 5))))
                .andExpect(status().isForbidden());
    }

    private long seed() {
        return seed(null);
    }

    private long seed(String cron) {
        ContainerEntity container = new ContainerEntity();
        container.setImageName("team/service");
        container.setTag("latest");
        container.setScanIntervalMinutes(60);
        container.setScanCron(cron);
        container.setRequiredAgentLabel("linux-x64");
        return containers.save(container).getId();
    }
}
