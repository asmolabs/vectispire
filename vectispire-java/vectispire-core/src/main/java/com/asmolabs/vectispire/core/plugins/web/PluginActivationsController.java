package com.asmolabs.vectispire.core.plugins.web;

import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.access.web.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.plugins.PluginActivationView;
import com.asmolabs.vectispire.core.plugins.PluginService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Which plugins analyse a project.
 *
 * <p><b>Switching a plugin on is governance work</b>, the decision activating a rule set is, scoped to
 * one project: {@code @RequiresSecurityLead} admits exactly the roles that {@code canWriteGovernance}
 * — the governor, an administrator, a CISO — each of whom sees the whole estate. Registering the code
 * was the governor's; deciding where it reads is theirs. Nothing is on by default.
 */
@Tag(name = "Plugins", description = "Third-party analysers run as containers, emitting SARIF")
@RestController
@RequestMapping("/api/v1/projects/{projectId}/plugins")
public class PluginActivationsController {

    private final PluginService plugins;

    public PluginActivationsController(PluginService plugins) {
        this.plugins = plugins;
    }

    @Operation(summary = "List plugins switched on for project", description = "404 when the project does not exist.")
    @GetMapping
    @RequiresGovernanceRead
    public List<PluginActivationView> list(@PathVariable long projectId) {
        return plugins.activations(projectId);
    }

    @Operation(summary = "Switch plugin on for project", description = "Its repositories run the plugin from the next "
            + "scan, where one of its languages is present. Repeating it changes nothing.")
    @PutMapping("/{pluginId}")
    @RequiresSecurityLead
    public PluginActivationView activate(
            @PathVariable long projectId,
            @PathVariable String pluginId,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return plugins.activate(projectId, pluginId, RequestActors.of(principal, request));
    }

    @Operation(summary = "Switch plugin off for project", description = "Its open issues are left as they are. 404 "
            + "when it was not on.")
    @DeleteMapping("/{pluginId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @RequiresSecurityLead
    public void deactivate(
            @PathVariable long projectId,
            @PathVariable String pluginId,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        plugins.deactivate(projectId, pluginId, RequestActors.of(principal, request));
    }
}
