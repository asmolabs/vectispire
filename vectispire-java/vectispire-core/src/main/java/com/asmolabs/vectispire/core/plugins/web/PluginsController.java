package com.asmolabs.vectispire.core.plugins.web;

import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.access.web.security.RequiresPlatformGovernor;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.plugins.PluginActivationView;
import com.asmolabs.vectispire.core.plugins.PluginService;
import com.asmolabs.vectispire.core.plugins.PluginView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * The plugin registry (decision 0017, amended).
 *
 * <p><b>Registering and changing a plugin is the platform governor's alone</b>, and not an
 * administrator's: a plugin is third-party code that will read the source of every project it is
 * switched on for, and deciding that such code may exist here is a rule, not a task. Reading the
 * registry is anybody's who is signed in: a definition names an image, its arguments and its
 * languages — platform configuration, no target, nothing of anybody's estate. Which projects a plugin
 * reads is governance, and answered to the roles that see the whole estate.
 *
 * <p>There is no delete: a plugin's id names every issue it ever opened, and other code registered
 * under it would inherit their triage. A plugin that should stop is disabled.
 */
@Tag(name = "Plugins", description = "Third-party analysers run as containers, emitting SARIF")
@RestController
@RequestMapping("/api/v1/plugins")
public class PluginsController {

    private final PluginService plugins;

    public PluginsController(PluginService plugins) {
        this.plugins = plugins;
    }

    /** @param enabled false stops every activation of the plugin at the next scan; they are kept */
    public record PluginEnabled(boolean enabled) {}

    @Operation(summary = "List plugins", description = "Every registered plugin, with the manifest it runs.")
    @GetMapping
    @RequiresAccount
    public List<PluginView> list() {
        return plugins.list();
    }

    @Operation(summary = "Read plugin")
    @GetMapping("/{id}")
    @RequiresAccount
    public PluginView get(@PathVariable String id) {
        return plugins.get(id);
    }

    @Operation(summary = "Register plugin", description = "Platform governor only. The image is pinned by digest; "
            + "the id is never reused. 409 when the id is taken.")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPlatformGovernor
    public PluginView register(
            @RequestBody PluginManifest manifest,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return plugins.register(manifest, RequestActors.of(principal, request));
    }

    @Operation(summary = "Update plugin", description = "Platform governor only. A new manifest under the same id — "
            + "a new image version keeps the id, and with it every issue's triage.")
    @PutMapping("/{id}")
    @RequiresPlatformGovernor
    public PluginView update(
            @PathVariable String id,
            @RequestBody PluginManifest manifest,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return plugins.update(id, manifest, RequestActors.of(principal, request));
    }

    @Operation(summary = "Enable or disable plugin", description = "Platform governor only. Disabling stops every "
            + "activation from the next scan without forgetting them.")
    @PutMapping("/{id}/enabled")
    @RequiresPlatformGovernor
    public PluginView setEnabled(
            @PathVariable String id,
            @RequestBody PluginEnabled body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        if (body == null) {
            throw new IllegalArgumentException("Say whether the plugin is enabled.");
        }
        return plugins.setEnabled(id, body.enabled(), RequestActors.of(principal, request));
    }

    @Operation(summary = "List projects a plugin analyses")
    @GetMapping("/{id}/projects")
    @RequiresGovernanceRead
    public List<PluginActivationView> projects(@PathVariable String id) {
        return plugins.activationsOf(id);
    }
}
