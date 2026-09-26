package com.asmolabs.vectispire.core.inventory.web;

import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.inventory.InventoryQueryService;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * "Do we ship this library, and in which release?"
 *
 * <p><b>The question the backlog cannot answer.</b> An issue exists only where something is
 * wrong, so searching issues finds the projects with a <em>vulnerable</em> log4j — and the day a
 * vulnerability is published, no scanner knows about it yet and every backlog is silent on
 * exactly the component being asked about. The inventory is the component list itself, flagged
 * or not.
 *
 * <p><b>The project's own version is the point of the answer, not decoration.</b> "Yes, we use
 * it" leaves the work undone; "it went out in 1.17.6 and is gone from 1.18.0" is what lets
 * somebody name the affected deliveries. That is why every row carries the version the scan read
 * from the project's manifest, beside the version of the component itself.
 */
@RestController
@RequestMapping("/api/v1/inventory")
@RequiresAccount
public class InventoryController {

    private final InventoryQueryService inventory;
    private final VisibilityService visibility;

    public InventoryController(InventoryQueryService inventory, VisibilityService visibility) {
        this.inventory = inventory;
        this.visibility = visibility;
    }

    @GetMapping("/search")
    public InventoryQueryService.Results search(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam String name,
            @RequestParam(required = false) String version) {

        return inventory.search(
                name, version, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

    /**
     * The versions of one component the caller may see, for the screen's second field.
     *
     * <p><b>Scoped like {@code search}, and it was not.</b> This route used to select distinct
     * versions with no join and no principal, so it answered for the whole estate: a reader given
     * one repository could ask "does anyone here run log4j 2.14.1" and be told, without reaching a
     * single target. A version list is a smaller disclosure than an occurrence list, and it is the
     * same disclosure in kind — it says who is exposed, which is the question this product exists
     * to answer and therefore the one worth asking without permission.
     *
     * <p>Filtered after the query rather than in SQL, for the reason {@code search} gives: the
     * restriction is a set of targets, and expressing it twice is how the two drift apart.
     */
    @GetMapping("/versions")
    public List<String> versions(
            @AuthenticationPrincipal VectispirePrincipal principal, @RequestParam String name) {
        return inventory.versions(name, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }
}
