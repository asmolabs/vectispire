package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.checklists.InvalidTemplateException;
import com.asmolabs.vectispire.core.checklists.internal.StoredForms;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionRepository;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * The trial rendering's verdict on each published version ({@link ChecklistTemplateService#trial}), tried
 * once per version and kept — for the versions a project is offered and for the one it opens or moves to.
 *
 * <p><b>Kept because a published version's workbook never changes</b>, nor its layout or its lines: the
 * verdict on one is the verdict for good, and rendering every published workbook at every read of the
 * offered versions would cost a full rendering per version per screen opened.
 *
 * <p><b>In memory rather than in a column.</b> The verdict is the workbook's <em>and this renderer's</em>: a
 * release whose renderer learns to write a shared formula's master would find a stored "unrenderable"
 * still refusing the version. Kept by the process, it is tried again by the next release on its first
 * read, and by nothing else. What that costs is one rendering per published version per process started,
 * on the first read that needs it; the published versions are a handful per template.
 *
 * <p><b>Keyed by the version's id and checked against its workbook's digest</b>: an id is never reused by
 * the engines deployed, and the digest is a second key that costs nothing to compare, read with the
 * summary the offered list reads anyway. A draft is never kept — its layout still changes — so the
 * publication's own trial does not go through here.
 */
@Component
class VersionTrials {

    /** What the trial found for one workbook: what refused it, or empty when a sign-off could fill it in. */
    private record Verdict(String sourceSha256, Optional<InvalidTemplateException> refusal) {}

    private final ChecklistTemplateVersionRepository versions;
    private final ChecklistItemRepository items;
    private final StoredForms forms;
    private final Map<Long, Verdict> verdicts = new ConcurrentHashMap<>();

    VersionTrials(ChecklistTemplateVersionRepository versions, ChecklistItemRepository items, StoredForms forms) {
        this.versions = versions;
        this.items = items;
        this.forms = forms;
    }

    /**
     * What refused a published version's trial rendering, read from its id and digest — the offered list
     * holds no workbook — and the version read only when no verdict is kept for it.
     */
    Optional<InvalidTemplateException> refusal(long versionId, String sourceSha256) {
        Verdict kept = verdicts.get(versionId);
        if (kept != null && kept.sourceSha256().equals(sourceSha256)) {
            return kept.refusal();
        }
        return versions.findById(versionId).map(this::refusal).orElse(Optional.empty());
    }

    /** What refused a published version's trial rendering, the version already read. */
    Optional<InvalidTemplateException> refusal(ChecklistTemplateVersionEntity version) {
        Verdict kept = verdicts.get(version.getId());
        if (kept != null && kept.sourceSha256().equals(version.getSourceSha256())) {
            return kept.refusal();
        }
        // Outside any lock: two readers meeting an untried version may both render it, and agree. A
        // rendering inside computeIfAbsent would hold every other version of the bin behind it.
        Optional<InvalidTemplateException> refusal = ChecklistTemplateService.trial(version,
                forms.layout(version.getLayout()),
                items.findByVersionIdOrderByPositionAsc(version.getId()).stream()
                        .map(ChecklistTemplateService::domain).toList());
        verdicts.put(version.getId(), new Verdict(version.getSourceSha256(), refusal));
        return refusal;
    }
}
