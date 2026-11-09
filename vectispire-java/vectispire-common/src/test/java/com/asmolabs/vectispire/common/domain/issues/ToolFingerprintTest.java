package com.asmolabs.vectispire.common.domain.issues;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The identity of a plugin's or an imported finding: rule, normalised path, tool — and nothing that
 * changes when the tool is upgraded. A data contract, like the rest of the fingerprint.
 */
@DisplayName("the fingerprint of a plugin or imported finding")
class ToolFingerprintTest {

    private static final ScanTarget REPO = new ScanTarget.Repository(3);

    private static String plugin(String id, String rule, String path) {
        return IssueFingerprint.ofTool(REPO, FindingType.PLUGIN, ToolKeys.plugin(id), rule, path);
    }

    /**
     * Pinned twice: as the formula, field by field, and as the value — computed outside the JVM
     * ({@code sha256("repo:3\0plugin\0ACME001\0plugin:acme-lint\0src/a.py")}) on 27 September 2026.
     * If this fails, the fix is not to update the constant; see {@code IssueFingerprintTest}.
     */
    @Test
    @DisplayName("is the one formula, with the tool key where the package would be")
    void theFormula() {
        assertThat(plugin("acme-lint", "ACME001", "src/a.py"))
                .isEqualTo(Digests.sha256Fields("repo:3", "plugin", "ACME001", "plugin:acme-lint", "src/a.py"))
                .isEqualTo("0567801c19c95ed638d202997c7ecc672a4b90e94bf9c0a5277bea636e22e616");
    }

    @Test
    @DisplayName("the plugin's image and version are not in it: an upgrade keeps the triage")
    void versionIsNotIdentity() {
        // Nothing about the image can reach the fingerprint: the only inputs are the target, the
        // type, the rule, the tool key — built from the plugin id alone — and the path.
        assertThat(ToolKeys.plugin("acme-lint")).isEqualTo("plugin:acme-lint");
        assertThat(plugin("acme-lint", "ACME001", "src/a.py")).isEqualTo(plugin("acme-lint", "ACME001", "src/a.py"));
    }

    @Test
    @DisplayName("renaming the plugin, the rule or the file is a different issue")
    void whatSeparates() {
        String base = plugin("acme-lint", "ACME001", "src/a.py");

        assertThat(plugin("acme-lint-2", "ACME001", "src/a.py")).isNotEqualTo(base);
        assertThat(plugin("acme-lint", "ACME002", "src/a.py")).isNotEqualTo(base);
        assertThat(plugin("acme-lint", "ACME001", "src/b.py")).isNotEqualTo(base);
    }

    @Test
    @DisplayName("two tools reporting the same rule on the same file are two issues")
    void toolsDoNotCollide() {
        assertThat(plugin("one", "CKV_AWS_20", "main.tf")).isNotEqualTo(plugin("two", "CKV_AWS_20", "main.tf"));
    }

    @Test
    @DisplayName("an executed plugin and an imported report never share an issue, even on the same tool name")
    void provenanceSeparates() {
        String imported = IssueFingerprint.ofTool(REPO, FindingType.IMPORTED, ToolKeys.imported("ci", "acme-lint"),
                "ACME001", "src/a.py");

        assertThat(imported).isNotEqualTo(plugin("acme-lint", "ACME001", "src/a.py"));
    }

    @Test
    @DisplayName("an imported tool's name is compared without case and its version is not in the key")
    void importedKey() {
        assertThat(ToolKeys.imported("ci-main", " ESLint ")).isEqualTo("import:ci-main/eslint");
        assertThat(ToolKeys.imported("ci-main", "eslint")).isEqualTo(ToolKeys.imported("ci-main", "ESLINT"));
    }

    @Test
    @DisplayName("a tool-scoped type needs its tool, and only a tool-scoped type is fingerprinted by one")
    void guards() {
        assertThatThrownBy(() -> IssueFingerprint.ofTool(REPO, FindingType.PLUGIN, " ", "r", "f"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> IssueFingerprint.ofTool(REPO, FindingType.SAST, "plugin:x", "r", "f"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(FindingType.PLUGIN.toolScoped()).isTrue();
        assertThat(FindingType.IMPORTED.toolScoped()).isTrue();
        assertThat(FindingType.SAST.toolScoped()).isFalse();
    }
}
