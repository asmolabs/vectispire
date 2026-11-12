package com.asmolabs.vectispire.common.domain.targets;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

/**
 * What {@link RepositoryUrl} answers for the URLs that tell two URL parsers apart — the Rust agent's
 * {@code repository_url} module reads it as the reference (see {@code ReferenceSet}).
 *
 * <p>The inputs are the Rust side's list, {@code repository-url/inputs.json}: whoever finds a URL the
 * two read differently adds it there, and this test writes the answer the Rust side must give.
 */
class RepositoryUrlReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void theAnswersTheRustPortIsHeldTo() throws Exception {
        ArrayNode inputs = (ArrayNode) JSON.readTree(ReferenceSet.read("repository-url/inputs.json"));
        ArrayNode answers = JSON.createArrayNode();
        for (var input : inputs) {
            String url = input.asText();
            ObjectNode answer = answers.addObject();
            answer.put("url", url);
            answer.put("validate", RepositoryUrl.validate(url).orElse(null));
            answer.put("host", RepositoryUrl.host(url).orElse(null));
            answer.put("redact", RepositoryUrl.redact(url));
            answer.put("is_https", RepositoryUrl.isHttps(url));
            answer.put("has_host_gitlab_example_org", RepositoryUrl.hasHost(url, "gitlab.example.org"));
        }
        ReferenceSet.expect("repository-url/expected.json", JSON.writeValueAsString(answers) + "\n");
    }
}
