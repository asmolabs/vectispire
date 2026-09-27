package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.github.dockerjava.transport.DockerHttpClient;
import com.github.dockerjava.transport.DockerHttpClient.Request;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * The header that keeps a request off a connection the socket proxy has closed. What it prevents —
 * the first {@code POST} after ten idle seconds failing — is {@code SocketProxyIntegrationTest}'s,
 * against the proxy itself; this is what is sent.
 */
@DisplayName("one request per connection to the daemon")
class OneRequestPerConnectionTest {

    @Test
    @DisplayName("an ordinary request asks for its connection to be closed, and keeps everything else")
    void closes() {
        DockerHttpClient delegate = mock(DockerHttpClient.class);
        Request create = Request.builder()
                .method(Request.Method.POST)
                .path("/v1.45/containers/create")
                .putHeader("Content-Type", "application/json")
                .bodyBytes("{}".getBytes(StandardCharsets.UTF_8))
                .build();

        new OneRequestPerConnection(delegate).execute(create);

        ArgumentCaptor<Request> sent = ArgumentCaptor.forClass(Request.class);
        verify(delegate).execute(sent.capture());
        assertThat(sent.getValue().headers()).containsEntry("Connection", "close")
                .containsEntry("Content-Type", "application/json");
        assertThat(sent.getValue().method()).isEqualTo("POST");
        assertThat(sent.getValue().path()).isEqualTo("/v1.45/containers/create");
        assertThat(sent.getValue().bodyBytes()).isEqualTo("{}".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("an upgraded request, or one that already says, is left as it is")
    void leavesUpgradesAlone() {
        Request attach = Request.builder()
                .method(Request.Method.POST)
                .path("/containers/x/attach")
                .hijackedInput(new ByteArrayInputStream(new byte[0]))
                .build();
        Request named = Request.builder().method(Request.Method.GET).path("/_ping").putHeader("connection", "keep-alive").build();

        assertThat(OneRequestPerConnection.closing(attach)).isSameAs(attach);
        assertThat(OneRequestPerConnection.closing(named)).isSameAs(named);
    }
}
