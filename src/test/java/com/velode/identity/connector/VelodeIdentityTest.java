package com.velode.identity.connector;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.velode.identity.connector.ConnectionManager.Connection;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Drives the connector against a stand-in for Identity that keeps only what Identity keeps: which keys are
 * waiting, which one is approved and which user tokens are valid.
 */
class VelodeIdentityTest {

    private static final String ORGANIZATION = "891602e0-f43a-41de-a768-281aeaf8b913";
    private static final String USER_ID = "5b4084b4-8c5c-47a5-a1e2-9d1654a7338b";
    private static final Instant NOW = Instant.parse("2026-10-12T10:00:00Z");

    private final Set<String> pendingKeys = new HashSet<>();
    private final List<String> requests = new ArrayList<>();
    private final MemoryStore store = new MemoryStore();
    private String approvedKey;
    private HttpServer identity;
    private MutableClock clock;
    private ConnectionManager connections;
    private VelodeIdentity velodeIdentity;

    @BeforeEach
    void startIdentity() throws IOException {
        identity = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        identity.createContext("/api/organizations/" + ORGANIZATION, this::answer);
        identity.start();
        clock = new MutableClock(NOW);
        connections = manager();
        velodeIdentity = new VelodeIdentity(properties(), connections, new IdentityClient(properties().apiUrl()));
    }

    @AfterEach
    void stopIdentity() {
        identity.stop(0);
    }

    @Test
    void should_AuthenticateUsersOnlyAfterAdministratorApproves() {
        connections.maintain();

        assertThat(velodeIdentity.isConnected()).isFalse();
        assertThat(velodeIdentity.loginUrl("state")).isEmpty();
        assertThat(velodeIdentity.verify("valid-token")).isEmpty();
        assertThat(pendingKeys).hasSize(1);
        assertThat(requests.getFirst())
            .contains("\"origin\":\"https://lista.velode.io\"", "\"name\":\"Lista \\\"beta\\\"\"");

        approve();
        connections.maintain();

        assertThat(velodeIdentity.loginUrl("a b")).contains(
            "http://localhost:" + identity.getAddress().getPort() + "/o/" + ORGANIZATION + "/login?appSlug=lista"
                + "&returnTo=https%3A%2F%2Flista.velode.io%2Fvelode-identity%2Fcallback&state=a+b");
        assertThat(velodeIdentity.verify("valid-token")).hasValueSatisfying(user -> {
            assertThat(user.userId()).hasToString(USER_ID);
            assertThat(user.email()).isEqualTo("user@velode.io");
        });
        assertThat(velodeIdentity.exchange("valid-code")).hasValueSatisfying(session -> {
            assertThat(session.token()).isEqualTo("valid-token");
            assertThat(session.expiresAt()).isEqualTo(NOW.plus(Duration.ofDays(1)));
            assertThat(session).hasToString("IdentitySession[user=" + session.user() + "]");
        });
        assertThat(velodeIdentity.verify("expired-token")).isEmpty();
        assertThat(velodeIdentity.isConnected()).isTrue();
    }

    @Test
    void should_ShareOneConnectionBetweenReplicas() {
        connections.maintain();
        ConnectionManager replica = manager();
        replica.maintain();

        assertThat(pendingKeys).hasSize(1);
        approve();
        replica.maintain();
        assertThat(replica.connected()).map(Connection::key).contains(approvedKey);
    }

    @Test
    void should_ReplaceItsKeyWhenDueAndLetOtherReplicasFollow() {
        connect();
        ConnectionManager replica = manager();
        replica.maintain();
        String firstKey = approvedKey;

        clock.advance(Duration.ofDays(29));
        connections.maintain();
        assertThat(approvedKey).isEqualTo(firstKey);

        clock.advance(Duration.ofDays(1));
        connections.maintain();
        assertThat(approvedKey).isNotEqualTo(firstKey);
        assertThat(connections.connected()).map(Connection::key).contains(approvedKey);

        VelodeIdentity replicaIdentity = new VelodeIdentity(properties(), replica, new IdentityClient(properties().apiUrl()));
        assertThat(replicaIdentity.verify("valid-token")).isPresent();
        assertThat(replica.connected()).map(Connection::key).contains(approvedKey);
    }

    @Test
    void should_KeepConnection_when_ItStoppedAfterIdentityAcceptedTheNewKey() {
        connect();
        Connection connected = connections.connected().orElseThrow();
        String acceptedKey = "N".repeat(43);
        store.save(new Connection(connected.key(), acceptedKey, connected.appSlug(), connected.rotatedAt()).encode());
        approvedKey = acceptedKey;

        assertThat(manager(velodeIdentity -> velodeIdentity.verify("valid-token"))).isPresent();
        assertThat(pendingKeys).isEmpty();
    }

    @Test
    void should_AskToConnectAgainWithNewKey_when_AdministratorDisconnects() {
        connect();
        String disconnectedKey = approvedKey;
        approvedKey = null;

        assertThat(velodeIdentity.verify("valid-token")).isEmpty();
        assertThat(velodeIdentity.isConnected()).isFalse();
        connections.maintain();

        assertThat(pendingKeys).hasSize(1).doesNotContain(disconnectedKey);
        approve();
        connections.maintain();
        assertThat(velodeIdentity.verify("valid-token")).isPresent();
    }

    private Optional<VelodeIdentity.IdentityUser> manager(
        java.util.function.Function<VelodeIdentity, Optional<VelodeIdentity.IdentityUser>> call
    ) {
        ConnectionManager restarted = manager();
        restarted.maintain();
        return call.apply(new VelodeIdentity(properties(), restarted, new IdentityClient(properties().apiUrl())));
    }

    private void connect() {
        connections.maintain();
        approve();
        connections.maintain();
        requests.clear();
    }

    private void approve() {
        approvedKey = pendingKeys.iterator().next();
        pendingKeys.clear();
    }

    private ConnectionManager manager() {
        return new ConnectionManager(
            properties(), "Lista \"beta\"", store, new IdentityClient(properties().apiUrl()), clock, new SecureRandom());
    }

    private VelodeIdentityProperties properties() {
        return new VelodeIdentityProperties(
            "http://localhost:" + identity.getAddress().getPort() + "/o/" + ORGANIZATION + "/", "https://lista.velode.io/", null, null);
    }

    private synchronized void answer(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath().substring(("/api/organizations/" + ORGANIZATION).length());
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String key = exchange.getRequestHeaders().getFirst("X-Server-API-Key");
        requests.add(body);
        if ("/connection".equals(path)) {
            String status = key.equals(approvedKey) ? "CONNECTED" : "PENDING";
            if ("PENDING".equals(status)) {
                pendingKeys.add(key);
            }
            assertThat(body).contains("\"key\":\"" + key + "\"");
            respond(exchange, 200, "{\"success\":true,\"data\":{\"status\":\"" + status + "\",\"code\":\"4F7-A92\""
                + ("CONNECTED".equals(status) ? ",\"appSlug\":\"lista\"" : ",\"appSlug\":null") + "}}");
        } else if (!key.equals(approvedKey)) {
            respond(exchange, 401, "{\"status\":401,\"error\":\"INVALID_CONNECTION_KEY\",\"message\":\"Invalid server API key\"}");
        } else if ("/connection/rotate".equals(path)) {
            approvedKey = body.replaceAll(".*\"newKey\":\"([^\"]+)\".*", "$1");
            respond(exchange, 204, "");
        } else if (body.contains("\"appSlug\":\"lista\"") && (body.contains("valid-token") || body.contains("valid-code"))) {
            respond(exchange, 200, "{\"success\":true,\"data\":{\"userId\":\"" + USER_ID + "\",\"email\":\"user@velode.io\","
                + "\"appSlug\":\"lista\",\"sessionToken\":\"valid-token\",\"expiresAt\":\"" + NOW.plus(Duration.ofDays(1)) + "\"}}");
        } else {
            respond(exchange, 401, "{\"status\":401,\"error\":\"UNAUTHORIZED\",\"message\":\"Invalid or expired token\"}");
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static final class MemoryStore implements ConnectionStore {

        private String value;

        @Override
        public synchronized Optional<String> load() {
            return Optional.ofNullable(value);
        }

        @Override
        public synchronized boolean create(String created) {
            if (value != null) {
                return false;
            }
            value = created;
            return true;
        }

        @Override
        public synchronized void save(String saved) {
            value = saved;
        }
    }

    private static final class MutableClock extends Clock {

        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
