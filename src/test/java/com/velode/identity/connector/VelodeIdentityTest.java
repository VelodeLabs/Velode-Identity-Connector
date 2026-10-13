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
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
    private volatile String approvedKey;
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
        clock.advance(Duration.ofDays(30));
        store.beforeCompareAndSet = (expected, updated) -> {
            if (expected.nextKey() != null && updated.nextKey() == null) {
                throw new IllegalStateException("Stopped before persisting the accepted key");
            }
        };

        assertThatThrownBy(connections::maintain).isInstanceOf(IllegalStateException.class);
        assertThat(store.load().map(Connection::decode)).map(Connection::nextKey).contains(approvedKey);
        store.beforeCompareAndSet = (expected, updated) -> { };

        assertThat(manager(identity -> identity.verify("valid-token"))).isPresent();
        assertThat(pendingKeys).isEmpty();
    }

    @Test
    void should_ShareOneCandidate_when_TwoReplicasRotateSimultaneously() throws Exception {
        connect();
        ConnectionManager replica = manager();
        replica.maintain();
        String previousKey = approvedKey;
        clock.advance(Duration.ofDays(30));
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch release = new CountDownLatch(1);
        store.beforeCompareAndSet = (expected, updated) -> {
            if (expected.nextKey() == null && updated.nextKey() != null) {
                ready.countDown();
                await(release);
            }
        };
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> first = executor.submit(connections::maintain);
            Future<?> second = executor.submit(replica::maintain);
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            release.countDown();
            first.get(10, TimeUnit.SECONDS);
            second.get(10, TimeUnit.SECONDS);
        } finally {
            release.countDown();
            executor.shutdownNow();
        }

        connections.maintain();
        replica.maintain();
        assertThat(approvedKey).isNotEqualTo(previousKey);
        assertThat(connections.connected()).map(Connection::key).contains(approvedKey);
        assertThat(replica.connected()).map(Connection::key).contains(approvedKey);
        assertThat(velodeIdentity.verify("valid-token")).isPresent();
        assertThat(new VelodeIdentity(properties(), replica, new IdentityClient(properties().apiUrl()))
            .verify("valid-token")).isPresent();
        assertThat(pendingKeys).isEmpty();
    }

    @Test
    void should_IgnoreLateConfirmation_when_AnotherReplicaAlreadyRotatedAgain() throws Exception {
        connect();
        ConnectionManager replica = manager();
        replica.maintain();
        clock.advance(Duration.ofDays(30));
        CountDownLatch confirmationReady = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<Thread> delayedThread = new AtomicReference<>();
        store.beforeCompareAndSet = (expected, updated) -> {
            if (Thread.currentThread() == delayedThread.get()
                && expected.nextKey() != null && updated.nextKey() == null) {
                confirmationReady.countDown();
                await(release);
            }
        };
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<?> delayed = executor.submit(() -> {
                delayedThread.set(Thread.currentThread());
                connections.maintain();
            });
            assertThat(confirmationReady.await(10, TimeUnit.SECONDS)).isTrue();
            String firstReplacement = approvedKey;
            replica.maintain();
            clock.advance(Duration.ofDays(30));
            replica.maintain();
            assertThat(approvedKey).isNotEqualTo(firstReplacement);
            release.countDown();
            delayed.get(10, TimeUnit.SECONDS);
        } finally {
            release.countDown();
            executor.shutdownNow();
        }

        assertThat(store.load().map(Connection::decode)).map(Connection::key).contains(approvedKey);
        assertThat(connections.connected()).map(Connection::key).contains(approvedKey);
        assertThat(replica.connected()).map(Connection::key).contains(approvedKey);
        assertThat(velodeIdentity.verify("valid-token")).isPresent();
        assertThat(pendingKeys).isEmpty();
    }

    @Test
    void should_ShareOneReconnection_when_TwoReplicasRecoverSimultaneously() throws Exception {
        connect();
        ConnectionManager replica = manager();
        replica.maintain();
        VelodeIdentity replicaIdentity = new VelodeIdentity(properties(), replica, new IdentityClient(properties().apiUrl()));
        approvedKey = null;
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch release = new CountDownLatch(1);
        store.beforeCompareAndSet = (expected, updated) -> {
            if (expected.appSlug() != null && updated.appSlug() == null) {
                ready.countDown();
                await(release);
            }
        };
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> first = executor.submit(() -> velodeIdentity.verify("valid-token"));
            Future<?> second = executor.submit(() -> replicaIdentity.verify("valid-token"));
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            release.countDown();
            first.get(10, TimeUnit.SECONDS);
            second.get(10, TimeUnit.SECONDS);
        } finally {
            release.countDown();
            executor.shutdownNow();
        }

        connections.maintain();
        replica.maintain();
        assertThat(pendingKeys).hasSize(1);
        approve();
        connections.maintain();
        replica.maintain();
        assertThat(velodeIdentity.verify("valid-token")).isPresent();
        assertThat(replicaIdentity.verify("valid-token")).isPresent();
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
        String key = exchange.getRequestHeaders().getFirst("X-Server-Connection-Key");
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
            respond(exchange, 401, "{\"status\":401,\"error\":\"INVALID_CONNECTION_KEY\",\"message\":\"Invalid server connection key\"}");
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

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out coordinating replicas");
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted coordinating replicas", exception);
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
        private volatile BiConsumer<Connection, Connection> beforeCompareAndSet = (expected, updated) -> { };

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
        public boolean compareAndSet(String expected, String updated) {
            beforeCompareAndSet.accept(Connection.decode(expected), Connection.decode(updated));
            synchronized (this) {
                if (!Objects.equals(value, expected)) {
                    return false;
                }
                value = updated;
                return true;
            }
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
