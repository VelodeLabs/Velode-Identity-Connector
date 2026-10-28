package com.velode.identity.connector;

import com.velode.identity.connector.IdentityClient.Response;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;

/**
 * Owns the application's connection to Identity: creates its key, asks to be approved, notices the decision,
 * replaces the key periodically and asks again when an administrator disconnects the application.
 */
class ConnectionManager implements SmartLifecycle {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionManager.class);
    private static final Duration CHECK_INTERVAL = Duration.ofSeconds(10);

    private final VelodeIdentityProperties properties;
    private final String name;
    private final ConnectionStore store;
    private final IdentityClient client;
    private final Clock clock;
    private final SecureRandom random;

    private volatile Connection connection;
    private String announcedStatus;
    private ScheduledExecutorService scheduler;

    ConnectionManager(
        VelodeIdentityProperties properties,
        String name,
        ConnectionStore store,
        IdentityClient client,
        Clock clock,
        SecureRandom random
    ) {
        this.properties = properties;
        this.name = name;
        this.store = store;
        this.client = client;
        this.clock = clock;
        this.random = random;
    }

    @Override
    public synchronized void start() {
        scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "velode-identity-connection");
            thread.setDaemon(true);
            return thread;
        });
        scheduler.scheduleWithFixedDelay(this::maintainQuietly, 0, CHECK_INTERVAL.toSeconds(), TimeUnit.SECONDS);
    }

    @Override
    public synchronized void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
    }

    @Override
    public synchronized boolean isRunning() {
        return scheduler != null;
    }

    /** The key and application slug to call Identity with, once an administrator has approved the connection. */
    Optional<Connection> connected() {
        Connection current = connection;
        return current != null && current.appSlug() != null ? Optional.of(current) : Optional.empty();
    }

    private void maintainQuietly() {
        try {
            maintain();
        } catch (RuntimeException exception) {
            LOGGER.warn("Velode Identity connection check failed: {}", exception.getMessage());
        }
    }

    /** One step of the connection's life; safe to repeat and to run on several replicas. */
    synchronized void maintain() {
        connection = loadOrCreate();
        if (connection.appSlug() == null) {
            requestConnection();
        } else if (!connection.rotatedAt().plus(properties.keyRotation()).isAfter(clock.instant())) {
            rotateKey();
        }
    }

    /**
     * Called after Identity refuses the key. Another replica may have replaced it, a replacement may have been
     * accepted just before a crash, or an administrator may have disconnected the application.
     */
    synchronized void recover(Connection refused) {
        Connection stored = loadOrCreate();
        connection = stored;
        if (!stored.key().equals(refused.key())) {
            return;
        }
        if (stored.nextKey() != null) {
            save(stored, new Connection(stored.nextKey(), null, stored.appSlug(), clock.instant()));
        } else {
            LOGGER.warn("Velode Identity no longer accepts this application's connection; asking to connect again");
            if (save(stored, new Connection(newKey(), null, null, clock.instant()))) {
                announcedStatus = null;
            }
        }
    }

    private Connection loadOrCreate() {
        Optional<String> stored = store.load();
        if (stored.isEmpty() && store.create(new Connection(newKey(), null, null, clock.instant()).encode())) {
            stored = store.load();
        }
        return Connection.decode(stored.or(store::load).orElseThrow(
            () -> new IllegalStateException("The Velode Identity connection could not be stored")));
    }

    private void requestConnection() {
        Connection current = connection;
        Response response = status(current.key());
        String status = response.status() == 200 ? response.text("status") : "HTTP " + response.status();
        if ("CONNECTED".equals(status)) {
            if (!save(current, new Connection(current.key(), null, response.text("appSlug"), clock.instant()))) {
                return;
            }
            LOGGER.info("Connected to Velode Identity as application '{}'", connection.appSlug());
        } else if (!status.equals(announcedStatus)) {
            if ("PENDING".equals(status)) {
                LOGGER.info("Waiting for a Velode Identity administrator to approve this application. Code: {}",
                    response.text("code"));
            } else {
                LOGGER.warn("Velode Identity did not accept the connection request ({})", status);
            }
        }
        announcedStatus = status;
    }

    private Response status(String key) {
        return client.post("/connection", key, Map.of("origin", properties.appUrl(), "name", name, "key", key));
    }

    private void rotateKey() {
        Connection current = connection;
        Connection pending = current;
        if (current.nextKey() == null) {
            // Stored first so a crash after Identity accepts the key does not lose the connection.
            pending = new Connection(current.key(), newKey(), current.appSlug(), current.rotatedAt());
            if (!save(current, pending)) {
                return;
            }
        }
        Response response = client.post("/connection/rotate", pending.key(), Map.of("newKey", pending.nextKey()));
        if (response.status() == 204) {
            save(pending, new Connection(pending.nextKey(), null, pending.appSlug(), clock.instant()));
        } else if (response.keyRefused()) {
            recover(pending);
        } else {
            throw new IdentityUnavailableException(
                "Velode Identity answered " + response.status() + " to a key replacement", null);
        }
    }

    private boolean save(Connection expected, Connection updated) {
        if (!store.compareAndSet(expected.encode(), updated.encode())) {
            connection = loadOrCreate();
            return false;
        }
        connection = updated;
        return true;
    }

    private String newKey() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * What the connector remembers: its key, a replacement key in flight, and the application it was approved as.
     */
    record Connection(String key, String nextKey, String appSlug, Instant rotatedAt) {

        private static final String SEPARATOR = "|";

        String encode() {
            return String.join(SEPARATOR, key, nextKey == null ? "" : nextKey, appSlug == null ? "" : appSlug,
                Long.toString(rotatedAt.getEpochSecond()));
        }

        static Connection decode(String value) {
            String[] parts = value.split("\\" + SEPARATOR, -1);
            return new Connection(
                parts[0],
                parts[1].isEmpty() ? null : parts[1],
                parts[2].isEmpty() ? null : parts[2],
                Instant.ofEpochSecond(Long.parseLong(parts[3]))
            );
        }

        @Override
        public String toString() {
            return "Connection[appSlug=" + appSlug + "]";
        }
    }
}
