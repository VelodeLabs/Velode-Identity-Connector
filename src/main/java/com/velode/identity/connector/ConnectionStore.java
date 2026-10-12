package com.velode.identity.connector;

import java.util.Optional;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Keeps the connector's own connection where every replica of the application can read it.
 */
public interface ConnectionStore {

    Optional<String> load();

    /** Stores the first value only; returns false when another replica already stored one. */
    boolean create(String value);

    void save(String value);

    /**
     * One row per connection in a table the connector creates in the application's database.
     */
    final class Jdbc implements ConnectionStore {

        private final JdbcTemplate jdbc;
        private final String id;

        public Jdbc(JdbcTemplate jdbc, String id) {
            this.jdbc = jdbc;
            this.id = id;
            jdbc.execute("""
                CREATE TABLE IF NOT EXISTS velode_identity_connection (
                    id VARCHAR(64) NOT NULL PRIMARY KEY,
                    connection VARCHAR(512) NOT NULL
                )
                """);
        }

        @Override
        public Optional<String> load() {
            return jdbc.queryForList("SELECT connection FROM velode_identity_connection WHERE id = ?", String.class, id)
                .stream().findFirst();
        }

        @Override
        public boolean create(String value) {
            try {
                jdbc.update("INSERT INTO velode_identity_connection (id, connection) VALUES (?, ?)", id, value);
                return true;
            } catch (DuplicateKeyException exception) {
                return false;
            }
        }

        @Override
        public void save(String value) {
            jdbc.update("UPDATE velode_identity_connection SET connection = ? WHERE id = ?", value, id);
        }
    }

    /**
     * One Redis key per connection.
     */
    final class Redis implements ConnectionStore {

        private final StringRedisTemplate redis;
        private final String key;

        public Redis(StringRedisTemplate redis, String id) {
            this.redis = redis;
            this.key = "velode:identity:connection:" + id;
        }

        @Override
        public Optional<String> load() {
            return Optional.ofNullable(redis.opsForValue().get(key));
        }

        @Override
        public boolean create(String value) {
            return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(key, value));
        }

        @Override
        public void save(String value) {
            redis.opsForValue().set(key, value);
        }
    }
}
