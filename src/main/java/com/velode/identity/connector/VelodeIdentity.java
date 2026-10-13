package com.velode.identity.connector;

import com.velode.identity.connector.ConnectionManager.Connection;
import com.velode.identity.connector.IdentityClient.Response;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * What a connected application asks Identity: where to send a user to sign in and who a session belongs to.
 * Identity only says who the user is and that they may enter this application; the application decides the rest.
 */
public class VelodeIdentity {

    /** Cookie in which the connector's web endpoints keep the user's application session token. */
    public static final String SESSION_COOKIE = "velode_identity_session_token";

    static final String CALLBACK_PATH = "/velode-identity/callback";

    private final VelodeIdentityProperties properties;
    private final ConnectionManager connections;
    private final IdentityClient client;

    VelodeIdentity(VelodeIdentityProperties properties, ConnectionManager connections, IdentityClient client) {
        this.properties = properties;
        this.connections = connections;
        this.client = client;
    }

    /** False until an administrator approves this application in the Identity panel. */
    public boolean isConnected() {
        return connections.connected().isPresent();
    }

    /** Identity's sign-in page; it returns the user to this application's callback with a one-time code. */
    public Optional<String> loginUrl(String state) {
        return connections.connected().map(connection -> properties.url() + "/login"
            + "?appSlug=" + encode(connection.appSlug())
            + "&returnTo=" + encode(properties.appUrl() + CALLBACK_PATH)
            + "&state=" + encode(state));
    }

    /** Trades the one-time code Identity appended to the callback for the user's session. */
    public Optional<IdentitySession> exchange(String code) {
        return call("/session/exchange", "code", code).map(response -> new IdentitySession(
            user(response), response.text("sessionToken"), Instant.parse(response.text("expiresAt"))));
    }

    /** The user a session token belongs to, while it is valid and the user may still enter this application. */
    public Optional<IdentityUser> verify(String token) {
        return call("/verify", "token", token).map(VelodeIdentity::user);
    }

    /** The user signed in through the connector's web endpoints, verified with Identity on every call. */
    public Optional<IdentityUser> currentUser(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        for (Cookie cookie : cookies) {
            if (SESSION_COOKIE.equals(cookie.getName())) {
                return verify(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    private Optional<Response> call(String path, String field, String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        // A refused key is retried once: another replica may have replaced it, or it was replaced before a crash.
        for (int attempt = 0; attempt < 2; attempt++) {
            Optional<Connection> connection = connections.connected();
            if (connection.isEmpty()) {
                return Optional.empty();
            }
            Map<String, String> body = new LinkedHashMap<>();
            body.put("appSlug", connection.get().appSlug());
            body.put(field, value);
            Response response = client.post(path, connection.get().key(), body);
            if (response.status() == 200) {
                return Optional.of(response);
            }
            if (!response.keyRefused()) {
                return Optional.empty();
            }
            connections.recover(connection.get());
        }
        return Optional.empty();
    }

    private static IdentityUser user(Response response) {
        return new IdentityUser(UUID.fromString(response.text("userId")), response.text("email"));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /**
     * A user Identity authenticated and admits to this application.
     *
     * @param userId immutable identifier to own the user's data with
     * @param email the user's primary email in the organization
     */
    public record IdentityUser(UUID userId, String email) {
    }

    /**
     * A user's session in this application.
     *
     * @param token opaque value to keep server-side or in an HttpOnly cookie and pass to {@link #verify(String)}
     */
    public record IdentitySession(IdentityUser user, String token, Instant expiresAt) {

        @Override
        public String toString() {
            return "IdentitySession[user=" + user + "]";
        }
    }
}
