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

    /** What this application's own sign-in page must render before {@link #startLogin}; empty until connected. */
    public Optional<LoginOptions> loginOptions() {
        return send("/login-flow/options", Map.of()).filter(response -> response.status() == 200)
            .map(response -> new LoginOptions(response.text("turnstileSiteKey"), response.text("turnstileAction")));
    }

    /**
     * Starts email sign-in on this application's own page. Identity answers {@code EMAIL_CODE} whether or not the
     * address has an account, and emails a code only when it may sign in.
     *
     * @param clientAddress IP address of the browser this request serves
     * @param turnstileToken token solved on this page when {@link #loginOptions()} names a site key, otherwise null
     */
    public LoginStep startLogin(String email, String clientAddress, String turnstileToken) {
        return loginStep("/login-flow/start", null, fields(
            "email", email, "clientAddress", clientAddress, "turnstileToken", turnstileToken));
    }

    /** Emails a fresh code for a started flow; Identity applies its cooldown and resend limit. */
    public LoginStep resendLoginCode(LoginFlow flow, String clientAddress, String turnstileToken) {
        return loginStep("/login-flow/resend", flow, fields(
            "clientAddress", clientAddress, "turnstileToken", turnstileToken));
    }

    /** Submits the emailed code; answers {@code TOTP} when the account has a second factor, otherwise {@code DONE}. */
    public LoginStep submitLoginCode(LoginFlow flow, String code, String clientAddress) {
        return loginStep("/login-flow/email-code", flow, fields("code", code, "clientAddress", clientAddress));
    }

    /** Submits the authenticator code of an account with a second factor. */
    public LoginStep submitAuthenticatorCode(LoginFlow flow, String code, String clientAddress) {
        return loginStep("/login-flow/totp", flow, fields("code", code, "clientAddress", clientAddress));
    }

    private LoginStep loginStep(String path, LoginFlow flow, Map<String, String> fields) {
        if (flow != null) {
            fields.put("flowId", flow.id().toString());
            fields.put("flowSecret", flow.secret());
        }
        Optional<Response> sent = send(path, fields);
        if (sent.isEmpty()) {
            return LoginStep.failed(LoginStep.NOT_CONNECTED);
        }
        Response response = sent.get();
        if (response.status() != 200) {
            return LoginStep.failed(response.text("error") == null ? LoginStep.LOGIN_FAILED : response.text("error"));
        }
        return switch (String.valueOf(response.text("next"))) {
            case "EMAIL_CODE" -> new LoginStep(LoginStep.Next.EMAIL_CODE, response.text("flowId") == null ? flow
                : new LoginFlow(UUID.fromString(response.text("flowId")), response.text("flowSecret")), null, null);
            case "TOTP" -> new LoginStep(LoginStep.Next.TOTP, flow, null, null);
            case "DONE" -> confirmed(new IdentitySession(
                user(response), response.text("sessionToken"), Instant.parse(response.text("expiresAt"))));
            default -> LoginStep.failed(LoginStep.LOGIN_FAILED);
        };
    }

    /** A session is handed to the application only after Identity confirms its token belongs to the same user. */
    private LoginStep confirmed(IdentitySession session) {
        return verify(session.token()).filter(user -> user.userId().equals(session.user().userId())).isPresent()
            ? new LoginStep(LoginStep.Next.DONE, null, session, null)
            : LoginStep.failed(LoginStep.LOGIN_FAILED);
    }

    private static Map<String, String> fields(String... namesAndValues) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (int index = 0; index < namesAndValues.length; index += 2) {
            if (namesAndValues[index + 1] != null) {
                fields.put(namesAndValues[index], namesAndValues[index + 1]);
            }
        }
        return fields;
    }

    private Optional<Response> call(String path, String field, String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        return send(path, Map.of(field, value)).filter(response -> response.status() == 200);
    }

    /** Identity's answer, or empty while this application is not connected. */
    private Optional<Response> send(String path, Map<String, String> fields) {
        // A refused key is retried once: another replica may have replaced it, or it was replaced before a crash.
        for (int attempt = 0; attempt < 2; attempt++) {
            Optional<Connection> connection = connections.connected();
            if (connection.isEmpty()) {
                return Optional.empty();
            }
            Map<String, String> body = new LinkedHashMap<>();
            body.put("appSlug", connection.get().appSlug());
            body.putAll(fields);
            Response response = client.post(path, connection.get().key(), body);
            if (!response.keyRefused()) {
                return Optional.of(response);
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
     * What this application's own sign-in page renders before starting email sign-in.
     *
     * @param turnstileSiteKey Cloudflare Turnstile site key the start requires, or null when it requires none
     * @param turnstileAction action the Turnstile widget must declare, or null
     */
    public record LoginOptions(String turnstileSiteKey, String turnstileAction) {
    }

    /**
     * One email sign-in in progress. Keep it server-side, such as in an HttpOnly cookie; it continues the sign-in.
     */
    public record LoginFlow(UUID id, String secret) {

        @Override
        public String toString() {
            return "LoginFlow[id=" + id + "]";
        }
    }

    /**
     * What Identity decided for one sign-in step: the next step, or the error that stopped this one.
     *
     * @param flow the flow to continue, until {@code DONE}
     * @param session the user's session in this application, once {@code DONE}
     * @param error Identity's error code, such as {@code INVALID_CODE}, {@code LOCKED} or {@code RATE_LIMITED}
     */
    public record LoginStep(Next next, LoginFlow flow, IdentitySession session, String error) {

        /** This application is not connected yet, so Identity cannot be asked. */
        public static final String NOT_CONNECTED = "NOT_CONNECTED";

        /** Identity gave no usable answer, or did not confirm the session it issued. */
        public static final String LOGIN_FAILED = "LOGIN_FAILED";

        static LoginStep failed(String error) {
            return new LoginStep(null, null, null, error);
        }

        public boolean failed() {
            return error != null;
        }

        /** The next thing the user does on this application's sign-in page. */
        public enum Next {
            EMAIL_CODE,
            TOTP,
            DONE
        }
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
