package com.velode.identity.connector;

import com.velode.identity.connector.VelodeIdentity.IdentitySession;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * Serves the application's sign-in, callback and sign-out addresses so it only has to link to them.
 */
class VelodeIdentityFilter extends HttpFilter {

    static final String LOGIN_PATH = "/velode-identity/login";
    static final String LOGOUT_PATH = "/velode-identity/logout";

    private static final long serialVersionUID = 1L;
    private static final String CODE_PARAMETER = "velode_identity_code";
    private static final String STATE_PARAMETER = "velode_identity_state";
    private static final String RETURN_PARAMETER = "returnTo";
    private static final String STATE_COOKIE = "velode_identity_state";
    private static final Duration STATE_TTL = Duration.ofMinutes(10);
    private static final String HOME = "/";

    private final transient VelodeIdentity identity;
    private final transient SecureRandom random;

    VelodeIdentityFilter(VelodeIdentity identity, SecureRandom random) {
        this.identity = identity;
        this.random = random;
    }

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        switch (path) {
            case LOGIN_PATH -> login(request, response);
            case VelodeIdentity.CALLBACK_PATH -> callback(request, response);
            case LOGOUT_PATH -> {
                response.addCookie(cookie(VelodeIdentity.SESSION_COOKIE, "", Duration.ZERO, request));
                response.sendRedirect(request.getContextPath() + HOME);
            }
            default -> chain.doFilter(request, response);
        }
    }

    private void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        byte[] bytes = new byte[24];
        random.nextBytes(bytes);
        String state = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Optional<String> loginUrl = identity.loginUrl(state);
        if (loginUrl.isEmpty()) {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Sign-in is not available yet");
            return;
        }
        String returnTo = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(localPath(request.getParameter(RETURN_PARAMETER)).getBytes(StandardCharsets.UTF_8));
        response.addCookie(cookie(STATE_COOKIE, state + "." + returnTo, STATE_TTL, request));
        response.sendRedirect(loginUrl.get());
    }

    private void callback(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] expected = cookieValue(request, STATE_COOKIE).split("\\.", 2);
        String state = request.getParameter(STATE_PARAMETER);
        response.addCookie(cookie(STATE_COOKIE, "", Duration.ZERO, request));
        if (expected.length != 2 || state == null || !MessageDigest.isEqual(
            expected[0].getBytes(StandardCharsets.UTF_8), state.getBytes(StandardCharsets.UTF_8))) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Sign-in could not be completed");
            return;
        }
        Optional<IdentitySession> session = identity.exchange(request.getParameter(CODE_PARAMETER));
        if (session.isEmpty()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Sign-in could not be completed");
            return;
        }
        Duration lifetime = Duration.between(Instant.now(), session.get().expiresAt());
        response.addCookie(cookie(VelodeIdentity.SESSION_COOKIE, session.get().token(), lifetime, request));
        String returnTo = new String(Base64.getUrlDecoder().decode(expected[1]), StandardCharsets.UTF_8);
        response.sendRedirect(request.getContextPath() + localPath(returnTo));
    }

    /** Only paths inside this application are followed after sign-in. */
    private static String localPath(String path) {
        return path != null && path.startsWith("/") && !path.startsWith("//") && !path.contains("\\")
            && path.chars().noneMatch(Character::isISOControl) ? path : HOME;
    }

    private static String cookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (name.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return "";
    }

    private static Cookie cookie(String name, String value, Duration lifetime, HttpServletRequest request) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(request.getContextPath().isEmpty() ? "/" : request.getContextPath());
        cookie.setMaxAge((int) Math.max(0, lifetime.toSeconds()));
        cookie.setAttribute("SameSite", "Lax");
        return cookie;
    }
}
