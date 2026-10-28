package com.velode.identity.connector;

import com.velode.identity.connector.ConnectionManager.Connection;
import com.velode.identity.connector.VelodeIdentity.IdentitySession;
import com.velode.identity.connector.VelodeIdentity.IdentityUser;
import com.velode.identity.connector.VelodeIdentity.LoginFlow;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the browser-facing protections of the connector's own addresses: the sign-in state, where users are sent
 * afterwards, what the cookies allow and what the JSON steps accept. Identity is replaced by a stand-in that only
 * hands out a sign-in address and trades one valid code.
 */
class VelodeIdentityFilterTest {

    private static final String LOGIN_URL = "https://iam.velode.io/o/organization/login?state=";
    private static final String STATE_COOKIE = "velode_identity_state";
    private static final String FLOW_COOKIE = "velode_identity_flow";
    private static final String SESSION_TOKEN = "session-token";
    private static final Duration SESSION_LIFETIME = Duration.ofHours(8);

    private final StubIdentity identity = new StubIdentity();
    private final VelodeIdentityFilter filter =
        new VelodeIdentityFilter(identity, "https://lista.velode.io", new SecureRandom());

    @ParameterizedTest
    @CsvSource(nullValues = "NULL", value = {
        "/projects?id=7, /projects?id=7",
        "/, /",
        "NULL, /",
        "'', /",
        "projects, /",
        "//evil.example, /",
        "///evil.example, /",
        "/\\evil.example, /",
        "https://evil.example, /",
        "javascript:alert(1), /"
    })
    void should_OnlyReturnToPathsInsideThisApplication(String returnTo, String expected) throws Exception {
        MockHttpServletResponse signedIn = signIn(returnTo);

        assertThat(signedIn.getRedirectedUrl()).isEqualTo(expected);
        assertThat(signedIn.getCookie(VelodeIdentity.SESSION_COOKIE).getValue()).isEqualTo(SESSION_TOKEN);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/projects\r\nSet-Cookie: injected=1", "/projects\u0000", "/projects\t"})
    void should_ReturnHome_when_ReturnAddressCarriesControlCharacters(String returnTo) throws Exception {
        assertThat(signIn(returnTo).getRedirectedUrl()).isEqualTo("/");
    }

    @Test
    void should_KeepContextPathInCookiesAndRedirects() throws Exception {
        MockHttpServletRequest login = new MockHttpServletRequest("GET", "/lista/velode-identity/login");
        login.setContextPath("/lista");
        login.setParameter("returnTo", "/projects");
        MockHttpServletResponse started = send(login);
        Cookie state = started.getCookie(STATE_COOKIE);
        assertThat(state.getPath()).isEqualTo("/lista");

        MockHttpServletRequest callback = callback(state, stateOf(state), "valid-code");
        callback.setRequestURI("/lista" + VelodeIdentity.CALLBACK_PATH);
        callback.setContextPath("/lista");
        MockHttpServletResponse signedIn = send(callback);

        assertThat(signedIn.getRedirectedUrl()).isEqualTo("/lista/projects");
        assertThat(signedIn.getCookie(VelodeIdentity.SESSION_COOKIE).getPath()).isEqualTo("/lista");
    }

    @Test
    void should_StartEverySignInWithAFreshUnguessableState() throws Exception {
        MockHttpServletResponse first = send(new MockHttpServletRequest("GET", VelodeIdentityFilter.LOGIN_PATH));
        MockHttpServletResponse second = send(new MockHttpServletRequest("GET", VelodeIdentityFilter.LOGIN_PATH));

        String state = stateOf(first.getCookie(STATE_COOKIE));
        assertThat(state).hasSize(32).isNotEqualTo(stateOf(second.getCookie(STATE_COOKIE)));
        assertThat(first.getRedirectedUrl()).isEqualTo(LOGIN_URL + state);
        assertThat(first.getCookie(STATE_COOKIE).getMaxAge()).isEqualTo(600);
        assertThat(first.getHeader("Cache-Control")).isEqualTo("no-store");
    }

    @Test
    void should_RefuseCallback_when_StateIsMissingOrBelongsToAnotherSignIn() throws Exception {
        Cookie state = send(new MockHttpServletRequest("GET", VelodeIdentityFilter.LOGIN_PATH)).getCookie(STATE_COOKIE);

        for (MockHttpServletRequest forged : List.of(
            callback(state, "another-state", "valid-code"),
            callback(state, null, "valid-code"),
            callback(null, stateOf(state), "valid-code"),
            callback(new Cookie(STATE_COOKIE, stateOf(state)), stateOf(state), "valid-code"),
            callback(state, stateOf(state).substring(1), "valid-code")
        )) {
            MockHttpServletResponse refused = send(forged);
            assertThat(refused.getStatus()).isEqualTo(400);
            assertThat(refused.getCookie(VelodeIdentity.SESSION_COOKIE)).isNull();
            assertThat(refused.getCookie(STATE_COOKIE).getMaxAge()).isZero();
        }
        assertThat(identity.exchanged).isEmpty();
    }

    @Test
    void should_ConsumeStateAndRefuseSession_when_IdentityRejectsTheCode() throws Exception {
        Cookie state = send(new MockHttpServletRequest("GET", VelodeIdentityFilter.LOGIN_PATH)).getCookie(STATE_COOKIE);

        MockHttpServletResponse refused = send(callback(state, stateOf(state), "used-code"));

        assertThat(refused.getStatus()).isEqualTo(401);
        assertThat(refused.getCookie(VelodeIdentity.SESSION_COOKIE)).isNull();
        assertThat(refused.getCookie(STATE_COOKIE).getMaxAge()).isZero();
        assertThat(identity.exchanged).containsExactly("used-code");
    }

    @Test
    void should_AnswerUnavailable_when_IdentityCannotBeReachedDuringCallback() throws Exception {
        Cookie state = send(new MockHttpServletRequest("GET", VelodeIdentityFilter.LOGIN_PATH)).getCookie(STATE_COOKIE);

        MockHttpServletResponse unavailable = send(callback(state, stateOf(state), "unreachable-code"));

        assertThat(unavailable.getStatus()).isEqualTo(503);
        assertThat(unavailable.getCookie(VelodeIdentity.SESSION_COOKIE)).isNull();
        assertThat(unavailable.getCookie(STATE_COOKIE).getMaxAge()).isZero();
    }

    @Test
    void should_RefuseSignIn_when_ApplicationIsNotConnectedYet() throws Exception {
        identity.connected = false;

        MockHttpServletResponse refused = send(new MockHttpServletRequest("GET", VelodeIdentityFilter.LOGIN_PATH));

        assertThat(refused.getStatus()).isEqualTo(503);
        assertThat(refused.getCookie(STATE_COOKIE)).isNull();
    }

    @Test
    void should_IssueCookiesScriptsCannotReadAndOtherSitesCannotSend() throws Exception {
        MockHttpServletResponse signedIn = signIn("/");
        Cookie session = signedIn.getCookie(VelodeIdentity.SESSION_COOKIE);
        MockHttpServletResponse started = send(new MockHttpServletRequest("GET", VelodeIdentityFilter.LOGIN_PATH));
        MockHttpServletResponse signedOut = send(new MockHttpServletRequest("GET", VelodeIdentityFilter.LOGOUT_PATH));

        for (Cookie cookie : List.of(session, started.getCookie(STATE_COOKIE),
            signedOut.getCookie(VelodeIdentity.SESSION_COOKIE))) {
            assertThat(cookie.isHttpOnly()).as(cookie.getName()).isTrue();
            assertThat(cookie.getSecure()).as(cookie.getName()).isTrue();
            assertThat(cookie.getAttribute("SameSite")).as(cookie.getName()).isEqualTo("Lax");
            assertThat(cookie.getPath()).as(cookie.getName()).isEqualTo("/");
        }
        int lifetime = (int) SESSION_LIFETIME.toSeconds();
        assertThat(session.getMaxAge()).isBetween(lifetime - 5, lifetime);
        assertThat(signedOut.getCookie(VelodeIdentity.SESSION_COOKIE).getMaxAge()).isZero();
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "GET  | start      | application/json | {}                 | 405 | METHOD_NOT_ALLOWED",
        "POST | options    | application/json | {}                 | 405 | METHOD_NOT_ALLOWED",
        "POST | start      | text/plain       | {}                 | 415 | JSON_REQUIRED",
        "POST | start      |                  | {}                 | 415 | JSON_REQUIRED",
        "POST | start      | application/json | email=user@velode.io | 400 | INVALID_REQUEST",
        "POST | start      | application/json | [\"user@velode.io\"] | 400 | INVALID_REQUEST",
        "POST | code       | application/json | {\"code\":\"1\"}   | 400 | NO_FLOW",
        "POST | totp       | application/json | {\"code\":\"1\"}   | 400 | NO_FLOW",
        "POST | ../login   | application/json | {}                 | 404 | NOT_FOUND",
        "POST | session    | application/json | {}                 | 404 | NOT_FOUND"
    })
    void should_RefuseFlowRequestsThatAreNotItsOwnJsonSteps(
        String method, String step, String contentType, String body, int status, String error
    ) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/velode-identity/flow/" + step);
        request.setContentType(contentType);
        request.setContent(body.getBytes(StandardCharsets.UTF_8));

        MockHttpServletResponse refused = send(request);

        assertThat(refused.getStatus()).isEqualTo(status);
        assertThat(refused.getContentAsString()).isEqualTo("{\"error\":\"" + error + "\"}");
        assertThat(refused.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(refused.getCookie(FLOW_COOKIE)).isNull();
    }

    @Test
    void should_RefuseBodiesLargerThanEightKilobytes() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/velode-identity/flow/start");
        request.setContentType("application/json");
        request.setContent(("{\"email\":\"" + "a".repeat(8192) + "\"}").getBytes(StandardCharsets.UTF_8));

        MockHttpServletResponse refused = send(request);

        assertThat(refused.getStatus()).isEqualTo(400);
        assertThat(refused.getContentAsString()).isEqualTo("{\"error\":\"INVALID_REQUEST\"}");
    }

    @Test
    void should_IgnoreFlowCookie_when_ItIsNotAFlowTheConnectorIssued() throws Exception {
        for (String value : List.of("", "no-separator", "not-a-uuid.secret", ".secret")) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/velode-identity/flow/code");
            request.setContentType("application/json");
            request.setContent("{\"code\":\"12345678\"}".getBytes(StandardCharsets.UTF_8));
            request.setCookies(new Cookie(FLOW_COOKIE, value));

            assertThat(send(request).getContentAsString()).as(value).isEqualTo("{\"error\":\"NO_FLOW\"}");
        }
    }

    @Test
    void should_PassOtherRequestsToTheApplication() throws Exception {
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/velode-identity/loginx");

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isSameAs(request);
    }

    @Test
    void should_KeepSecretsOutOfLogs() {
        String key = "K".repeat(43);
        String secret = "S".repeat(43);
        IdentityUser user = new IdentityUser(UUID.randomUUID(), "user@velode.io");

        assertThat(new Connection(key, secret, "lista", Instant.EPOCH).toString())
            .doesNotContain(key, secret).contains("lista");
        assertThat(new LoginFlow(UUID.randomUUID(), secret).toString()).doesNotContain(secret);
        assertThat(new IdentitySession(user, SESSION_TOKEN, Instant.EPOCH).toString()).doesNotContain(SESSION_TOKEN);
    }

    private MockHttpServletResponse signIn(String returnTo) throws Exception {
        MockHttpServletRequest login = new MockHttpServletRequest("GET", VelodeIdentityFilter.LOGIN_PATH);
        login.setParameter("returnTo", returnTo);
        Cookie state = send(login).getCookie(STATE_COOKIE);
        return send(callback(state, stateOf(state), "valid-code"));
    }

    private static MockHttpServletRequest callback(Cookie state, String stateParameter, String code) {
        MockHttpServletRequest callback = new MockHttpServletRequest("GET", VelodeIdentity.CALLBACK_PATH);
        if (state != null) {
            callback.setCookies(state);
        }
        callback.setParameter("velode_identity_state", stateParameter);
        callback.setParameter("velode_identity_code", code);
        return callback;
    }

    private static String stateOf(Cookie cookie) {
        return cookie.getValue().split("\\.", 2)[0];
    }

    private MockHttpServletResponse send(MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    /**
     * Hands out Identity's sign-in address while connected, trades only {@code valid-code} and cannot reach Identity
     * for {@code unreachable-code}.
     */
    private static final class StubIdentity extends VelodeIdentity {

        private final List<String> exchanged = new ArrayList<>();
        private boolean connected = true;

        StubIdentity() {
            super(null, null, null);
        }

        @Override
        public Optional<String> loginUrl(String state) {
            return connected ? Optional.of(LOGIN_URL + state) : Optional.empty();
        }

        @Override
        public Optional<IdentitySession> exchange(String code) {
            exchanged.add(code);
            if ("unreachable-code".equals(code)) {
                throw new IdentityUnavailableException("Velode Identity could not be reached", null);
            }
            return "valid-code".equals(code)
                ? Optional.of(new IdentitySession(new IdentityUser(UUID.randomUUID(), "user@velode.io"), SESSION_TOKEN,
                    Instant.now().plus(SESSION_LIFETIME)))
                : Optional.empty();
        }
    }
}
