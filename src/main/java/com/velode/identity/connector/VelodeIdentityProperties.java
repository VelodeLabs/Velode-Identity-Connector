package com.velode.identity.connector;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Locale;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The only settings a connected application provides; none of them is a secret.
 *
 * @param url organization address copied from the Identity panel, such as {@code https://iam.velode.io/o/{organizationId}}
 * @param appUrl public HTTPS origin of this application
 * @param name name suggested to the administrator; defaults to {@code spring.application.name}
 * @param keyRotation how often the connector replaces its own key
 */
@ConfigurationProperties(prefix = "velode.identity")
public record VelodeIdentityProperties(String url, String appUrl, String name, Duration keyRotation) {

    private static final String ORGANIZATION_SEGMENT = "/o/";
    private static final Set<String> LOOPBACK_HOSTS = Set.of("localhost", "127.0.0.1", "[::1]");

    public VelodeIdentityProperties {
        url = withoutTrailingSlash(url);
        appUrl = withoutTrailingSlash(appUrl);
        keyRotation = keyRotation == null ? Duration.ofDays(30) : keyRotation;
        if (url == null || !url.contains(ORGANIZATION_SEGMENT)) {
            throw new IllegalStateException(
                "velode.identity.url must be the organization address from the Identity panel, ending in /o/{organizationId}");
        }
        secure(url, "velode.identity.url");
        if (appUrl == null || !secure(appUrl, "velode.identity.app-url").getRawPath().isEmpty()) {
            throw new IllegalStateException(
                "velode.identity.app-url must be the public origin of this application, such as https://app.example.com");
        }
    }

    /** Server-to-server base of the organization. */
    String apiUrl() {
        int segment = url.lastIndexOf(ORGANIZATION_SEGMENT);
        return url.substring(0, segment) + "/api/organizations/" + url.substring(segment + ORGANIZATION_SEGMENT.length());
    }

    /**
     * Session tokens and connection keys travel to these addresses, so they must be HTTPS. Plain HTTP is accepted
     * only on this machine, for development.
     */
    private static URI secure(String value, String property) {
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException exception) {
            throw new IllegalStateException(property + " is not a valid URL", exception);
        }
        if (uri.getScheme() == null || uri.getHost() == null
            || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new IllegalStateException(property + " must be an absolute URL without credentials, query or fragment");
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!"https".equals(scheme)
            && !("http".equals(scheme) && LOOPBACK_HOSTS.contains(uri.getHost().toLowerCase(Locale.ROOT)))) {
            throw new IllegalStateException(property + " must use https; plain http is only accepted for localhost");
        }
        return uri;
    }

    private static String withoutTrailingSlash(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }
}
