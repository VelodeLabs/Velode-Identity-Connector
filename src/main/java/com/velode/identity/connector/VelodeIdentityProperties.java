package com.velode.identity.connector;

import java.net.URI;
import java.time.Duration;
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

    public VelodeIdentityProperties {
        url = withoutTrailingSlash(url);
        appUrl = withoutTrailingSlash(appUrl);
        keyRotation = keyRotation == null ? Duration.ofDays(30) : keyRotation;
        if (url == null || !url.contains(ORGANIZATION_SEGMENT)) {
            throw new IllegalStateException(
                "velode.identity.url must be the organization address from the Identity panel, ending in /o/{organizationId}");
        }
        if (appUrl == null || URI.create(appUrl).getHost() == null) {
            throw new IllegalStateException("velode.identity.app-url must be the public URL of this application");
        }
    }

    /** Server-to-server base of the organization. */
    String apiUrl() {
        int segment = url.lastIndexOf(ORGANIZATION_SEGMENT);
        return url.substring(0, segment) + "/api/organizations/" + url.substring(segment + ORGANIZATION_SEGMENT.length());
    }

    private static String withoutTrailingSlash(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }
}
