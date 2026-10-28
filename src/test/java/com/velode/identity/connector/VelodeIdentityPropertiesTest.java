package com.velode.identity.connector;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Session tokens and connection keys only travel over HTTPS, except to this machine during development.
 */
class VelodeIdentityPropertiesTest {

    private static final String ORGANIZATION_URL = "https://iam.velode.io/o/891602e0-f43a-41de-a768-281aeaf8b913";
    private static final String APP_URL = "https://lista.velode.io";

    @Test
    void should_AcceptHttpsAddressesAndDeriveTheApiBase() {
        VelodeIdentityProperties properties = new VelodeIdentityProperties(ORGANIZATION_URL + "/", APP_URL + "/", null, null);

        assertThat(properties.url()).isEqualTo(ORGANIZATION_URL);
        assertThat(properties.appUrl()).isEqualTo(APP_URL);
        assertThat(properties.apiUrl())
            .isEqualTo("https://iam.velode.io/api/organizations/891602e0-f43a-41de-a768-281aeaf8b913");
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "HTTP://LOCALHOST"})
    void should_AcceptPlainHttp_when_AddressIsThisMachine(String local) {
        assertThat(new VelodeIdentityProperties(local + "/o/organization", local, null, null).appUrl()).isEqualTo(local);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "http://iam.velode.io/o/organization",
        "ftp://iam.velode.io/o/organization",
        "https://user:password@iam.velode.io/o/organization",
        "https://iam.velode.io/o/organization?next=https://evil.example",
        "https://iam.velode.io/o/organization#fragment",
        "//iam.velode.io/o/organization",
        "https://iam.velode.io/organizations/organization",
        "https://iam velode.io/o/organization"
    })
    void should_RefuseOrganizationAddress_when_ItIsNotSecureOrNotAnOrganization(String url) {
        assertThatThrownBy(() -> new VelodeIdentityProperties(url, APP_URL, null, null))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("velode.identity.url");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "http://lista.velode.io",
        "https://lista.velode.io/app",
        "https://lista.velode.io?x=1",
        "https://user@lista.velode.io",
        "lista.velode.io",
        " "
    })
    void should_RefuseApplicationAddress_when_ItIsNotAnHttpsOrigin(String appUrl) {
        assertThatThrownBy(() -> new VelodeIdentityProperties(ORGANIZATION_URL, appUrl, null, null))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("velode.identity.app-url");
    }
}
