package com.velode.identity.connector;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.HexFormat;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Connects the application to Velode Identity as soon as {@code velode.identity.url} is set.
 */
@AutoConfiguration(afterName = {
    "org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration",
    "org.springframework.boot.jdbc.autoconfigure.JdbcTemplateAutoConfiguration"
})
@ConditionalOnProperty(prefix = "velode.identity", name = "url")
@EnableConfigurationProperties(VelodeIdentityProperties.class)
public class VelodeIdentityAutoConfiguration {

    private static final String DEFAULT_NAME = "Application";

    @Bean
    IdentityClient velodeIdentityClient(VelodeIdentityProperties properties) {
        return new IdentityClient(properties.apiUrl());
    }

    @Bean
    ConnectionManager velodeIdentityConnectionManager(
        VelodeIdentityProperties properties,
        ConnectionStore store,
        IdentityClient client,
        Environment environment
    ) {
        String name = properties.name() != null
            ? properties.name()
            : environment.getProperty("spring.application.name", DEFAULT_NAME);
        return new ConnectionManager(properties, name, store, client, Clock.systemUTC(), new SecureRandom());
    }

    @Bean
    @ConditionalOnMissingBean
    VelodeIdentity velodeIdentity(VelodeIdentityProperties properties, ConnectionManager connections, IdentityClient client) {
        return new VelodeIdentity(properties, connections, client);
    }

    /** Separates the connections of applications or organizations that share one database. */
    private static String storeId(VelodeIdentityProperties properties) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest((properties.url() + "\n" + properties.appUrl()).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 16);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(JdbcTemplate.class)
    static class JdbcStoreConfiguration {

        @Bean
        @ConditionalOnBean(JdbcTemplate.class)
        @ConditionalOnMissingBean(ConnectionStore.class)
        ConnectionStore velodeIdentityJdbcConnectionStore(JdbcTemplate jdbcTemplate, VelodeIdentityProperties properties) {
            return new ConnectionStore.Jdbc(jdbcTemplate, storeId(properties));
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    static class WebConfiguration {

        @Bean
        VelodeIdentityFilter velodeIdentityFilter(VelodeIdentity identity) {
            return new VelodeIdentityFilter(identity, new SecureRandom());
        }
    }
}
