package com.velode.identity.connector;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.boot.json.BasicJsonParser;
import org.springframework.boot.json.JsonParseException;

/**
 * Sends the connector's JSON calls to one organization of Identity.
 */
class IdentityClient {

    private static final String KEY_HEADER = "X-Server-Connection-Key";
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final String apiUrl;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();

    IdentityClient(String apiUrl) {
        this.apiUrl = apiUrl;
    }

    /** Returns the HTTP status with the {@code data} object of a success or the fields of an error. */
    Response post(String path, String key, Map<String, String> body) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(apiUrl + path))
            .timeout(TIMEOUT)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json(body)));
        if (key != null) {
            request.header(KEY_HEADER, key);
        }
        try {
            HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
            return new Response(response.statusCode(), data(response));
        } catch (IOException exception) {
            throw new IdentityUnavailableException("Velode Identity could not be reached", exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IdentityUnavailableException("Interrupted while calling Velode Identity", exception);
        }
    }

    private static Map<String, Object> data(HttpResponse<String> response) {
        if (response.body().isBlank()) {
            return Map.of();
        }
        Map<String, Object> body;
        try {
            body = new BasicJsonParser().parseMap(response.body());
        } catch (JsonParseException exception) {
            // A proxy in front of Identity answered; only the status is meaningful.
            return Map.of();
        }
        return (response.statusCode() == 200 ? body.get("data") : body) instanceof Map<?, ?> data
            ? data.entrySet().stream()
                .filter(entry -> entry.getValue() != null)
                .collect(Collectors.toMap(entry -> String.valueOf(entry.getKey()), Map.Entry::getValue))
            : Map.of();
    }

    /** Every value the connector sends is a URL, a name or base64url text, so escaping stays minimal. */
    private static String json(Map<String, String> body) {
        return body.entrySet().stream()
            .map(entry -> '"' + entry.getKey() + "\":\"" + escape(entry.getValue()) + '"')
            .collect(Collectors.joining(",", "{", "}"));
    }

    private static String escape(String value) {
        StringBuilder escaped = new StringBuilder(value.length());
        for (char character : value.toCharArray()) {
            if (character == '"' || character == '\\') {
                escaped.append('\\').append(character);
            } else if (character < 0x20) {
                escaped.append(String.format("\\u%04x", (int) character));
            } else {
                escaped.append(character);
            }
        }
        return escaped.toString();
    }

    record Response(int status, Map<String, Object> data) {

        /** Identity refused the connection key itself, not the user token or code sent with it. */
        boolean keyRefused() {
            return status == 401 && "INVALID_CONNECTION_KEY".equals(text("error"));
        }

        String text(String field) {
            Object value = data.get(field);
            return value == null ? null : value.toString();
        }
    }

    /**
     * Identity did not answer; the caller cannot tell whether a user is authenticated.
     */
    public static class IdentityUnavailableException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public IdentityUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
