package com.velode.identity.connector;

/**
 * Velode Identity did not answer, so the caller cannot tell whether a user is authenticated. Applications usually answer
 * {@code 503 Service Unavailable} and let the user try again.
 */
public class IdentityUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public IdentityUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
