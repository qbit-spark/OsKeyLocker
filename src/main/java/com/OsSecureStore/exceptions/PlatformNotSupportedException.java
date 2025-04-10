package com.OsSecureStore.exceptions;

/**
 * Exception thrown when the current platform is not supported
 */
public class PlatformNotSupportedException extends SecureStorageException {

    public PlatformNotSupportedException(String message) {
        super(message);
    }

    public PlatformNotSupportedException(String message, Throwable cause) {
        super(message, cause);
    }
}